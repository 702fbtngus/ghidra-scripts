// Scans uncovered function pointers, their struct-field stores, and later field-based ICALL uses.
// @category CubeSat

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.extension.datatype.finder.DecompilerDataTypeReferenceFinder;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeReference;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class UncoveredFunctionUsageAnalyzer extends GhidraScript {

    private static final String DEFAULT_INPUT = "uncovered_functions_usage.txt";
    private static final String DEFAULT_OUTPUT = "uncovered_functions_usage_auto.tsv";
    private static final int INDIRECT_CALL_SEARCH_BYTES = 32;
    private static final int CSP_IFACE_NEXTHOP_OFFSET = 8;
    private static final Pattern TARGET_LINE = Pattern.compile("^\\s*([0-9a-fA-F]{8})\\s+([^\\s|]+)");
    private static final Pattern PTR_LABEL = Pattern.compile("PTR_([A-Za-z0-9_]+)_([0-9a-fA-F]{8})");
    private static final Pattern DAT_LABEL = Pattern.compile("\\bDAT_([0-9a-fA-F]{8})\\b");
    private static final Pattern VARIABLE_NAME = Pattern.compile("^[A-Za-z_]\\w*$");
    private static final Pattern POINTER_OFFSET_ALIAS =
        Pattern.compile("\\b([A-Za-z_]\\w*)\\s*=\\s*([A-Za-z_]\\w*)\\s*\\+\\s*(0x[0-9a-fA-F]+|\\d+)\\b");
    private static final Pattern POINTER_OFFSET_STORE =
        Pattern.compile("\\*\\s*\\([^)]*\\*\\*\\)\\s*\\(\\s*([A-Za-z_]\\w*)\\s*\\+\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\)\\s*=\\s*([^;]+)");
    private static final Pattern SIMPLE_INDIRECT_CALL =
        Pattern.compile("\\(\\*+[A-Za-z_]\\w*\\)\\s*\\(");
    private static final Pattern LOCAL_TARGET_ASSIGNMENT =
        Pattern.compile("\\b([A-Za-z]*Stack_[0-9a-fA-F]+|local_[0-9a-fA-F]+)\\s*=\\s*(?:&\\s*)?PTR_%s_[0-9a-fA-F]+");
    private static final Pattern LOCAL_ADDRESS =
        Pattern.compile("&\\s*([A-Za-z]*Stack_[0-9a-fA-F]+|local_[0-9a-fA-F]+)");

    private final Map<Address, DecompileResults> decompileCache = new HashMap<>();
    private Map<Address, List<RegistrationSite>> staticIfaceRegistrationSites;

    private DecompInterface decompiler;
    private FunctionManager functionManager;
    private ReferenceManager referenceManager;

    @Override
    protected void run() throws Exception {
        functionManager = currentProgram.getFunctionManager();
        referenceManager = currentProgram.getReferenceManager();

        Path inputPath = resolveScriptPath(DEFAULT_INPUT);
        Path outputPath = resolveScriptPath(DEFAULT_OUTPUT);
        List<TargetFunction> targets = readTargets(inputPath);

        decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Decompiler unavailable: " + decompiler.getLastMessage());
            }

            List<UsageRecord> records = new ArrayList<>();
            for (TargetFunction target : targets) {
                monitor.checkCancelled();
                records.addAll(analyzeTarget(target));
            }
            records.sort(Comparator
                .comparing((UsageRecord record) -> record.targetAddress)
                .thenComparing(record -> record.field)
                .thenComparing(record -> record.useAddress)
                .thenComparing(record -> record.icallAddress));

            writeRecords(outputPath, records);
            println("Uncovered usage auto analysis: targets=" + targets.size() +
                " records=" + records.size());
            println("Output: " + outputPath.toAbsolutePath());
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
        }
    }

    private List<TargetFunction> readTargets(Path inputPath) throws IOException {
        List<TargetFunction> targets = new ArrayList<>();
        for (String line : Files.readAllLines(inputPath)) {
            Matcher matcher = TARGET_LINE.matcher(line);
            if (!matcher.find()) {
                continue;
            }
            Address address = toAddr(Long.parseUnsignedLong(matcher.group(1), 16));
            Function function = functionManager.getFunctionAt(address);
            String name = matcher.group(2);
            if (function != null) {
                name = function.getName();
            }
            targets.add(new TargetFunction(address, name, function));
        }
        return targets;
    }

    private List<UsageRecord> analyzeTarget(TargetFunction target) throws Exception {
        List<UsageRecord> records = new ArrayList<>();
        Set<FieldStore> fieldStores = findFieldStores(target);

        Map<FieldKey, List<DataTypeReference>> fieldReferences = new HashMap<>();
        DecompilerDataTypeReferenceFinder finder = new DecompilerDataTypeReferenceFinder();

        for (FieldStore store : fieldStores) {
            FieldKey key = store.key();
            if (!fieldReferences.containsKey(key)) {
                List<DataTypeReference> references = new ArrayList<>();
                finder.findReferences(
                    currentProgram,
                    new FieldMatcher(store.dataType, store.fieldOffset),
                    references::add,
                    monitor
                );
                references.sort(Comparator
                    .comparing((DataTypeReference ref) -> safeAddressString(ref.getAddress()))
                    .thenComparing(ref -> safeFunctionName(ref.getFunction())));
                fieldReferences.put(key, references);
            }

            List<DataTypeReference> references = fieldReferences.getOrDefault(key, List.of());
            if (references.isEmpty()) {
                records.add(new UsageRecord(
                    target,
                    store.fieldDisplay(),
                    store.storeAddress.toString(),
                    store.storeFunction.getName(),
                    "",
                    "",
                    "",
                    "",
                    store.contextLine,
                    "field_store_no_field_uses"
                ));
                continue;
            }

            for (DataTypeReference reference : references) {
                monitor.checkCancelled();
                Function useFunction = reference.getFunction();
                Address useAddress = reference.getAddress();
                String context = reference.getContext() == null
                    ? ""
                    : oneLine(reference.getContext().getPlainText());
                IcallSite icallSite = findNearbyIndirectCall(useFunction, useAddress);
                String kind = icallSite == null ? "field_ref" : "field_ref_to_icall";
                records.add(new UsageRecord(
                    target,
                    store.fieldDisplay(),
                    store.storeAddress.toString(),
                    store.storeFunction.getName(),
                    safeAddressString(useAddress),
                    safeFunctionName(useFunction),
                    icallSite == null ? "" : icallSite.address.toString(),
                    icallSite == null ? "" : icallSite.text,
                    context.isEmpty() ? store.contextLine : context,
                    kind
                ));
            }
        }

        records.addAll(findHeuristicUsageRecords(target));
        records.addAll(findStaticCspIfaceRecords(target));
        records = dedupeRecords(records);
        if (records.isEmpty()) {
            records.add(new UsageRecord(target, "", "", "", "", "", "", "", "", "no_usage_chain_found"));
        }

        return records;
    }

    private List<UsageRecord> findStaticCspIfaceRecords(TargetFunction target) throws Exception {
        List<UsageRecord> records = new ArrayList<>();
        Function cspSendDirect = findNamedFunction("csp_send_direct");
        if (cspSendDirect == null) {
            return records;
        }

        List<ParamUse> sendUses = findCalleeParamIndirectUses(cspSendDirect, 2, CSP_IFACE_NEXTHOP_OFFSET);
        if (sendUses.isEmpty()) {
            return records;
        }

        for (Reference reference : referenceManager.getReferencesTo(target.address)) {
            Address fromAddress = reference.getFromAddress();
            if (!currentProgram.getMemory().contains(fromAddress)) {
                continue;
            }
            if (functionManager.getFunctionContaining(fromAddress) != null) {
                continue;
            }

            Symbol owner = findNearestPrimarySymbol(fromAddress);
            if (owner == null) {
                continue;
            }
            long offset = fromAddress.subtract(owner.getAddress());
            if (offset != CSP_IFACE_NEXTHOP_OFFSET) {
                continue;
            }

            List<RegistrationSite> registrationSites = findStaticIfaceRegistrationSites(owner.getAddress());
            for (RegistrationSite registrationSite : registrationSites) {
                for (ParamUse use : sendUses) {
                    records.add(new UsageRecord(
                        target,
                        owner.getName() + ".nexthop+" + offset,
                        fromAddress.toString(),
                        registrationSite.functionName,
                        registrationSite.contextAddress,
                        cspSendDirect.getName(),
                        use.icallAddress,
                        use.icallText,
                        owner.getName() + "+" + offset + " = " + target.name +
                            " | " + registrationSite.context + " | " + use.context,
                        "static_csp_iface_nexthop_to_icall"
                    ));
                }
            }
        }
        return records;
    }

    private Symbol findNearestPrimarySymbol(Address address) {
        AddressSet addressSet = new AddressSet(address.getAddressSpace().getMinAddress(), address);
        SymbolIterator symbols = currentProgram.getSymbolTable().getPrimarySymbolIterator(addressSet, false);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getAddress().compareTo(address) <= 0) {
                return symbol;
            }
        }
        return null;
    }

    private List<RegistrationSite> findStaticIfaceRegistrationSites(Address ifaceAddress) throws Exception {
        return getStaticIfaceRegistrationSites().getOrDefault(ifaceAddress, List.of());
    }

    private Map<Address, List<RegistrationSite>> getStaticIfaceRegistrationSites() throws Exception {
        if (staticIfaceRegistrationSites != null) {
            return staticIfaceRegistrationSites;
        }

        staticIfaceRegistrationSites = new HashMap<>();
        FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            Function function = functions.next();
            DecompileResults results = decompile(function);
            if (results == null || results.getDecompiledFunction() == null) {
                continue;
            }
            for (String rawLine : collectCStatements(results.getDecompiledFunction().getC())) {
                String line = oneLine(rawLine);
                Function callee = resolvePointerLabelFunction(line);
                if (callee == null || !isCspIfaceRegistrationFunction(callee)) {
                    continue;
                }
                for (String argument : parseCallArguments(line)) {
                    Address resolved = resolveDataPointerExpression(argument);
                    if (resolved != null) {
                        staticIfaceRegistrationSites
                            .computeIfAbsent(resolved, ignored -> new ArrayList<>())
                            .add(new RegistrationSite(
                            function.getName(),
                            "",
                            line
                        ));
                    }
                }
            }
        }
        return staticIfaceRegistrationSites;
    }

    private List<UsageRecord> findHeuristicUsageRecords(TargetFunction target) {
        List<UsageRecord> records = new ArrayList<>();
        Set<Address> ifaceFallbackFunctions = new HashSet<>();
        for (Reference reference : referenceManager.getReferencesTo(target.address)) {
            Address fromAddress = reference.getFromAddress();
            Function containingFunction = functionManager.getFunctionContaining(fromAddress);
            if (containingFunction == null) {
                continue;
            }

            DecompileResults results = decompile(containingFunction);
            if (results == null || results.getDecompiledFunction() == null) {
                continue;
            }

            List<String> statements = collectCStatements(results.getDecompiledFunction().getC());
            for (String statement : statements) {
                String cleanLine = oneLine(statement);
                if (!mentionsTarget(cleanLine, target)) {
                    continue;
                }
                records.addAll(
                    findLocalStructFallbackRecords(target, containingFunction, fromAddress, cleanLine, statements)
                );
                records.addAll(findCallbackArgumentRecords(target, containingFunction, fromAddress, cleanLine));
                records.addAll(findCanFilterCallbackRecords(target, containingFunction, fromAddress, cleanLine));
            }
            if (ifaceFallbackFunctions.add(containingFunction.getEntryPoint())) {
                records.addAll(
                    findCspIfaceNexthopFallbackRecords(target, containingFunction, fromAddress, statements)
                );
            }
        }
        return records;
    }

    private List<UsageRecord> findCanFilterCallbackRecords(
        TargetFunction target,
        Function containingFunction,
        Address refAddress,
        String line
    ) {
        List<UsageRecord> records = new ArrayList<>();
        Function registrationFunction = resolvePointerLabelFunction(line);
        if (registrationFunction == null ||
            !"gs_can_set_extended_filter_mask".equals(registrationFunction.getName())) {
            return records;
        }

        List<String> args = parseCallArguments(line);
        int callbackArgIndex = -1;
        for (int argIndex = 0; argIndex < args.size(); argIndex++) {
            if (mentionsTarget(args.get(argIndex), target)) {
                callbackArgIndex = argIndex;
                break;
            }
        }
        if (callbackArgIndex < 0) {
            return records;
        }

        Function dispatcher = findNamedFunction("can_mbox_rx");
        if (dispatcher == null) {
            return records;
        }

        for (ParamUse use : findFunctionIndirectUses(dispatcher)) {
            records.add(new UsageRecord(
                target,
                registrationFunction.getName() + ".arg" + (callbackArgIndex + 1),
                refAddress.toString(),
                containingFunction.getName(),
                use.contextAddress,
                dispatcher.getName(),
                use.icallAddress,
                use.icallText,
                line + " | " + use.context,
                "can_filter_callback_to_icall"
            ));
        }
        return records;
    }

    private List<UsageRecord> findCspIfaceNexthopFallbackRecords(
        TargetFunction target,
        Function containingFunction,
        Address refAddress,
        List<String> statements
    ) {
        List<UsageRecord> records = new ArrayList<>();
        Set<String> targetAliases = collectTargetAliases(target, statements);
        Map<String, PointerAlias> pointerAliases = collectPointerAliases(statements);
        Function cspSendDirect = findNamedFunction("csp_send_direct");
        if (cspSendDirect == null) {
            return records;
        }

        List<ParamUse> sendUses = findCalleeParamIndirectUses(cspSendDirect, 2, CSP_IFACE_NEXTHOP_OFFSET);
        if (sendUses.isEmpty()) {
            return records;
        }

        for (String rawStoreLine : statements) {
            String storeLine = oneLine(rawStoreLine);
            Matcher storeMatcher = POINTER_OFFSET_STORE.matcher(storeLine);
            if (!storeMatcher.find()) {
                continue;
            }

            String storeBase = storeMatcher.group(1);
            Integer storeOffset = parseNumber(storeMatcher.group(2));
            if (storeOffset == null || !isTargetExpression(storeMatcher.group(3), target, targetAliases)) {
                continue;
            }

            Integer ifaceBaseOffset =
                findRegisteredCspIfaceBaseOffset(storeBase, statements, pointerAliases);
            if (ifaceBaseOffset == null ||
                storeOffset - ifaceBaseOffset != CSP_IFACE_NEXTHOP_OFFSET) {
                continue;
            }

            for (ParamUse use : sendUses) {
                records.add(new UsageRecord(
                    target,
                    "csp_iface_t.nexthop+" + CSP_IFACE_NEXTHOP_OFFSET,
                    refAddress.toString(),
                    containingFunction.getName(),
                    use.contextAddress,
                    cspSendDirect.getName(),
                    use.icallAddress,
                    use.icallText,
                    storeLine + " | " + use.context,
                    "csp_iface_nexthop_to_icall"
                ));
            }
        }
        return records;
    }

    private Set<String> collectTargetAliases(TargetFunction target, List<String> statements) {
        Set<String> aliases = new HashSet<>();
        aliases.add(target.name);
        Pattern targetAssignment = Pattern.compile(
            "\\b([A-Za-z_]\\w*)\\s*=\\s*(?:&\\s*)?(?:PTR_" +
            Pattern.quote(target.name) + "_[0-9a-fA-F]+|" + Pattern.quote(target.name) + ")\\b"
        );
        for (String rawLine : statements) {
            Matcher matcher = targetAssignment.matcher(oneLine(rawLine));
            while (matcher.find()) {
                aliases.add(matcher.group(1));
            }
        }
        return aliases;
    }

    private Map<String, PointerAlias> collectPointerAliases(List<String> statements) {
        Map<String, PointerAlias> aliases = new HashMap<>();
        for (String rawLine : statements) {
            Matcher matcher = POINTER_OFFSET_ALIAS.matcher(oneLine(rawLine));
            while (matcher.find()) {
                Integer offset = parseNumber(matcher.group(3));
                if (offset != null) {
                    aliases.put(matcher.group(1), new PointerAlias(matcher.group(2), offset));
                }
            }
        }
        return aliases;
    }

    private Integer findRegisteredCspIfaceBaseOffset(
        String storeBase,
        List<String> statements,
        Map<String, PointerAlias> pointerAliases
    ) {
        for (String rawLine : statements) {
            String line = oneLine(rawLine);
            Function callee = resolvePointerLabelFunction(line);
            if (callee == null || !isCspIfaceRegistrationFunction(callee)) {
                continue;
            }
            for (String argument : parseCallArguments(line)) {
                Integer offset = resolveOffsetFromBase(argument, storeBase, pointerAliases, new HashSet<>());
                if (offset != null) {
                    return offset;
                }
            }
        }
        return null;
    }

    private boolean isCspIfaceRegistrationFunction(Function function) {
        String name = function.getName();
        return "csp_iflist_add".equals(name) || "csp_rtable_set".equals(name);
    }

    private Integer resolveOffsetFromBase(
        String expression,
        String baseVariable,
        Map<String, PointerAlias> pointerAliases,
        Set<String> seenVariables
    ) {
        String normalized = stripExpressionNoise(expression);
        if (baseVariable.equals(normalized)) {
            return 0;
        }

        Matcher directOffset = Pattern.compile(
            "\\b" + Pattern.quote(baseVariable) + "\\s*\\+\\s*(0x[0-9a-fA-F]+|\\d+)\\b"
        ).matcher(normalized);
        if (directOffset.find()) {
            return parseNumber(directOffset.group(1));
        }

        if (!VARIABLE_NAME.matcher(normalized).matches() || !seenVariables.add(normalized)) {
            return null;
        }

        PointerAlias alias = pointerAliases.get(normalized);
        if (alias == null) {
            return null;
        }
        Integer baseOffset = resolveOffsetFromBase(
            alias.baseVariable,
            baseVariable,
            pointerAliases,
            seenVariables
        );
        if (baseOffset == null) {
            return null;
        }
        return baseOffset + alias.offset;
    }

    private List<UsageRecord> findLocalStructFallbackRecords(
        TargetFunction target,
        Function containingFunction,
        Address storeAddress,
        String storeLine,
        List<String> containingFunctionLines
    ) {
        List<UsageRecord> records = new ArrayList<>();
        Pattern assignmentPattern =
            Pattern.compile(String.format(LOCAL_TARGET_ASSIGNMENT.pattern(), Pattern.quote(target.name)));
        Matcher assignmentMatcher = assignmentPattern.matcher(storeLine);
        if (!assignmentMatcher.find()) {
            return records;
        }

        String storedLocal = assignmentMatcher.group(1);
        Integer storedLocalOffset = parseLocalOffset(storedLocal);
        if (storedLocalOffset == null) {
            return records;
        }

        for (String rawCallLine : containingFunctionLines) {
            String callLine = oneLine(rawCallLine);
            if (!callLine.contains("&local_") || !callLine.contains("PTR_")) {
                continue;
            }

            Function callee = resolvePointerLabelFunction(callLine);
            if (callee == null) {
                continue;
            }
            List<String> args = parseCallArguments(callLine);
            for (int argIndex = 0; argIndex < args.size(); argIndex++) {
                Matcher localMatcher = LOCAL_ADDRESS.matcher(args.get(argIndex));
                if (!localMatcher.find()) {
                    continue;
                }
                Integer baseLocalOffset = parseLocalOffset(localMatcher.group(1));
                if (baseLocalOffset == null) {
                    continue;
                }
                int byteOffset = baseLocalOffset - storedLocalOffset;
                if (byteOffset < 0) {
                    continue;
                }

                List<ParamUse> uses = findCalleeParamIndirectUses(callee, argIndex, byteOffset);
                for (ParamUse use : uses) {
                    records.add(new UsageRecord(
                        target,
                        "stack:" + localMatcher.group(1) + "+" + String.format("0x%x", byteOffset),
                        storeAddress.toString(),
                        containingFunction.getName(),
                        use.contextAddress,
                        callee.getName(),
                        use.icallAddress,
                        use.icallText,
                        storeLine + " | " + use.context,
                        "stack_local_field_to_icall"
                    ));
                }
            }
        }
        return records;
    }

    private List<UsageRecord> findCallbackArgumentRecords(
        TargetFunction target,
        Function containingFunction,
        Address refAddress,
        String line
    ) {
        List<UsageRecord> records = new ArrayList<>();
        if (!line.contains("(") || !line.contains(")")) {
            return records;
        }

        Function callee = resolvePointerLabelFunction(line);
        if (callee == null) {
            return records;
        }

        List<String> args = parseCallArguments(line);
        for (int argIndex = 0; argIndex < args.size(); argIndex++) {
            if (!mentionsTarget(args.get(argIndex), target)) {
                continue;
            }
            List<ParamUse> uses = findCalleeParamIndirectUses(callee, argIndex, null);
            for (ParamUse use : uses) {
                records.add(new UsageRecord(
                    target,
                    callee.getName() + ".arg" + (argIndex + 1),
                    refAddress.toString(),
                    containingFunction.getName(),
                    use.contextAddress,
                    callee.getName(),
                    use.icallAddress,
                    use.icallText,
                    line + " | " + use.context,
                    "callback_arg_to_icall"
                ));
            }
        }
        return records;
    }

    private List<ParamUse> findCalleeParamIndirectUses(
        Function callee,
        int argIndex,
        Integer byteOffset
    ) {
        List<ParamUse> uses = new ArrayList<>();
        DecompileResults results = decompile(callee);
        if (results == null || results.getDecompiledFunction() == null) {
            return uses;
        }

        String paramName = "param_" + (argIndex + 1);
        List<IcallSite> icallSites = findIndirectCalls(callee);
        if (icallSites.isEmpty()) {
            return uses;
        }

        for (String rawLine : collectCStatements(results.getDecompiledFunction().getC())) {
            String line = oneLine(rawLine);
            if (!looksLikeIndirectCallLine(line) || !line.contains(paramName)) {
                continue;
            }
            if (byteOffset != null && !lineMentionsByteOffset(line, paramName, byteOffset)) {
                continue;
            }

            for (IcallSite icallSite : icallSites) {
                uses.add(new ParamUse(
                    "",
                    icallSite.address.toString(),
                    icallSite.text,
                    line
                ));
            }
        }
        return uses;
    }

    private List<ParamUse> findFunctionIndirectUses(Function function) {
        List<ParamUse> uses = new ArrayList<>();
        DecompileResults results = decompile(function);
        if (results == null || results.getDecompiledFunction() == null) {
            return uses;
        }

        List<IcallSite> icallSites = findIndirectCalls(function);
        if (icallSites.isEmpty()) {
            return uses;
        }

        List<String> contexts = new ArrayList<>();
        for (String rawLine : collectCStatements(results.getDecompiledFunction().getC())) {
            String line = oneLine(rawLine);
            if (looksLikeIndirectCallLine(line)) {
                contexts.add(line);
            }
        }
        String context = contexts.isEmpty() ? "" : contexts.get(0);

        for (IcallSite icallSite : icallSites) {
            uses.add(new ParamUse(
                "",
                icallSite.address.toString(),
                icallSite.text,
                context
            ));
        }
        return uses;
    }

    private List<IcallSite> findIndirectCalls(Function function) {
        List<IcallSite> calls = new ArrayList<>();
        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (isIndirectCall(instruction)) {
                calls.add(new IcallSite(instruction.getAddress(), oneLine(instruction.toString())));
            }
        }
        return calls;
    }

    private List<String> collectCStatements(String cCode) {
        List<String> statements = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (String rawLine : cCode.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("/*") ||
                (line.startsWith("*") && !line.startsWith("*("))) {
                continue;
            }
            if (current.length() > 0) {
                current.append(' ');
            }
            current.append(line);
            if (line.endsWith(";") || line.endsWith("{") || line.endsWith("}")) {
                statements.add(current.toString());
                current.setLength(0);
            }
        }
        if (current.length() > 0) {
            statements.add(current.toString());
        }
        return statements;
    }

    private boolean mentionsTarget(String line, TargetFunction target) {
        return line.contains(target.name) || line.contains("PTR_" + target.name + "_");
    }

    private boolean isTargetExpression(String expression, TargetFunction target, Set<String> aliases) {
        String normalized = stripExpressionNoise(expression);
        return aliases.contains(normalized) ||
            target.name.equals(normalized) ||
            normalized.startsWith("PTR_" + target.name + "_");
    }

    private String stripExpressionNoise(String expression) {
        String normalized = oneLine(expression)
            .replace("&", "")
            .replace(";", "")
            .trim();
        while (normalized.startsWith("(") && normalized.endsWith(")") &&
            findMatchingOpenParen(normalized, normalized.length() - 1) == 0) {
            normalized = normalized.substring(1, normalized.length() - 1).trim();
        }
        return normalized;
    }

    private boolean looksLikeIndirectCallLine(String line) {
        return line.contains("(*(code *)") ||
            line.contains("(**(code **)") ||
            SIMPLE_INDIRECT_CALL.matcher(line).find();
    }

    private boolean lineMentionsByteOffset(String line, String paramName, int byteOffset) {
        if (byteOffset % 4 == 0 && line.contains(paramName + "[0x" + Integer.toHexString(byteOffset / 4) + "]")) {
            return true;
        }
        if (byteOffset % 4 == 0 && line.contains(paramName + "[" + (byteOffset / 4) + "]")) {
            return true;
        }
        if (line.contains(paramName + " + 0x" + Integer.toHexString(byteOffset))) {
            return true;
        }
        return line.contains(paramName + " + " + byteOffset);
    }

    private Integer parseLocalOffset(String localName) {
        int underscore = localName.lastIndexOf('_');
        if (underscore < 0 || underscore == localName.length() - 1) {
            return null;
        }
        try {
            return Integer.parseUnsignedInt(localName.substring(underscore + 1), 16);
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private Integer parseNumber(String value) {
        try {
            if (value.startsWith("0x") || value.startsWith("0X")) {
                return Integer.parseUnsignedInt(value.substring(2), 16);
            }
            return Integer.parseUnsignedInt(value, 10);
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private Function resolvePointerLabelFunction(String line) {
        Matcher matcher = PTR_LABEL.matcher(line);
        while (matcher.find()) {
            Address pointerAddress = toAddr(Long.parseUnsignedLong(matcher.group(2), 16));
            Function function = readPointerFunction(pointerAddress);
            if (function != null) {
                return function;
            }
            function = findNamedFunction(matcher.group(1));
            if (function != null) {
                return function;
            }
        }
        return null;
    }

    private Function readPointerFunction(Address pointerAddress) {
        try {
            Memory memory = currentProgram.getMemory();
            int raw = memory.getInt(pointerAddress);
            Address targetAddress = toAddr(Integer.toUnsignedLong(raw));
            Function function = functionManager.getFunctionAt(targetAddress);
            if (function != null) {
                return function;
            }
            return functionManager.getFunctionContaining(targetAddress);
        } catch (Exception ignored) {
            return null;
        }
    }

    private Address resolveDataPointerExpression(String expression) {
        String normalized = stripExpressionNoise(expression);
        Matcher matcher = DAT_LABEL.matcher(normalized);
        if (matcher.find()) {
            Address pointerAddress = toAddr(Long.parseUnsignedLong(matcher.group(1), 16));
            try {
                int raw = currentProgram.getMemory().getInt(pointerAddress);
                return toAddr(Integer.toUnsignedLong(raw));
            } catch (Exception ignored) {
                return null;
            }
        }

        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(normalized);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getAddress() != null) {
                return symbol.getAddress();
            }
        }
        return null;
    }

    private Function findNamedFunction(String name) {
        FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (name.equals(function.getName())) {
                return function;
            }
        }
        return null;
    }

    private List<String> parseCallArguments(String line) {
        int closeParen = line.lastIndexOf(')');
        int openParen = findMatchingOpenParen(line, closeParen);
        if (openParen < 0 || closeParen <= openParen) {
            return List.of();
        }
        String argsText = line.substring(openParen + 1, closeParen);
        List<String> args = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int depth = 0;
        for (int i = 0; i < argsText.length(); i++) {
            char ch = argsText.charAt(i);
            if (ch == '(' || ch == '[' || ch == '{') {
                depth++;
            } else if (ch == ')' || ch == ']' || ch == '}') {
                depth = Math.max(0, depth - 1);
            } else if (ch == ',' && depth == 0) {
                args.add(current.toString().trim());
                current.setLength(0);
                continue;
            }
            current.append(ch);
        }
        if (current.length() > 0 || !argsText.isBlank()) {
            args.add(current.toString().trim());
        }
        return args;
    }

    private int findMatchingOpenParen(String line, int closeParen) {
        if (closeParen < 0) {
            return -1;
        }
        int depth = 0;
        for (int i = closeParen; i >= 0; i--) {
            char ch = line.charAt(i);
            if (ch == ')') {
                depth++;
            } else if (ch == '(') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private List<UsageRecord> dedupeRecords(List<UsageRecord> records) {
        List<UsageRecord> deduped = new ArrayList<>();
        Set<String> seen = new TreeSet<>();
        for (UsageRecord record : records) {
            String key = String.join("|",
                record.targetAddress,
                record.targetName,
                record.field,
                record.storeAddress,
                record.storeFunction,
                record.useAddress,
                record.useFunction,
                record.icallAddress,
                record.context,
                record.kind
            );
            if (seen.add(key)) {
                deduped.add(record);
            }
        }
        return deduped;
    }

    private Set<FieldStore> findFieldStores(TargetFunction target) {
        Set<FieldStore> fieldStores = new HashSet<>();
        for (Reference reference : referenceManager.getReferencesTo(target.address)) {
            Address fromAddress = reference.getFromAddress();
            Function containingFunction = functionManager.getFunctionContaining(fromAddress);
            if (containingFunction == null) {
                continue;
            }

            DecompileResults results = decompile(containingFunction);
            if (results == null || results.getCCodeMarkup() == null) {
                continue;
            }

            for (ClangLine line : collectLines(results.getCCodeMarkup())) {
                FieldStore store = fieldStoreFromLine(target, containingFunction, fromAddress, line);
                if (store != null) {
                    fieldStores.add(store);
                }
            }
        }
        return fieldStores;
    }

    private FieldStore fieldStoreFromLine(
        TargetFunction target,
        Function containingFunction,
        Address fromAddress,
        ClangLine line
    ) {
        List<ClangToken> tokens = line.getAllTokens();
        int targetIndex = -1;
        int equalsIndex = -1;
        for (int i = 0; i < tokens.size(); i++) {
            String text = tokens.get(i).getText();
            if ("=".equals(text)) {
                equalsIndex = i;
            }
            if (target.name.equals(text)) {
                targetIndex = i;
            }
        }
        if (targetIndex < 0 || equalsIndex < 0 || equalsIndex > targetIndex) {
            return null;
        }

        ClangFieldToken chosenField = null;
        for (int i = equalsIndex - 1; i >= 0; i--) {
            ClangToken token = tokens.get(i);
            if (token instanceof ClangFieldToken) {
                chosenField = (ClangFieldToken) token;
                break;
            }
        }
        if (chosenField == null || chosenField.getDataType() == null) {
            return null;
        }

        return new FieldStore(
            chosenField.getDataType(),
            chosenField.getText(),
            chosenField.getOffset(),
            fromAddress,
            containingFunction,
            oneLine(lineText(line))
        );
    }

    private IcallSite findNearbyIndirectCall(Function function, Address useAddress) {
        if (function == null || useAddress == null) {
            return null;
        }

        InstructionIterator instructions =
            currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Address address = instruction.getAddress();
            if (address.compareTo(useAddress) < 0) {
                continue;
            }
            if (address.subtract(useAddress) > INDIRECT_CALL_SEARCH_BYTES) {
                return null;
            }
            if (isIndirectCall(instruction)) {
                return new IcallSite(address, oneLine(instruction.toString()));
            }
        }
        return null;
    }

    private boolean isIndirectCall(Instruction instruction) {
        FlowType flowType = instruction.getFlowType();
        if (flowType == null || !flowType.isComputed() || !flowType.isCall()) {
            return false;
        }

        boolean hasRegisterOperand = false;
        boolean hasScalarOperand = false;
        for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++) {
            Object[] operandObjects = instruction.getOpObjects(operandIndex);
            for (Object operandObject : operandObjects) {
                if (operandObject == null) {
                    continue;
                }
                String className = operandObject.getClass().getSimpleName();
                if (className.contains("Register")) {
                    hasRegisterOperand = true;
                } else if (className.contains("Scalar")) {
                    hasScalarOperand = true;
                }
            }
        }
        return hasRegisterOperand && !hasScalarOperand;
    }

    private DecompileResults decompile(Function function) {
        if (function == null) {
            return null;
        }
        return decompileCache.computeIfAbsent(
            function.getEntryPoint(),
            ignored -> {
                DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
                if (results == null || !results.decompileCompleted()) {
                    return null;
                }
                return results;
            }
        );
    }

    private List<ClangLine> collectLines(ClangTokenGroup root) {
        List<ClangNode> nodes = new ArrayList<>();
        root.flatten(nodes);
        List<ClangLine> lines = new ArrayList<>();
        Set<ClangLine> seen = new HashSet<>();
        for (ClangNode node : nodes) {
            if (!(node instanceof ClangToken)) {
                continue;
            }
            ClangLine line = ((ClangToken) node).getLineParent();
            if (line != null && seen.add(line)) {
                lines.add(line);
            }
        }
        return lines;
    }

    private String lineText(ClangLine line) {
        StringBuilder builder = new StringBuilder();
        for (ClangToken token : line.getAllTokens()) {
            builder.append(token.getText());
        }
        return builder.toString();
    }

    private void writeRecords(Path outputPath, List<UsageRecord> records) throws IOException {
        Files.createDirectories(outputPath.getParent());
        try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(outputPath))) {
            writer.println(
                "target_address\ttarget_name\tfield\tstore_address\tstore_function\t" +
                "field_use_address\tfield_use_function\ticall_address\ticall_text\tcontext\tkind"
            );
            for (UsageRecord record : records) {
                writer.println(String.join("\t",
                    tsv(record.targetAddress),
                    tsv(record.targetName),
                    tsv(record.field),
                    tsv(record.storeAddress),
                    tsv(record.storeFunction),
                    tsv(record.useAddress),
                    tsv(record.useFunction),
                    tsv(record.icallAddress),
                    tsv(record.icallText),
                    tsv(record.context),
                    tsv(record.kind)
                ));
            }
        }
    }

    private Path resolveScriptPath(String filename) {
        return Path.of(getSourceFile().getParentFile().getAbsolutePath(), filename);
    }

    private String safeAddressString(Address address) {
        return address == null ? "" : address.toString();
    }

    private String safeFunctionName(Function function) {
        return function == null ? "" : function.getName();
    }

    private String oneLine(String value) {
        return value == null ? "" : value.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ').trim();
    }

    private String tsv(String value) {
        return oneLine(value);
    }

    private static final class TargetFunction {
        private final Address address;
        private final String name;
        private final Function function;

        private TargetFunction(Address address, String name, Function function) {
            this.address = address;
            this.name = name;
            this.function = function;
        }
    }

    private static final class FieldStore {
        private final DataType dataType;
        private final String fieldName;
        private final int fieldOffset;
        private final Address storeAddress;
        private final Function storeFunction;
        private final String contextLine;

        private FieldStore(
            DataType dataType,
            String fieldName,
            int fieldOffset,
            Address storeAddress,
            Function storeFunction,
            String contextLine
        ) {
            this.dataType = dataType;
            this.fieldName = fieldName;
            this.fieldOffset = fieldOffset;
            this.storeAddress = storeAddress;
            this.storeFunction = storeFunction;
            this.contextLine = contextLine;
        }

        private FieldKey key() {
            return new FieldKey(dataType, fieldOffset);
        }

        private String fieldDisplay() {
            return dataType.getName() + "." + fieldName + "+" + fieldOffset;
        }

        @Override
        public int hashCode() {
            return Objects.hash(dataType, fieldName, fieldOffset, storeAddress, storeFunction.getEntryPoint());
        }

        @Override
        public boolean equals(Object object) {
            if (!(object instanceof FieldStore)) {
                return false;
            }
            FieldStore other = (FieldStore) object;
            return Objects.equals(dataType, other.dataType) &&
                Objects.equals(fieldName, other.fieldName) &&
                fieldOffset == other.fieldOffset &&
                Objects.equals(storeAddress, other.storeAddress) &&
                Objects.equals(storeFunction.getEntryPoint(), other.storeFunction.getEntryPoint());
        }
    }

    private static final class FieldKey {
        private final DataType dataType;
        private final int offset;

        private FieldKey(DataType dataType, int offset) {
            this.dataType = dataType;
            this.offset = offset;
        }

        @Override
        public int hashCode() {
            return Objects.hash(dataType, offset);
        }

        @Override
        public boolean equals(Object object) {
            if (!(object instanceof FieldKey)) {
                return false;
            }
            FieldKey other = (FieldKey) object;
            return Objects.equals(dataType, other.dataType) && offset == other.offset;
        }
    }

    private static final class IcallSite {
        private final Address address;
        private final String text;

        private IcallSite(Address address, String text) {
            this.address = address;
            this.text = text;
        }
    }

    private static final class ParamUse {
        private final String contextAddress;
        private final String icallAddress;
        private final String icallText;
        private final String context;

        private ParamUse(String contextAddress, String icallAddress, String icallText, String context) {
            this.contextAddress = contextAddress;
            this.icallAddress = icallAddress;
            this.icallText = icallText;
            this.context = context;
        }
    }

    private static final class PointerAlias {
        private final String baseVariable;
        private final int offset;

        private PointerAlias(String baseVariable, int offset) {
            this.baseVariable = baseVariable;
            this.offset = offset;
        }
    }

    private static final class RegistrationSite {
        private final String functionName;
        private final String contextAddress;
        private final String context;

        private RegistrationSite(String functionName, String contextAddress, String context) {
            this.functionName = functionName;
            this.contextAddress = contextAddress;
            this.context = context;
        }
    }

    private static final class UsageRecord {
        private final String targetAddress;
        private final String targetName;
        private final String field;
        private final String storeAddress;
        private final String storeFunction;
        private final String useAddress;
        private final String useFunction;
        private final String icallAddress;
        private final String icallText;
        private final String context;
        private final String kind;

        private UsageRecord(
            TargetFunction target,
            String field,
            String storeAddress,
            String storeFunction,
            String useAddress,
            String useFunction,
            String icallAddress,
            String icallText,
            String context,
            String kind
        ) {
            this.targetAddress = target.address.toString();
            this.targetName = target.name;
            this.field = field;
            this.storeAddress = storeAddress;
            this.storeFunction = storeFunction;
            this.useAddress = useAddress;
            this.useFunction = useFunction;
            this.icallAddress = icallAddress;
            this.icallText = icallText;
            this.context = context;
            this.kind = kind;
        }
    }
}

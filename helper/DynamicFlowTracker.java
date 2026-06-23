package helper;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

public final class DynamicFlowTracker implements AutoCloseable {
    private static final String EMUL_SUFFIX = ".emul";
    private static final String DYNAMIC_FLOW_LOG_FILENAME = "dynamic_flow.tsv";
    private static final String DYNAMIC_FLOW_BOOKMARK_TYPE = "DynamicFlow";
    private static final String INDIRECT_FLOW_BOOKMARK_CATEGORY = "IndirectFlowCovered";

    private final Context context;
    private final Logger logger;
    private final ReferenceManager referenceManager;
    private final boolean enabled;
    private final Path flowLogPath;
    private final Set<String> loggedFlowKeys = new HashSet<>();

    private BufferedWriter flowLogWriter;
    private int transactionId = -1;
    private int loggedCount = 0;
    private int loggedUseropCount = 0;
    private int appliedReferenceCount = 0;
    private int coveredBookmarkCount = 0;
    private int skippedRepeatedObservationCount = 0;
    private int skippedDuplicateReferenceCount = 0;
    private int skippedMissingFunctionCount = 0;
    private int skippedMalformedLogCount = 0;

    public DynamicFlowTracker(Context context, Logger logger) {
        this.context = context;
        this.logger = logger;
        this.referenceManager = context.currentProgram.getReferenceManager();
        this.enabled = isEmulatedProgram(context.currentProgram.getDomainFile());
        this.flowLogPath = logger.resolveLogPath(DYNAMIC_FLOW_LOG_FILENAME);

        if (enabled) {
            openFlowLog();
            logger.println(
                "Dynamic flow logging enabled for " + getProgramName() + " -> " + flowLogPath,
                6
            );
        } else {
            logger.println("Dynamic flow logging disabled for " + getProgramName(), 6);
        }
    }

    public void recordComputedFlow(Instruction instruction, Address nextAddress) {
        if (!enabled || instruction == null || nextAddress == null) {
            return;
        }

        FlowType flowType = instruction.getFlowType();
        if (flowType == null || !flowType.isComputed() || (!flowType.isCall() && !flowType.isJump())) {
            return;
        }

        Address fallthrough = instruction.getFallThrough();
        if (fallthrough != null && fallthrough.equals(nextAddress) && flowType.hasFallthrough()) {
            return;
        }

        recordFlow(
            instruction,
            nextAddress,
            getReferenceType(flowType),
            flowType.isCall() ? "dynamic call" : "dynamic jump",
            false,
            false
        );
    }

    public boolean recordUseropFlow(Instruction instruction, Address nextAddress, String useropName) {
        if (!enabled || instruction == null || nextAddress == null) {
            return false;
        }

        if (instruction.getAddress().equals(nextAddress)) {
            return false;
        }

        Address fallthrough = instruction.getFallThrough();
        if (fallthrough != null && fallthrough.equals(nextAddress)) {
            return false;
        }

        RefType referenceType = isSupervisorCall(instruction, useropName)
            ? RefType.COMPUTED_CALL
            : RefType.COMPUTED_JUMP;
        return recordFlow(
            instruction,
            nextAddress,
            referenceType,
            "userop " + useropName,
            true,
            true
        );
    }

    private boolean recordFlow(
        Instruction instruction,
        Address nextAddress,
        RefType referenceType,
        String reason,
        boolean allowExternalTarget,
        boolean userop
    ) {
        if (referenceType == null) {
            return false;
        }

        Function sourceFunction =
            context.currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
        if (sourceFunction == null) {
            skippedMissingFunctionCount++;
            return false;
        }

        DynamicFlowRecord record = new DynamicFlowRecord(
            instruction.getAddress(),
            nextAddress,
            getReferenceTypeName(referenceType),
            reason,
            allowExternalTarget
        );
        String key = record.key();
        if (!loggedFlowKeys.add(key)) {
            skippedRepeatedObservationCount++;
            return false;
        }

        writeLogRecord(record);
        loggedCount++;
        if (userop) {
            loggedUseropCount++;
        }

        logger.println(String.format(
            "Logged %s flow: %s (%s) -> %s",
            reason,
            instruction.getAddress(),
            sourceFunction.getName(),
            nextAddress
        ), 6);
        return true;
    }

    private void openFlowLog() {
        try {
            Files.createDirectories(flowLogPath.getParent());
            flowLogWriter = Files.newBufferedWriter(flowLogPath, StandardCharsets.UTF_8);
            flowLogWriter.write("from_address\tto_address\treference_type\treason\tallow_external_target");
            flowLogWriter.newLine();
        } catch (IOException e) {
            throw new RuntimeException("Failed to open dynamic flow log: " + flowLogPath, e);
        }
    }

    private void writeLogRecord(DynamicFlowRecord record) {
        try {
            flowLogWriter.write(record.toTsvLine());
            flowLogWriter.newLine();
            flowLogWriter.flush();
        } catch (IOException e) {
            throw new RuntimeException("Failed to write dynamic flow log: " + flowLogPath, e);
        }
    }

    private void closeFlowLog() {
        if (flowLogWriter == null) {
            return;
        }
        try {
            flowLogWriter.close();
        } catch (IOException e) {
            throw new RuntimeException("Failed to close dynamic flow log: " + flowLogPath, e);
        } finally {
            flowLogWriter = null;
        }
    }

    private void applyLoggedFlows() {
        if (!Files.exists(flowLogPath)) {
            logger.println("Dynamic flow log does not exist: " + flowLogPath, 6);
            return;
        }

        transactionId = context.currentProgram.startTransaction("apply emulated dynamic flow log");
        boolean commit = false;
        try {
            for (String line : Files.readAllLines(flowLogPath, StandardCharsets.UTF_8)) {
                if (line.isBlank() || line.startsWith("from_address\t")) {
                    continue;
                }
                DynamicFlowRecord record = parseLogRecord(line);
                if (record == null) {
                    skippedMalformedLogCount++;
                    continue;
                }
                applyLogRecord(record);
            }
            commit = true;
        } catch (IOException e) {
            throw new RuntimeException("Failed to read dynamic flow log: " + flowLogPath, e);
        } finally {
            context.currentProgram.endTransaction(transactionId, commit);
            transactionId = -1;
        }
    }

    private DynamicFlowRecord parseLogRecord(String line) {
        String[] parts = line.split("\t", -1);
        if (parts.length != 5) {
            return null;
        }

        Address fromAddress = context.currentProgram.getAddressFactory().getAddress(parts[0]);
        Address toAddress = context.currentProgram.getAddressFactory().getAddress(parts[1]);
        if (fromAddress == null || toAddress == null || parseReferenceType(parts[2]) == null) {
            return null;
        }

        return new DynamicFlowRecord(
            fromAddress,
            toAddress,
            parts[2],
            decodeField(parts[3]),
            Boolean.parseBoolean(parts[4])
        );
    }

    private boolean applyLogRecord(DynamicFlowRecord record) {
        RefType referenceType = parseReferenceType(record.referenceTypeName);
        if (referenceType == null) {
            skippedMalformedLogCount++;
            return false;
        }

        Instruction instruction = context.currentProgram.getListing().getInstructionAt(record.fromAddress);
        if (instruction == null) {
            skippedMissingFunctionCount++;
            return false;
        }

        Function sourceFunction =
            context.currentProgram.getFunctionManager().getFunctionContaining(record.fromAddress);
        Function targetFunction =
            context.currentProgram.getFunctionManager().getFunctionContaining(record.toAddress);

        if (sourceFunction == null) {
            skippedMissingFunctionCount++;
            return false;
        }

        if (markIndirectFlowCovered(instruction, record.toAddress, record.reason)) {
            coveredBookmarkCount++;
        }

        if (targetFunction == null && !record.allowExternalTarget) {
            skippedMissingFunctionCount++;
            return false;
        }

        if (targetFunction != null && sourceFunction.equals(targetFunction)) {
            return false;
        }

        if (hasFlowReference(record.fromAddress, record.toAddress, referenceType)) {
            skippedDuplicateReferenceCount++;
            return false;
        }

        referenceManager.addMemoryReference(
            record.fromAddress,
            record.toAddress,
            referenceType,
            SourceType.USER_DEFINED,
            ReferenceManager.MNEMONIC
        );
        appliedReferenceCount++;

        String targetName = targetFunction == null
            ? record.toAddress.toString()
            : targetFunction.getName();
        logger.println(String.format(
            "Applied %s flow: %s (%s) -> %s (%s)",
            record.reason,
            record.fromAddress,
            sourceFunction.getName(),
            record.toAddress,
            targetName
        ), 6);
        return true;
    }

    private boolean markIndirectFlowCovered(Instruction instruction, Address nextAddress, String reason) {
        String entry = reason + " -> " + nextAddress;
        Bookmark bookmark = context.currentProgram.getBookmarkManager().getBookmark(
            instruction.getAddress(),
            DYNAMIC_FLOW_BOOKMARK_TYPE,
            INDIRECT_FLOW_BOOKMARK_CATEGORY
        );
        if (bookmark == null) {
            context.currentProgram.getBookmarkManager().setBookmark(
                instruction.getAddress(),
                DYNAMIC_FLOW_BOOKMARK_TYPE,
                INDIRECT_FLOW_BOOKMARK_CATEGORY,
                entry
            );
            return true;
        }

        String comment = bookmark.getComment();
        if (comment == null || comment.isBlank()) {
            bookmark.set(INDIRECT_FLOW_BOOKMARK_CATEGORY, entry);
            return true;
        }
        if (!comment.contains(nextAddress.toString())) {
            bookmark.set(INDIRECT_FLOW_BOOKMARK_CATEGORY, comment + "; " + entry);
            return true;
        }
        return false;
    }

    private boolean isSupervisorCall(Instruction instruction, String useropName) {
        return "SCALL".equals(instruction.getMnemonicString()) ||
            (useropName != null && useropName.contains("SupervisorCallSetup"));
    }

    private boolean hasFlowReference(Address fromAddress, Address toAddress, RefType referenceType) {
        for (Reference reference : referenceManager.getFlowReferencesFrom(fromAddress)) {
            if (!toAddress.equals(reference.getToAddress())) {
                continue;
            }
            if (referenceType.equals(reference.getReferenceType())) {
                return true;
            }
        }
        return false;
    }

    private RefType getReferenceType(FlowType flowType) {
        if (flowType.isCall()) {
            return flowType.isConditional()
                ? RefType.CONDITIONAL_COMPUTED_CALL
                : RefType.COMPUTED_CALL;
        }
        if (flowType.isJump()) {
            return flowType.isConditional()
                ? RefType.CONDITIONAL_COMPUTED_JUMP
                : RefType.COMPUTED_JUMP;
        }
        return null;
    }

    private String getReferenceTypeName(RefType referenceType) {
        if (RefType.CONDITIONAL_COMPUTED_CALL.equals(referenceType)) {
            return "CONDITIONAL_COMPUTED_CALL";
        }
        if (RefType.COMPUTED_CALL.equals(referenceType)) {
            return "COMPUTED_CALL";
        }
        if (RefType.CONDITIONAL_COMPUTED_JUMP.equals(referenceType)) {
            return "CONDITIONAL_COMPUTED_JUMP";
        }
        if (RefType.COMPUTED_JUMP.equals(referenceType)) {
            return "COMPUTED_JUMP";
        }
        return referenceType.toString();
    }

    private RefType parseReferenceType(String referenceTypeName) {
        switch (referenceTypeName) {
            case "CONDITIONAL_COMPUTED_CALL":
                return RefType.CONDITIONAL_COMPUTED_CALL;
            case "COMPUTED_CALL":
                return RefType.COMPUTED_CALL;
            case "CONDITIONAL_COMPUTED_JUMP":
                return RefType.CONDITIONAL_COMPUTED_JUMP;
            case "COMPUTED_JUMP":
                return RefType.COMPUTED_JUMP;
            default:
                return null;
        }
    }

    private String encodeField(String value) {
        if (value == null) {
            return "";
        }
        return value
            .replace("\\", "\\\\")
            .replace("\t", "\\t")
            .replace("\n", "\\n")
            .replace("\r", "\\r");
    }

    private String decodeField(String value) {
        StringBuilder result = new StringBuilder();
        boolean escaping = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!escaping) {
                if (c == '\\') {
                    escaping = true;
                } else {
                    result.append(c);
                }
                continue;
            }

            switch (c) {
                case 't':
                    result.append('\t');
                    break;
                case 'n':
                    result.append('\n');
                    break;
                case 'r':
                    result.append('\r');
                    break;
                default:
                    result.append(c);
                    break;
            }
            escaping = false;
        }
        if (escaping) {
            result.append('\\');
        }
        return result.toString();
    }

    private boolean isEmulatedProgram(DomainFile domainFile) {
        return domainFile != null && domainFile.getName().endsWith(EMUL_SUFFIX);
    }

    private String getProgramName() {
        DomainFile domainFile = context.currentProgram.getDomainFile();
        if (domainFile != null) {
            return domainFile.getName();
        }
        return context.currentProgram.getName();
    }

    @Override
    public void close() {
        if (!enabled) {
            return;
        }

        closeFlowLog();
        applyLoggedFlows();
        logger.println(String.format(
            "Committed dynamic flow metadata: logged=%d userop=%d applied=%d covered=%d repeated=%d duplicate=%d missing-function=%d malformed-log=%d log=%s",
            loggedCount,
            loggedUseropCount,
            appliedReferenceCount,
            coveredBookmarkCount,
            skippedRepeatedObservationCount,
            skippedDuplicateReferenceCount,
            skippedMissingFunctionCount,
            skippedMalformedLogCount,
            flowLogPath
        ), 6);
    }

    private final class DynamicFlowRecord {
        private final Address fromAddress;
        private final Address toAddress;
        private final String referenceTypeName;
        private final String reason;
        private final boolean allowExternalTarget;

        private DynamicFlowRecord(
            Address fromAddress,
            Address toAddress,
            String referenceTypeName,
            String reason,
            boolean allowExternalTarget
        ) {
            this.fromAddress = fromAddress;
            this.toAddress = toAddress;
            this.referenceTypeName = referenceTypeName;
            this.reason = reason;
            this.allowExternalTarget = allowExternalTarget;
        }

        private String key() {
            return fromAddress + "\t" + toAddress + "\t" + referenceTypeName + "\t" + reason;
        }

        private String toTsvLine() {
            return fromAddress + "\t" +
                toAddress + "\t" +
                referenceTypeName + "\t" +
                encodeField(reason) + "\t" +
                allowExternalTarget;
        }
    }
}

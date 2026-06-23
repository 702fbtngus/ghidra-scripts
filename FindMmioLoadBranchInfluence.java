import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindMmioLoadBranchInfluence extends GhidraScript {
    private static final Pattern DEVICE_LOAD_LINE = Pattern.compile(
        "^\\[(.*?)\\]\\s+Load from\\s+(\\S+)\\s+@\\s+(0x[0-9A-Fa-f]+)"
    );
    private static final Pattern INSTR_LINE = Pattern.compile("^\\[(.*?)\\]\\s+\\d+");
    private static final Pattern PC_IN_HEADER = Pattern.compile("\\b(0x[0-9A-Fa-f]+)\\b");
    private static final long U32_MASK = 0xffffffffL;

    private record SiteKey(long pc, String device, long mmio) {}

    private static final class LoadEvent {
        final String header;
        final SiteKey site;
        final String firstLog;

        LoadEvent(String header, SiteKey site, String firstLog) {
            this.header = header;
            this.site = site;
            this.firstLog = firstLog;
        }
    }

    private record VarnodeKey(String space, long offset, int size) {
        static VarnodeKey of(Varnode varnode) {
            return new VarnodeKey(
                varnode.getAddress().getAddressSpace().getName(),
                varnode.getOffset(),
                varnode.getSize()
            );
        }
    }

    private static final class CompareInfo {
        final long pc;
        final int step;
        final String instruction;
        final String op;
        final String operands;

        CompareInfo(long pc, int step, String instruction, String op, String operands) {
            this.pc = pc;
            this.step = step;
            this.instruction = instruction;
            this.op = op;
            this.operands = operands;
        }
    }

    private static final class TaintInfo {
        final CompareInfo compare;

        TaintInfo(CompareInfo compare) {
            this.compare = compare;
        }

        TaintInfo withCompare(CompareInfo newCompare) {
            if (compare != null) {
                return this;
            }
            return new TaintInfo(newCompare);
        }
    }

    private record HitKey(
        long loadPc,
        String device,
        long mmio,
        long comparePc,
        long branchPc,
        String branchDecision
    ) {}

    private static final class HitRow {
        final HitKey key;
        int count;
        String loadFunction = "";
        String compareInstruction = "";
        String compareOp = "";
        String compareOperands = "";
        int compareStep;
        String branchInstruction = "";
        int branchStep;
        String firstLog = "";

        HitRow(HitKey key) {
            this.key = key;
        }
    }

    private static final class Hit {
        final CompareInfo compare;
        final long branchPc;
        final int branchStep;
        final String branchInstruction;
        final String branchDecision;

        Hit(CompareInfo compare, long branchPc, int branchStep, String branchInstruction, String branchDecision) {
            this.compare = compare;
            this.branchPc = branchPc;
            this.branchStep = branchStep;
            this.branchInstruction = branchInstruction;
            this.branchDecision = branchDecision;
        }
    }

    private static final class LongList {
        private long[] values = new long[1024];
        private int size;

        void add(long value) {
            if (size == values.length) {
                long[] next = new long[values.length * 2];
                System.arraycopy(values, 0, next, 0, values.length);
                values = next;
            }
            values[size++] = value;
        }

        long get(int index) {
            return values[index];
        }

        int size() {
            return size;
        }
    }

    @Override
    public void run() throws Exception {
        Path deviceLogDir = Paths.get("log/device");
        Path instrLog = Paths.get("log/instr.log");
        Path outPath = Paths.get("log/device_load_branch_influence.tsv");
        int window = 10;
        boolean printAll = false;

        for (String arg : getScriptArgs()) {
            if (arg.startsWith("--device-log-dir=")) {
                deviceLogDir = Paths.get(arg.substring("--device-log-dir=".length()));
            } else if (arg.startsWith("--instr-log=")) {
                instrLog = Paths.get(arg.substring("--instr-log=".length()));
            } else if (arg.startsWith("--out=")) {
                outPath = Paths.get(arg.substring("--out=".length()));
            } else if (arg.startsWith("--window=")) {
                window = Integer.parseInt(arg.substring("--window=".length()));
            } else if (arg.equals("--print-all")) {
                printAll = true;
            } else {
                throw new IllegalArgumentException("Unknown argument: " + arg);
            }
        }

        List<LoadEvent> loadEvents = readLoadEvents(deviceLogDir);
        Set<String> neededHeaders = new HashSet<>();
        for (LoadEvent event : loadEvents) {
            neededHeaders.add(event.header);
        }

        Map<String, Integer> traceIndexByHeader = new HashMap<>();
        LongList tracePcs = readInstructionTrace(instrLog, neededHeaders, traceIndexByHeader);
        AnalysisResult result = analyzeEvents(loadEvents, tracePcs, traceIndexByHeader, window);
        writeRows(outPath, result.rows);
        printSummary(deviceLogDir, instrLog, outPath, window, loadEvents, tracePcs, result, printAll);
    }

    private List<LoadEvent> readLoadEvents(Path deviceLogDir) throws IOException {
        List<LoadEvent> events = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(deviceLogDir, "*.log")) {
            for (Path file : stream) {
                readLoadEventsFromFile(file, events);
            }
        }
        return events;
    }

    private void readLoadEventsFromFile(Path file, List<LoadEvent> events) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                Matcher matcher = DEVICE_LOAD_LINE.matcher(line);
                if (!matcher.find()) {
                    continue;
                }

                String header = matcher.group(1);
                Long pc = pcFromHeader(header);
                if (pc == null) {
                    continue;
                }
                String device = matcher.group(2);
                long mmio = Long.decode(matcher.group(3)) & U32_MASK;
                events.add(new LoadEvent(
                    header,
                    new SiteKey(pc & U32_MASK, device, mmio),
                    file + ":" + lineNumber
                ));
            }
        }
    }

    private LongList readInstructionTrace(
        Path instrLog,
        Set<String> neededHeaders,
        Map<String, Integer> traceIndexByHeader
    ) throws IOException {
        LongList tracePcs = new LongList();
        try (BufferedReader reader = Files.newBufferedReader(instrLog, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                Matcher matcher = INSTR_LINE.matcher(line);
                if (!matcher.find()) {
                    continue;
                }

                String header = matcher.group(1);
                Long pc = pcFromHeader(header);
                if (pc == null) {
                    continue;
                }

                int index = tracePcs.size();
                tracePcs.add(pc & U32_MASK);
                if (neededHeaders.contains(header)) {
                    traceIndexByHeader.putIfAbsent(header, index);
                }
            }
        }
        return tracePcs;
    }

    private static final class AnalysisResult {
        final List<HitRow> rows;
        int matchedTraceEvents;
        int noLoadPcodeEvents;
        int hitEvents;

        AnalysisResult(List<HitRow> rows) {
            this.rows = rows;
        }
    }

    private AnalysisResult analyzeEvents(
        List<LoadEvent> loadEvents,
        LongList tracePcs,
        Map<String, Integer> traceIndexByHeader,
        int window
    ) {
        Map<HitKey, HitRow> rowsByKey = new LinkedHashMap<>();
        AnalysisResult result = new AnalysisResult(new ArrayList<>());

        for (LoadEvent event : loadEvents) {
            if (monitor.isCancelled()) {
                break;
            }

            Integer traceIndex = traceIndexByHeader.get(event.header);
            if (traceIndex == null) {
                continue;
            }
            result.matchedTraceEvents++;

            Hit hit = analyzeEvent(event, traceIndex, tracePcs, window);
            if (hit == null) {
                continue;
            }
            if (hit.compare == null) {
                result.noLoadPcodeEvents++;
                continue;
            }

            result.hitEvents++;
            HitKey key = new HitKey(
                event.site.pc(),
                event.site.device(),
                event.site.mmio(),
                hit.compare.pc,
                hit.branchPc,
                hit.branchDecision
            );
            HitRow row = rowsByKey.computeIfAbsent(key, HitRow::new);
            row.count++;
            if (row.firstLog.isEmpty()) {
                row.loadFunction = functionName(event.site.pc());
                row.compareInstruction = hit.compare.instruction;
                row.compareOp = hit.compare.op;
                row.compareOperands = hit.compare.operands;
                row.compareStep = hit.compare.step;
                row.branchInstruction = hit.branchInstruction;
                row.branchStep = hit.branchStep;
                row.firstLog = event.firstLog;
            }
        }

        result.rows.addAll(rowsByKey.values());
        result.rows.sort((left, right) -> {
            int countCompare = Integer.compare(right.count, left.count);
            if (countCompare != 0) {
                return countCompare;
            }
            int pcCompare = Long.compare(left.key.loadPc(), right.key.loadPc());
            if (pcCompare != 0) {
                return pcCompare;
            }
            return Long.compare(left.key.branchPc(), right.key.branchPc());
        });
        return result;
    }

    private Hit analyzeEvent(LoadEvent event, int traceIndex, LongList tracePcs, int window) {
        Map<VarnodeKey, TaintInfo> taint = new HashMap<>();
        Instruction loadInstruction = getInstructionAt(toAddr(event.site.pc()));
        if (loadInstruction == null) {
            return null;
        }

        boolean initialized = initializeLoadTaint(loadInstruction, taint);
        if (!initialized) {
            return new Hit(null, 0, 0, "", "");
        }

        int maxStep = Math.min(window, tracePcs.size() - traceIndex - 1);
        for (int step = 1; step <= maxStep; step++) {
            long pc = tracePcs.get(traceIndex + step);
            Instruction instruction = getInstructionAt(toAddr(pc));
            if (instruction == null) {
                continue;
            }

            Hit hit = processInstruction(instruction, taint, step, traceIndex + step, tracePcs);
            if (hit != null) {
                return hit;
            }
        }

        return null;
    }

    private boolean initializeLoadTaint(Instruction instruction, Map<VarnodeKey, TaintInfo> taint) {
        boolean sawLoad = false;
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.LOAD && op.getOutput() != null) {
                taint.put(VarnodeKey.of(op.getOutput()), new TaintInfo(null));
                sawLoad = true;
                continue;
            }

            updateTaintForOutput(op, instruction, taint, 0);
        }
        removeUniqueTaints(taint);
        return sawLoad;
    }

    private Hit processInstruction(
        Instruction instruction,
        Map<VarnodeKey, TaintInfo> taint,
        int step,
        int traceIndex,
        LongList tracePcs
    ) {
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() == PcodeOp.CBRANCH && op.getNumInputs() >= 2) {
                TaintInfo condition = taint.get(VarnodeKey.of(op.getInput(1)));
                if (condition != null && condition.compare != null) {
                    return new Hit(
                        condition.compare,
                        instruction.getAddress().getOffset() & U32_MASK,
                        step,
                        instruction.toString(),
                        branchDecision(instruction, traceIndex, tracePcs)
                    );
                }
            }

            updateTaintForOutput(op, instruction, taint, step);
        }
        removeUniqueTaints(taint);
        return null;
    }

    private void updateTaintForOutput(
        PcodeOp op,
        Instruction instruction,
        Map<VarnodeKey, TaintInfo> taint,
        int step
    ) {
        Varnode output = op.getOutput();
        if (output == null) {
            return;
        }
        if (isStatusRegister(output)) {
            taint.remove(VarnodeKey.of(output));
            return;
        }

        TaintInfo inputTaint = mergedInputTaint(op, taint);
        if (inputTaint == null) {
            taint.remove(VarnodeKey.of(output));
            return;
        }

        if (isCompareLike(op)) {
            inputTaint = inputTaint.withCompare(new CompareInfo(
                instruction.getAddress().getOffset() & U32_MASK,
                step,
                instruction.toString(),
                op.getMnemonic(),
                pcodeInputText(op)
            ));
        }

        taint.put(VarnodeKey.of(output), inputTaint);
    }

    private TaintInfo mergedInputTaint(PcodeOp op, Map<VarnodeKey, TaintInfo> taint) {
        TaintInfo merged = null;
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            if (input == null || input.isConstant()) {
                continue;
            }
            if (isStatusRegister(input)) {
                continue;
            }
            TaintInfo inputTaint = taint.get(VarnodeKey.of(input));
            if (inputTaint == null) {
                continue;
            }
            if (inputTaint.compare != null) {
                return inputTaint;
            }
            merged = inputTaint;
        }
        return merged;
    }

    private void removeUniqueTaints(Map<VarnodeKey, TaintInfo> taint) {
        taint.keySet().removeIf(key -> key.space().equalsIgnoreCase("unique"));
    }

    private boolean isStatusRegister(Varnode varnode) {
        if (varnode == null || varnode.isConstant()) {
            return false;
        }
        return varnode.getAddress().getAddressSpace().getName().equalsIgnoreCase("register")
            && varnode.getOffset() == 0
            && varnode.getSize() == 4;
    }

    private boolean isCompareLike(PcodeOp op) {
        return switch (op.getOpcode()) {
            case PcodeOp.INT_EQUAL,
                PcodeOp.INT_NOTEQUAL,
                PcodeOp.INT_LESS,
                PcodeOp.INT_SLESS,
                PcodeOp.INT_LESSEQUAL,
                PcodeOp.INT_SLESSEQUAL,
                PcodeOp.INT_CARRY,
                PcodeOp.INT_SCARRY,
                PcodeOp.INT_SBORROW,
                PcodeOp.FLOAT_EQUAL,
                PcodeOp.FLOAT_NOTEQUAL,
                PcodeOp.FLOAT_LESS,
                PcodeOp.FLOAT_LESSEQUAL -> true;
            default -> false;
        };
    }

    private String branchDecision(Instruction branchInstruction, int traceIndex, LongList tracePcs) {
        if (traceIndex + 1 >= tracePcs.size()) {
            return "unknown";
        }

        Address fallthrough = branchInstruction.getFallThrough();
        if (fallthrough == null) {
            return "unknown";
        }

        long nextPc = tracePcs.get(traceIndex + 1) & U32_MASK;
        long fallthroughPc = fallthrough.getOffset() & U32_MASK;
        return nextPc == fallthroughPc ? "not_taken" : "taken";
    }

    private Long pcFromHeader(String header) {
        Matcher matcher = PC_IN_HEADER.matcher(header);
        Long pc = null;
        while (matcher.find()) {
            pc = Long.decode(matcher.group(1)) & U32_MASK;
        }
        return pc;
    }

    private String functionName(long pc) {
        Function function = currentProgram.getFunctionManager().getFunctionContaining(toAddr(pc));
        return function == null ? "" : function.getName();
    }

    private String pcodeInputText(PcodeOp op) {
        List<String> inputs = new ArrayList<>();
        for (int i = 0; i < op.getNumInputs(); i++) {
            inputs.add(varnodeText(op.getInput(i)));
        }
        return String.join(", ", inputs);
    }

    private String varnodeText(Varnode varnode) {
        if (varnode == null) {
            return "";
        }
        if (varnode.isConstant()) {
            return String.format("const:0x%X", varnode.getOffset() & U32_MASK);
        }
        return varnode.getAddress() + ":" + varnode.getSize();
    }

    private void writeRows(Path outPath, List<HitRow> rows) throws IOException {
        Path parent = outPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(outPath, StandardCharsets.UTF_8)) {
            writer.write(String.join("\t",
                "load_pc",
                "device",
                "mmio",
                "count",
                "load_function",
                "compare_step",
                "compare_pc",
                "compare_instruction",
                "compare_pcode_op",
                "compare_pcode_inputs",
                "branch_step",
                "branch_pc",
                "branch_instruction",
                "branch_decision",
                "first_log"
            ));
            writer.newLine();

            for (HitRow row : rows) {
                writer.write(String.join("\t",
                    hex(row.key.loadPc()),
                    row.key.device(),
                    hex(row.key.mmio()),
                    Integer.toString(row.count),
                    clean(row.loadFunction),
                    Integer.toString(row.compareStep),
                    hex(row.key.comparePc()),
                    clean(row.compareInstruction),
                    clean(row.compareOp),
                    clean(row.compareOperands),
                    Integer.toString(row.branchStep),
                    hex(row.key.branchPc()),
                    clean(row.branchInstruction),
                    row.key.branchDecision(),
                    clean(row.firstLog)
                ));
                writer.newLine();
            }
        }
    }

    private void printSummary(
        Path deviceLogDir,
        Path instrLog,
        Path outPath,
        int window,
        List<LoadEvent> loadEvents,
        LongList tracePcs,
        AnalysisResult result,
        boolean printAll
    ) {
        println("Device log dir: " + deviceLogDir);
        println("Instruction log: " + instrLog);
        println("Output: " + outPath);
        println("Window: " + window);
        println("Instruction trace entries: " + tracePcs.size());
        println("Load events: " + loadEvents.size());
        println("Load events matched to trace: " + result.matchedTraceEvents);
        println("Events with no LOAD p-code at logged PC: " + result.noLoadPcodeEvents);
        println("Events where loaded value reaches compare-controlled branch: " + result.hitEvents);
        println("Unique hit patterns: " + result.rows.size());

        if (!printAll) {
            return;
        }

        println("");
        println("Rows:");
        for (HitRow row : result.rows) {
            println(String.format(
                "%s\t%s\t%s\tcount=%d\tcmp=%s %s\tbr=%s %s\t%s",
                hex(row.key.loadPc()),
                row.key.device(),
                hex(row.key.mmio()),
                row.count,
                hex(row.key.comparePc()),
                row.compareInstruction,
                hex(row.key.branchPc()),
                row.branchInstruction,
                row.key.branchDecision()
            ));
        }
    }

    private String clean(String value) {
        return value == null ? "" : value.replace('\t', ' ').replace('\n', ' ');
    }

    private String hex(long value) {
        return String.format("0x%08X", value & U32_MASK);
    }
}

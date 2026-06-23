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
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindHardcodedMmioLoads extends GhidraScript {
    private static final Pattern LOAD_LINE = Pattern.compile(
        "\\[.*?\\b(0x[0-9A-Fa-f]+)\\s+[^\\]]*\\]\\s+Load from\\s+(\\S+)\\s+@\\s+(0x[0-9A-Fa-f]+)"
    );

    private static final long U32_MASK = 0xffffffffL;

    private record SiteKey(long pc, String device, long mmio) {}

    private static final class Site {
        final SiteKey key;
        int count;
        String firstFile = "";
        int firstLine;

        Site(SiteKey key) {
            this.key = key;
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

    private record LoadSource(String value, boolean hardcodedMatch) {}

    @Override
    public void run() throws Exception {
        Path logDir = Paths.get("log/device");
        Path outPath = Paths.get("log/device_load_source_analysis.tsv");
        boolean printAll = false;

        for (String arg : getScriptArgs()) {
            if (arg.startsWith("--log-dir=")) {
                logDir = Paths.get(arg.substring("--log-dir=".length()));
            } else if (arg.startsWith("--out=")) {
                outPath = Paths.get(arg.substring("--out=".length()));
            } else if (arg.equals("--print-all")) {
                printAll = true;
            } else {
                throw new IllegalArgumentException("Unknown argument: " + arg);
            }
        }

        Map<SiteKey, Site> sites = readSites(logDir);
        List<Row> rows = analyzeSites(sites);
        writeRows(outPath, rows);
        printSummary(logDir, outPath, rows, printAll);
    }

    private Map<SiteKey, Site> readSites(Path logDir) throws IOException {
        Map<SiteKey, Site> sites = new LinkedHashMap<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(logDir, "*.log")) {
            for (Path file : stream) {
                readSitesFromFile(file, sites);
            }
        }
        return sites;
    }

    private void readSitesFromFile(Path file, Map<SiteKey, Site> sites) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                Matcher matcher = LOAD_LINE.matcher(line);
                if (!matcher.find()) {
                    continue;
                }

                long pc = Long.decode(matcher.group(1)) & U32_MASK;
                String device = matcher.group(2);
                long mmio = Long.decode(matcher.group(3)) & U32_MASK;
                SiteKey key = new SiteKey(pc, device, mmio);
                Site site = sites.computeIfAbsent(key, Site::new);
                site.count++;
                if (site.firstFile.isEmpty()) {
                    site.firstFile = file.toString();
                    site.firstLine = lineNumber;
                }
            }
        }
    }

    private List<Row> analyzeSites(Map<SiteKey, Site> sites) {
        List<Row> rows = new ArrayList<>();
        for (Site site : sites.values()) {
            rows.add(analyzeSite(site));
            if (monitor.isCancelled()) {
                break;
            }
        }
        rows.sort(Comparator
            .comparingLong((Row row) -> row.pc)
            .thenComparing(row -> row.device)
            .thenComparingLong(row -> row.mmio));
        return rows;
    }

    private Row analyzeSite(Site site) {
        Address address = toAddr(site.key.pc());
        Instruction instruction = getInstructionAt(address);
        if (instruction == null) {
            return Row.from(site, "NO_INSTRUCTION", "", "", "", "");
        }

        List<LoadSource> sources = getLoadSources(instruction, site.key.mmio());
        boolean hasHardcodedMatch = sources.stream().anyMatch(LoadSource::hardcodedMatch);
        boolean hasLoadPcode = !sources.isEmpty();
        String status = hasHardcodedMatch
            ? "HARDCODED_LOAD_SOURCE"
            : (hasLoadPcode ? "REGISTER_OR_DYNAMIC_LOAD_SOURCE" : "NO_LOAD_PCODE");

        return Row.from(
            site,
            status,
            functionName(instruction),
            instruction.toString(),
            operandText(instruction),
            sourceText(sources)
        );
    }

    private List<LoadSource> getLoadSources(Instruction instruction, long targetMmio) {
        List<LoadSource> sources = new ArrayList<>();
        Map<VarnodeKey, Long> constants = new HashMap<>();

        for (PcodeOp op : instruction.getPcode()) {
            Long resolved = resolveOutputConstant(op, constants);
            if (op.getOutput() != null) {
                if (resolved == null) {
                    constants.remove(VarnodeKey.of(op.getOutput()));
                } else {
                    constants.put(VarnodeKey.of(op.getOutput()), resolved & U32_MASK);
                }
            }

            if (op.getOpcode() != PcodeOp.LOAD || op.getNumInputs() < 2) {
                continue;
            }

            Varnode source = op.getInput(1);
            Long sourceValue = constantValue(source, constants);
            if (sourceValue == null) {
                sources.add(new LoadSource(varnodeText(source), false));
            } else {
                long normalized = sourceValue & U32_MASK;
                sources.add(new LoadSource(hex(normalized), normalized == (targetMmio & U32_MASK)));
            }
        }

        return sources;
    }

    private Long resolveOutputConstant(PcodeOp op, Map<VarnodeKey, Long> constants) {
        return switch (op.getOpcode()) {
            case PcodeOp.COPY -> constantValue(op.getInput(0), constants);
            case PcodeOp.INT_ADD -> binaryConstant(op, constants, (left, right) -> left + right);
            case PcodeOp.INT_SUB -> binaryConstant(op, constants, (left, right) -> left - right);
            case PcodeOp.INT_AND -> binaryConstant(op, constants, (left, right) -> left & right);
            case PcodeOp.INT_OR -> binaryConstant(op, constants, (left, right) -> left | right);
            case PcodeOp.INT_XOR -> binaryConstant(op, constants, (left, right) -> left ^ right);
            default -> null;
        };
    }

    private interface LongBinary {
        long apply(long left, long right);
    }

    private Long binaryConstant(PcodeOp op, Map<VarnodeKey, Long> constants, LongBinary operation) {
        if (op.getNumInputs() < 2) {
            return null;
        }
        Long left = constantValue(op.getInput(0), constants);
        Long right = constantValue(op.getInput(1), constants);
        if (left == null || right == null) {
            return null;
        }
        return operation.apply(left, right) & U32_MASK;
    }

    private Long constantValue(Varnode varnode, Map<VarnodeKey, Long> constants) {
        if (varnode == null) {
            return null;
        }
        if (varnode.isConstant()) {
            return varnode.getOffset() & U32_MASK;
        }
        return constants.get(VarnodeKey.of(varnode));
    }

    private String functionName(Instruction instruction) {
        Function function = currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
        return function == null ? "" : function.getName();
    }

    private String operandText(Instruction instruction) {
        List<String> operands = new ArrayList<>();
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            operands.add(instruction.getDefaultOperandRepresentation(i));
        }
        return String.join(", ", operands);
    }

    private String sourceText(List<LoadSource> sources) {
        List<String> values = new ArrayList<>();
        for (LoadSource source : sources) {
            values.add(source.value());
        }
        return String.join("; ", values);
    }

    private String varnodeText(Varnode varnode) {
        return varnode.getAddress() + ":" + varnode.getSize();
    }

    private void writeRows(Path outPath, List<Row> rows) throws IOException {
        Path parent = outPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(outPath, StandardCharsets.UTF_8)) {
            writer.write(String.join("\t",
                "status",
                "pc",
                "device",
                "mmio",
                "count",
                "function",
                "instruction",
                "operands",
                "load_sources",
                "first_log"
            ));
            writer.newLine();

            for (Row row : rows) {
                writer.write(String.join("\t",
                    row.status,
                    hex(row.pc),
                    row.device,
                    hex(row.mmio),
                    Integer.toString(row.count),
                    clean(row.function),
                    clean(row.instruction),
                    clean(row.operands),
                    clean(row.loadSources),
                    clean(row.firstLog)
                ));
                writer.newLine();
            }
        }
    }

    private void printSummary(Path logDir, Path outPath, List<Row> rows, boolean printAll) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Row row : rows) {
            counts.merge(row.status, 1, Integer::sum);
        }

        println("Log dir: " + logDir);
        println("Output: " + outPath);
        println("Unique load sites: " + rows.size());
        for (Map.Entry<String, Integer> entry : counts.entrySet()) {
            println(entry.getKey() + ": " + entry.getValue());
        }

        println("");
        println(printAll ? "Rows:" : "Hardcoded rows:");
        for (Row row : rows) {
            if (!printAll && !Objects.equals(row.status, "HARDCODED_LOAD_SOURCE")) {
                continue;
            }
            println(String.format(
                "%s\t%s\t%s\t%s\tcount=%d\t%s\t%s\tload_sources=%s",
                row.status,
                hex(row.pc),
                row.device,
                hex(row.mmio),
                row.count,
                row.function,
                row.instruction,
                row.loadSources
            ));
        }
    }

    private String clean(String value) {
        return value == null ? "" : value.replace('\t', ' ').replace('\n', ' ');
    }

    private String hex(long value) {
        return String.format("0x%08X", value & U32_MASK);
    }

    private static final class Row {
        final String status;
        final long pc;
        final String device;
        final long mmio;
        final int count;
        final String function;
        final String instruction;
        final String operands;
        final String loadSources;
        final String firstLog;

        private Row(
            String status,
            long pc,
            String device,
            long mmio,
            int count,
            String function,
            String instruction,
            String operands,
            String loadSources,
            String firstLog
        ) {
            this.status = status;
            this.pc = pc;
            this.device = device;
            this.mmio = mmio;
            this.count = count;
            this.function = function;
            this.instruction = instruction;
            this.operands = operands;
            this.loadSources = loadSources;
            this.firstLog = firstLog;
        }

        static Row from(
            Site site,
            String status,
            String function,
            String instruction,
            String operands,
            String loadSources
        ) {
            return new Row(
                status,
                site.key.pc(),
                site.key.device(),
                site.key.mmio(),
                site.count,
                function,
                instruction,
                operands,
                loadSources,
                site.firstFile + ":" + site.firstLine
            );
        }
    }
}

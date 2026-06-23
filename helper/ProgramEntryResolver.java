package helper;

import java.io.File;
import java.util.function.BiConsumer;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public final class ProgramEntryResolver {

    public static final class ResolvedStartAddress {
        private final Address address;
        private final String source;

        private ResolvedStartAddress(Address address, String source) {
            this.address = address;
            this.source = source;
        }

        public Address getAddress() {
            return address;
        }

        public String getSource() {
            return source;
        }
    }

    private ProgramEntryResolver() {
    }

    public static ResolvedStartAddress resolveStartAddress(GhidraScript script) throws Exception {
        return resolveStartAddress(script, (message, detailLevel) -> {});
    }

    public static ResolvedStartAddress resolveStartAddress(
        GhidraScript script,
        BiConsumer<String, Integer> logger
    ) throws Exception {
        Address entryPoint = resolveElfHeaderEntryPoint(script, logger);
        if (entryPoint != null) {
            return new ResolvedStartAddress(entryPoint, "ELF header entry point");
        }

        entryPoint = resolveNamedEntryPoint(script);
        if (entryPoint != null) {
            return new ResolvedStartAddress(entryPoint, "entry symbol");
        }

        entryPoint = resolveFirstFunctionEntryPoint(script);
        if (entryPoint != null) {
            return new ResolvedStartAddress(entryPoint, "first function");
        }

        entryPoint = resolveExternalEntryPoint(script);
        if (entryPoint != null) {
            return new ResolvedStartAddress(entryPoint, "external entry point");
        }

        throw new IllegalStateException(
            "Could not resolve start address from ELF header, symbols, functions, or program entry points."
        );
    }

    private static Address resolveElfHeaderEntryPoint(
        GhidraScript script,
        BiConsumer<String, Integer> logger
    ) throws Exception {
        String executablePath = script.getCurrentProgram().getExecutablePath();
        if (executablePath == null || executablePath.isEmpty()) {
            return null;
        }

        File executable = new File(executablePath);
        if (!executable.isFile()) {
            logger.accept("Executable path is not readable, skipping ELF header entry: " + executablePath, 6);
            return null;
        }

        try (ByteProvider provider = new RandomAccessByteProvider(executable)) {
            ElfHeader elf = new ElfHeader(provider, message -> logger.accept("ELF header warning: " + message, 6));
            long entry = elf.e_entry();
            if (entry == 0) {
                return null;
            }
            return script.toAddr(entry);
        }
    }

    private static Address resolveExternalEntryPoint(GhidraScript script) {
        SymbolTable symbolTable = script.getCurrentProgram().getSymbolTable();
        AddressIterator entries = symbolTable.getExternalEntryPointIterator();
        while (entries.hasNext()) {
            Address address = entries.next();
            if (isExecutableAddress(script, address)) {
                return address;
            }
        }
        return null;
    }

    private static Address resolveNamedEntryPoint(GhidraScript script) {
        SymbolTable symbolTable = script.getCurrentProgram().getSymbolTable();
        String[] names = new String[] {"entry", "_start", "start", "EntryPoint", "_EntryPoint"};
        for (String name : names) {
            SymbolIterator symbols = symbolTable.getSymbols(name);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                Address address = symbol.getAddress();
                if (isExecutableAddress(script, address)) {
                    return address;
                }
            }
        }
        return null;
    }

    private static Address resolveFirstFunctionEntryPoint(GhidraScript script) {
        FunctionManager functionManager = script.getCurrentProgram().getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            Address address = function.getEntryPoint();
            if (isExecutableAddress(script, address)) {
                return address;
            }
        }
        return null;
    }

    private static boolean isExecutableAddress(GhidraScript script, Address address) {
        return address != null && script.getCurrentProgram().getListing().getInstructionAt(address) != null;
    }
}

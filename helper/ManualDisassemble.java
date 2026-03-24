package helper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;

public class ManualDisassemble extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Address start = toAddr(0x401000L);
        // Address end   = toAddr(0x402000L);

        // AddressSet range = new AddressSet(start, end);

        Address addr = toAddr(0x80005b86L);
        println("instr (before): " + getInstructionAt(addr));
        disassemble(addr);
        println("instr (after): " + getInstructionAt(addr));
    }
}
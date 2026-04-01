package helper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;

public class ManualDisassemble extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address addr = toAddr(0x80005b86L);
        println("instr (before): " + getInstructionAt(addr));
        disassemble(addr);
        println("instr (after): " + getInstructionAt(addr));

        Address ptrStart = toAddr(0x8001b90cL);
        Address ptrEnd = toAddr(0x8001b92bL);
        int pointerSize = currentProgram.getDefaultPointerSize();

        println("pointer range clear: " + ptrStart + " - " + ptrEnd);
        clearListing(ptrStart, ptrEnd);

        for (Address cur = ptrStart; cur.compareTo(ptrEnd) < 0; cur = cur.add(pointerSize)) {
            createData(cur, PointerDataType.dataType);
            println("pointer created at: " + cur);
            println("data: " + getDataAt(cur));
        }
    }
}

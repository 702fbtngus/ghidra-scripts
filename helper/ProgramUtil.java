package helper;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;

public final class ProgramUtil {
    private GhidraScript script;
    
    public ProgramUtil(GhidraScript script) {
        this.script = script;
    }

    public Instruction getInstructionAt(Address addr) {
        return script.getInstructionAt(addr);
    }

    public Instruction getInstructionAfter(Address addr) {
        return script.getInstructionAfter(addr);
    }

    public Address toAddr(long offset) {
        return script.toAddr(offset);
    }

    public AddressSpace getAddressSpace(String name) {
        return script.getCurrentProgram().getAddressFactory().getAddressSpace(name);
    }

}

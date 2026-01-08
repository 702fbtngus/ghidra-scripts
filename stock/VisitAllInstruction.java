// Ghidra Java script: print pcode ops starting from program entrypoint
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

// VisitAllInstruction.java
public class VisitAllInstruction extends GhidraScript {

    public void run() throws Exception {
        // TODO Add User Code Here
		InstructionIterator instIter = currentProgram.getListing().getInstructions(true);
		int i = 0;
        Set<Address> visited_1 = new HashSet<>();
		// while (instIter.hasNext() && i < 5) {
		while (instIter.hasNext()) {
			i++;
			Instruction inst = instIter.next();
			// println("Instruction " + inst().());
			visited_1.add(inst.getAddress());
			printf("Instruction (%s): %s\n", inst.getAddress().toString(), inst.toString());
			// printf("PCodes: %s\n", Arrays.stream(inst.getPcode())
            //      .map(a -> a.toString())
            //      .collect(Collectors.joining(", ", "[", "]")));
		}
		println("# of instructions: " + visited_1.size());
    }


}
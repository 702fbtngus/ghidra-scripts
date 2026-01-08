// Ghidra Java script: print pcode ops starting from program entrypoint
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.util.*;
import java.util.function.Consumer;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

// BlockWalker.java
public class BlockWalker extends GhidraScript {

	private void analyzeBlock(CodeBlock block) {
        Listing listing = currentProgram.getListing();
		// iterate instructions inside this block (listing.getInstructions(block, true) works)
		InstructionIterator insIter = listing.getInstructions(block, true);
		while (insIter.hasNext()) {
			Instruction ins = insIter.next();
			println(ins.getAddress() + ":\t" + ins); // prints disasm
			// println(String.format("\t\tPCodes: %s\n", Arrays.stream(ins.getPcode())
			// 	.map(a -> a.toString())
			// 	.collect(Collectors.joining(", \n\t\t\t", "[\n\t\t\t", "\n\t\t]"))));
			println("PCodes: [");
			for (PcodeOp pco: ins.getPcode()) {
				println("\t" + pco.toString());
			};
			println("        ]\n");
		}

        DefUseBuilder.DefUseChain duc = DefUseBuilder.buildDefUseChainForBlock(block, currentProgram);

        // 출력 예시
        println("Defs found: " + duc.defToUses.size());
        for (Map.Entry<PcodeOp, List<DefUseBuilder.UseSite>> e : duc.defToUses.entrySet()) {
            PcodeOp def = e.getKey();
            println("DEF op: " + def + " (mnemonic=" + def.getMnemonic() + ")");
            for (DefUseBuilder.UseSite u : e.getValue()) {
                println("   -> use at instr " + (u.instr!=null?u.instr.getAddress():"?") + " inputIdx=" + u.inputIndex);
            }
        }
    }

    public void run() throws Exception {
        //TODO Add User Code Here
		// InstructionIterator instIter = currentProgram.getListing().getInstructions(true);
		// int i = 0;
        // Set<Address> visited_1 = new HashSet<>();
		// while (instIter.hasNext() && i < 5) {
		// // while (instIter.hasNext()) {
		// 	i++;
		// 	Instruction inst = instIter.next();
		// 	// println("Instruction " + inst().());
		// 	visited_1.add(inst.getAddress());
		// 	printf("Instruction (%s): %s\n", inst.getAddress().toString(), inst.toString());
		// 	printf("PCodes: %s\n", Arrays.stream(inst.getPcode())
        //          .map(a -> a.toString())
        //          .collect(Collectors.joining(", ", "[", "]")));
		// }
		// println("visited_1: " + visited_1.size());

		Address entry = findEntrypoint();
        if (entry == null) {
            println("No entrypoint found. Set currentAddress or ensure program has symbols/functions.");
            return;
        }
        println("Starting CFG traversal from entry: " + entry);

        // 2) build basic-block model and find starting block
        BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
        CodeBlock startBlock = null;
        try {
            startBlock = bbModel.getFirstCodeBlockContaining(entry, monitor);
        } catch (CancelledException e) {
            println("Operation cancelled while locating start block.");
            return;
        }
        if (startBlock == null) {
            println("No code block contains entry address: " + entry);
            return;
        }

        // 3) BFS across blocks, iterating instructions inside each block
		walkBlocks(bbModel, startBlock, this::analyzeBlock);
        
    }

	private void walkBlocks(BasicBlockModel bbModel, CodeBlock startBlock, Consumer<CodeBlock> func) {
		Queue<CodeBlock> q = new LinkedList<>();
        Set<Address> visited = new HashSet<>();
        q.add(startBlock);
        visited.add(startBlock.getFirstStartAddress());

        int blockCount = 0;
        while (!q.isEmpty() && blockCount < 2) {
        // while (!q.isEmpty()) {
            if (monitor.isCancelled()) {
                println("Cancelled by user.");
                return;
            }
            CodeBlock block = q.poll();
            blockCount++;
			println(String.format("=== Block %d: start=%s (modelName=%s) ===",
				blockCount, block.getFirstStartAddress(), bbModel.getName(block)));
			func.accept(block);

			// get destinations (outgoing edges) and enqueue unseen blocks
			try {
				CodeBlockReferenceIterator dests = bbModel.getDestinations(block, monitor);
				while (dests.hasNext()) {
					CodeBlockReference cref = dests.next();
					CodeBlock dest = cref.getDestinationBlock();
					Address destAddr = dest.getFirstStartAddress();
					if (!visited.contains(destAddr)) {
						visited.add(destAddr);
						q.add(dest);
						println("\t-> enqueue dest block at " + destAddr);
					} else {
						println("\t-> already visited dest " + destAddr);
					}
				}
			} catch (CancelledException e) {
				println("Cancelled while iterating destinations.");
				return;
			}
        }
        println("Traversal finished. Visited " + blockCount + " blocks.");
	}

	// simple entrypoint finder: try symbol names then first function
    private Address findEntrypoint() {
        SymbolTable symTab = currentProgram.getSymbolTable();
        String[] names = new String[] {"_start", "entry", "EntryPoint", "_EntryPoint", "start"};
        for (String n : names) {
            try {
                SymbolIterator s = symTab.getSymbols(n);
                if (s != null && s.hasNext()) {
                    return s.next().getAddress();
                }
            } catch (Exception e) {
                // ignore
            }
        }
        // fallback: first function
        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            FunctionIterator fit = fm.getFunctions(true);
            if (fit.hasNext()) {
                Function f = fit.next();
                return f.getEntryPoint();
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

}
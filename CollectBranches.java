// Ghidra Java script: print pcode ops starting from program entrypoint
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;

// CollectBranches.java

public class CollectBranches extends GhidraScript {
    @Override
    public void run() throws Exception {
        File outFile = new File("/Users/suhyeonryu/CubeSatPcode/ghidra_scripts/branches.txt");
        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            // BasicBlockModel bbm = new BasicBlockModel(currentProgram);
            SimpleBlockModel bbm = new SimpleBlockModel(currentProgram);
            Listing listing = currentProgram.getListing();
            InstructionIterator instructions = listing.getInstructions(true); // 전체 프로그램 순회
            
            while (instructions.hasNext() && !monitor.isCancelled()) {
                Instruction instr = instructions.next();
                FlowType ft = instr.getFlowType();
                CodeBlock[] cbs = bbm.getCodeBlocksContaining(instr.getAddress(), monitor);
                CodeBlock cb = null;
                if (cbs.length > 1) {
                    println("The instruction " + instr.getAddress() + " is contained in multiple blocks");
                } else if (cbs.length == 0) {
                    println("The instruction " + instr.getAddress() + " is contained in no blocks");
                } else {
                    cb = cbs[0];
                }
                
                // branch 계열 판별
                if (ft.isJump() || ft.isConditional() || ft.isTerminal() || ft.isCall()) {
                // if (ft.isConditional()) {
                    Address[] flows = instr.getFlows();
                    Address fallthrough = instr.getFallThrough();

                    // flows + fallthrough 합치기
                    int extra = (fallthrough != null) ? 1 : 0;
                    Address[] dests = new Address[flows.length + extra];
                    System.arraycopy(flows, 0, dests, 0, flows.length);
                    if (fallthrough != null) {
                        dests[flows.length] = fallthrough;
                    }
                    // if (dests.length >= 2 || (ft.isTerminal() && dests.length == 1)) {
                    if (true) {
                        StringBuilder sb = new StringBuilder();
                        sb.append(instr.getAddress()).append(" (");
                        if (cb != null) {
                            sb.append(cb.getMinAddress());
                        } else {
                            sb.append("null");
                        }
                        sb.append("): ").append(instr);
                        sb.append(" -> [");
                        for (int i = 0; i < dests.length; i++) {
                            sb.append(dests[i]);
                            if (i < dests.length - 1) sb.append(", ");
                        }
                        sb.append("]");
                            
                        // println(sb.toString());
                        pw.println(sb.toString());
                    }
                }
            }
        }
        println("분기 정보가 파일에 저장되었습니다: " + outFile.getAbsolutePath());
    }
}

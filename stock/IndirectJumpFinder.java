// Ghidra Java script: print pcode ops starting from program entrypoint
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.FlowType;

// IndirectJumpFinder.java
// Ghidra script to find all indirect jumps in the current program

public class IndirectJumpFinder extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(true);

        println("=== Indirect Jump Finder (AVR32) ===");
        int totalCount = 0;

        // Mnemonic별 통계 테이블
        Map<String, int[]> stats = new LinkedHashMap<>();
        // [0] = resolved count, [1] = unresolved count

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction inst = instructions.next();
            FlowType flow = inst.getFlowType();

            // Step 1. 점프나 호출 계열인지 판별
            if (flow.isJump() || flow.isCall()) {
                boolean hasRegisterOperand = false;
                boolean hasScalarOperand = false;

                // Step 2. 오퍼랜드를 검사
                int numOps = inst.getNumOperands();
                for (int i = 0; i < numOps; i++) {
                    Object[] objs = inst.getOpObjects(i);
                    for (Object o : objs) {
                        String cls = o.getClass().getSimpleName();
                        if (cls.contains("Register")) {
                            hasRegisterOperand = true;
                        } else if (cls.contains("Scalar")) {
                            hasScalarOperand = true;
                        }
                    }
                }

                // Step 3. 레지스터 기반 간접 점프만 선택
                // if (hasRegisterOperand && !hasScalarOperand) {
                if (hasRegisterOperand) {
                    totalCount++;
                    String mnemonic = inst.getMnemonicString().toUpperCase();

                    // Step 4. resolve 여부 판단
                    Address[] flows = inst.getFlows();
                    boolean resolved = (flows != null && flows.length > 0);

                    // Step 5. 출력
                    String status;
                    if (resolved) {
                        StringBuilder sb = new StringBuilder();
                        for (Address addr : flows) {
                            sb.append(String.format("0x%s ", addr.toString()));
                        }
                        status = "[resolved → " + sb.toString().trim() + "]";
                    } else {
                        status = "[unresolved]";
                    // }

                    println(String.format(
                        "[%04d] 0x%s : %-8s %s %s",
                        totalCount,
                        inst.getMinAddress().toString(),
                        mnemonic,
                        inst.getDefaultOperandRepresentation(0),
                        status
                    ));

                    println("PCodes: [");
                        for (PcodeOp pco: inst.getPcode()) {
                            println("\t" + pco.toString());
                        };
                        println("        ]\n");
                    }

                    // Step 6. 통계 누적
                    int[] arr = stats.computeIfAbsent(mnemonic, k -> new int[2]);
                    if (resolved) arr[0]++; else arr[1]++;
                }
            }
        }

        // 요약 출력
        int resolved_sum = 0;
        int unresolved_sum = 0;
        int total_sum = 0;

        println("\n=== Summary by Mnemonic ===");
        println(String.format("%-10s  %8s  %10s  %8s", "Mnemonic", "Resolved", "Unresolved", "Total"));
        for (Map.Entry<String, int[]> e : stats.entrySet()) {
            String mnem = e.getKey();
            int resolved = e.getValue()[0];
            int unresolved = e.getValue()[1];
            int total = resolved + unresolved;
            resolved_sum += resolved;
            unresolved_sum += unresolved;
            total_sum += total;
            println(String.format("%-10s  %8d  %10d  %8d", mnem, resolved, unresolved, total));
        }
        println("----------  --------  ----------  --------");
        println(String.format("%-10s  %8d  %10d  %8d", "Total", resolved_sum, unresolved_sum, total_sum));

        println(String.format("\nTotal indirect jumps/calls found: %d", totalCount));

    }
}
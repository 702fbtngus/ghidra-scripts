// 필요한 import들

import ghidra.app.script.GhidraScript;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.program.model.address.AddressIterator;

import java.util.*;

/**
 * DefUseBuilder: 코드블록(하나)을 입력받아 블록 내에서의 def->uses 맵을 생성
 *
 * 반환 타입은 DefUseChain 이며, def(PcodeOp) -> List<UseSite> 형태로 제공된다.
 *
 * (이 스크립트는 GhidraScript 환경 내에서 helper로 사용하도록 작성됨)
 */
public class DefUseBuilder {

    // 외부에서 접근 가능한 결과 컨테이너
    public static class UseSite {
        public final PcodeOp userOp;   // 사용을 가진 PcodeOp
        public final int inputIndex;   // userOp의 몇번째 input인지 (0..n-1)
        public final Instruction instr; // 해당 PcodeOp가 속한 Instruction (nullable)
        public UseSite(PcodeOp userOp, int inputIndex, Instruction instr) {
            this.userOp = userOp;
            this.inputIndex = inputIndex;
            this.instr = instr;
        }
        @Override
        public String toString() {
            String addr = (instr!=null && instr.getAddress()!=null) ? instr.getAddress().toString() : "unknown";
            return String.format("Use(op=%s@%s, idx=%d)", userOp.getMnemonic(), addr, inputIndex);
        }
    }

    // 결과 컨테이너
    public static class DefUseChain {
        // 정의 PcodeOp -> 리스트의 UseSite
        public final Map<PcodeOp, List<UseSite>> defToUses = new LinkedHashMap<>();

        // (선택) useSite -> reaching def(s) (여기선 단일 최근 def 혹은 EXTERNAL_DEF)
        public final Map<UseSite, List<PcodeOp>> useToDefs = new LinkedHashMap<>();

        // debugging pretty print
        public String toString() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<PcodeOp, List<UseSite>> e : defToUses.entrySet()) {
                PcodeOp def = e.getKey();
                sb.append(String.format("DEF: %s (op:%s) -> uses:\n", def.getMnemonic(), def));
                for (UseSite u : e.getValue()) {
                    sb.append("   - ").append(u.toString()).append("\n");
                }
            }
            return sb.toString();
        }
    }

    // 안정적 키: varnode의 공간/오프셋/사이즈/상수/unique 여부로 식별
    public static class VarnodeKey {
        public final String spaceName;
        public final long offset;
        public final int size;
        public final boolean isConstant;
        public final boolean isUnique;

        public VarnodeKey(Varnode vn) {
            Address a = vn.getAddress();
            AddressSpace s = a.getAddressSpace();
            this.spaceName = s.getName();
            this.offset = a.getOffset();
            this.size = vn.getSize();
            this.isConstant = vn.isConstant();
            this.isUnique = s.getName().equalsIgnoreCase("unique");
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof VarnodeKey)) return false;
            VarnodeKey k = (VarnodeKey) o;
            return offset == k.offset && size == k.size &&
                    isConstant == k.isConstant && isUnique == k.isUnique &&
                    Objects.equals(spaceName, k.spaceName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(spaceName, offset, size, isConstant, isUnique);
        }

        @Override
        public String toString() {
            return String.format("%s:0x%X(sz=%d,const=%b,uniq=%b)", spaceName, offset, size, isConstant, isUnique);
        }
    }

    // 특별 마커: 외부에서 온 정의 (블록 입구)
    private static final PcodeOp EXTERNAL_DEF = null;

    /**
     * 블록 내 PcodeOps를 순회하여 intra-block def-use chain을 만든다.
     *
     * @param block  분석할 CodeBlock (단일 블록)
     * @param program 현재 Program (Listing, 주소/space 조회용)
     * @return DefUseChain (def -> list of uses), use->defs 매핑 포함
     */
    public static DefUseChain buildDefUseChainForBlock(CodeBlock block, Program program) {
        Objects.requireNonNull(block, "block");
        Objects.requireNonNull(program, "program");

        Listing listing = program.getListing();
        DefUseChain result = new DefUseChain();

        // 현재 블록에서 "가장 최근의 정의"를 추적하는 맵
        // VarnodeKey -> PcodeOp (the latest definition inside block)
        Map<VarnodeKey, PcodeOp> curDefs = new HashMap<>();

        // 주소 반복자: 블록 내부의 주소들을 순회 (forward order)
        AddressIterator addrIter = block.getAddresses(true);

        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            Instruction instr = listing.getInstructionAt(addr);
            if (instr == null) {
                continue;
            }

            // getPcode()는 일부 Ghidra 버전에서 PcodeOp[] 반환
            PcodeOp[] pcodeOps;
            try {
                pcodeOps = instr.getPcode(); // may return null or empty
            } catch (Exception e) {
                // 안전하게 건너뛰기: 어떤 환경에서는 예외가 날 수 있음
                Msg.warn(null, "Failed to get Pcode for instruction at " + addr + ": " + e.getMessage());
                continue;
            }
            if (pcodeOps == null) continue;

            // 각 PcodeOp를 블록 내 순서대로 처리
            for (PcodeOp op : pcodeOps) {
                if (op == null) continue;

                // -- inputs: 모든 input varnode에 대해 가장 최신 정의를 찾아 연결
                int numInputs = op.getNumInputs();
                for (int i = 0; i < numInputs; i++) {
                    Varnode inVn = op.getInput(i);
                    if (inVn == null) continue;
                    VarnodeKey key = new VarnodeKey(inVn);

                    UseSite useSite = new UseSite(op, i, instr);

                    PcodeOp reachingDef = curDefs.get(key); // 최근 블록 내부 정의
                    if (reachingDef != null) {
                        // def -> use 연결
                        result.defToUses.computeIfAbsent(reachingDef, k -> new ArrayList<>()).add(useSite);
                        result.useToDefs.computeIfAbsent(useSite, k -> new ArrayList<>()).add(reachingDef);
                    } else {
                        // 블록 내부에 정의가 없음: 외부에서 온 정의(입구)로 표시
                        result.useToDefs.computeIfAbsent(useSite, k -> new ArrayList<>()).add(EXTERNAL_DEF);
                    }
                }

                // -- output: 이 op가 varnode를 정의하면 curDefs 갱신
                Varnode outVn = op.getOutput();
                if (outVn != null) {
                    VarnodeKey outKey = new VarnodeKey(outVn);
                    // 이 op를 이 varnode의 최신 정의로 기록
                    curDefs.put(outKey, op);
                    // ensure defToUses has an entry (even if no uses yet)
                    result.defToUses.computeIfAbsent(op, k -> new ArrayList<>());
                }
            } // end pcodeOps loop
        } // end addresses loop

        return result;
    }

} // end class

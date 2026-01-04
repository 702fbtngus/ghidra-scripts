
import java.util.HashMap;
import java.util.Map;

public class SystemRegister {

    // Internal storage for registers
    private Map<Integer, Integer> regs = new HashMap<>();

    // Special behavior registers
    private int COUNT = 0;

    public SystemRegister() {
        // Initialize all system registers with placeholder values
        initPlaceholders();
    }

    private void initPlaceholders() {

        // Table 2-7 registers (0 ~ about 444)
        int[] addresses = new int[]{
                0,4,8,12,16,20,24,28,32,36,40,44,48,52,56,60,64,68,72,76,80,84,88,92,
                96,100,104,108,112,116,120,124,128,
                // 132~252 reserved → skip
                256,260,264,268,272,276,280,284,288,292,296,300,304,308,312,316,
                320,324,328,332,336,340,344,348,352,356,360,364,368,372,376,380,384,
                388,392,396,400,404,408,412,416,420,424,428,432,436,440,444
                // 448~764 reserved
                // 768~1020 implementation-defined
        };

        for (int a : addresses) {
            regs.put(a, 0);  // default placeholder 0
        }
    }

    /** Handle mtsr (write) */
    public boolean onWrite(int ofs, int val) {
        // Special case COUNT register
        if (ofs == 264) {
            COUNT = val;
            regs.put(ofs, val);
            return true;
        }

        // For now, we accept writes to all known registers
        if (regs.containsKey(ofs)) {
            regs.put(ofs, val);
            return true;
        }

        // unknown CSR address
        return false;
    }

    /** Handle mfsr (read) */
    public Integer onRead(int ofs) {

        // Special behavior: COUNT increments every read (placeholder model)
        if (ofs == 264) {
            COUNT += 0x100;           // emulate ticking
            regs.put(ofs, COUNT);
            return COUNT;
        }

        // if (ofs == 20) {
        //     regs.put(ofs, 0x80025094);
        //     return 0x80025094;
        // }

        // Known (placeholder) registers
        if (regs.containsKey(ofs)) {
            return regs.get(ofs);
        }

        // Unknown → GHIDRA should treat as CPU exception or undefined
        return null;
    }
}

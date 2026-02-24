package hw;

import etc.Util;

public class INTC extends MmioDevice {

    // 64 Interrupt Priority Registers (RW)
    private final int[] IPR = new int[64];

    // 64 Interrupt Request Registers (RO)
    private final int[] IRR = new int[64];

    // 4 Interrupt Cause Registers (RO)
    private final int[] ICR = new int[4];

    public int highestPrio = -1;


    public INTC(long baseAddr, String name, int group) {

        super(baseAddr, name, group);   // INTC base & size (0x000~0x20C)

        resetRegisters();
    }
    
    @Override
    protected void link() {}


    private void resetRegisters() {
        // IPR reset = 0
        for (int i = 0; i < 64; i++)
            IPR[i] = 0;

        // IRR, ICR undefined at reset → leave as 0
    }


    @Override
    protected boolean onWrite(int ofs, int value) {

        // --------------------
        // IPR 0x000 ~ 0x0FC
        // --------------------
        if (ofs < 0x100) {
            int index = ofs >>> 2;   // /4
            if (index < 64) {
                IPR[index] = value;
                updateHighestPriority();
                return true;
            }
            return false;
        }

        // --------------------
        // IRR 0x100 ~ 0x1FC (RO)
        // --------------------
        if (ofs >= 0x100 && ofs < 0x200)
            return false;  // read-only

        // --------------------
        // ICR 0x200 ~ 0x20C (RO)
        // --------------------
        if (ofs >= 0x200 && ofs < 0x210)
            return false;  // read-only

        return false;
    }


    @Override
    protected Integer onRead(int ofs) {

        // if (ofs == 0x20c)
        //     return 0x21;

        if (ofs == 0x184)
            return 0x4;

        // --------------------
        // IPR 0x000 ~ 0x0FC
        // --------------------
        if (ofs < 0x100) {
            int index = ofs >>> 2;
            Util.println("INTC IPR index = " + index);
            if (index < 64)
                return IPR[index];
            return null;
        }

        // --------------------
        // IRR 0x100 ~ 0x1FC
        // --------------------
        if (ofs >= 0x100 && ofs < 0x200) {
            int index = (ofs - 0x100) >>> 2;
            Util.println("INTC IRR index = " + index);
            if (index < 64)
                return IRR[index];
            return null;
        }

        // --------------------
        // ICR 0x200 ~ 0x20C
        // --------------------
        if (ofs >= 0x200 && ofs < 0x210) {
            int index = (0x20c - ofs) >>> 2;
            Util.println("INTC ICR index = " + index);
            if (index < 4)
                return ICR[index];
            return null;
        }

        return null;
    }


    // ------------------------------------------
    // ⚡ External helper to trigger an interrupt
    // ------------------------------------------
    public void raiseInterrupt(int group, int line) {
        if (group < 0 || group >= 64) return;

        IRR[group] |= 1 << line;
        updateHighestPriority();
    }

    public void clearInterrupt(int group, int line) {
        if (group < 0 || group >= 64) return;

        IRR[group] &= ~(1 << line);
        updateHighestPriority();
    }

    public void setInterruptCause(int cpu, int cause) {
        if (cpu >= 0 && cpu < 4)
            ICR[cpu] = cause;
    }
    
    // ------------------------------------------
    // ⚡ External helper to trigger an interrupt
    // ------------------------------------------

    private void updateHighestPriority() {
        int bestPrio = -1;
    
        for (int irq = 0; irq < 64; irq++) {
            if (IRR[irq] == 0)
                continue;
    
            int prio = IPR[irq] >>> 0x36;
    
            if (prio > bestPrio ||
               (prio == bestPrio)) {
                bestPrio = prio;
            }
            
            ICR[prio] = irq;
        }
    
        highestPrio = bestPrio;
    }
    
}

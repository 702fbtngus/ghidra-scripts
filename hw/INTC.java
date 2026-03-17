package hw;

import helper.DeviceManager;
import helper.Logger;
import hw.MmioDevice.Register.AccessType;

public class INTC extends MmioDevice {

    // 64 Interrupt Priority Registers (RW)
    private final Register[] IPR = new Register[64];

    // 64 Interrupt Request Registers (RO)
    private final Register[] IRR = new Register[64];

    // 4 Interrupt Cause Registers (RO)
    private final Register[] ICR = new Register[4];

    public int highestPrio = -1;


    public INTC(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);   // INTC base & size (0x000~0x20C)

        resetRegisters();
    }
    
    @Override
    public void link() {}


    private void resetRegisters() {
        // IPR reset = 0
        for (int i = 0; i < 64; i++)
            IPR[i] = newRegister(i * 4, 0, AccessType.READ_WRITE);

        for (int i = 0; i < 64; i++)
            IRR[i] = newRegister(0x100 + i * 4, 0, AccessType.READ_ONLY);

        for (int i = 0; i < 4; i++)
            ICR[i] = newRegister(0x20C - i * 4, 0, AccessType.READ_ONLY);
    }


    @Override
    protected boolean onWrite(int ofs, int value) {

        // --------------------
        // IPR 0x000 ~ 0x0FC
        // --------------------
        if (ofs < 0x100) {
            int index = ofs >>> 2;   // /4
            if (index < 64) {
                IPR[index].value = value;
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
            Logger.printlnGlobal("INTC IPR index = " + index);
            if (index < 64)
                return IPR[index].value;
            return null;
        }

        // --------------------
        // IRR 0x100 ~ 0x1FC
        // --------------------
        if (ofs >= 0x100 && ofs < 0x200) {
            int index = (ofs - 0x100) >>> 2;
            Logger.printlnGlobal("INTC IRR index = " + index);
            if (index < 64)
                return IRR[index].value;
            return null;
        }

        // --------------------
        // ICR 0x200 ~ 0x20C
        // --------------------
        if (ofs >= 0x200 && ofs < 0x210) {
            int index = (0x20c - ofs) >>> 2;
            Logger.printlnGlobal("INTC ICR index = " + index);
            if (index < 4)
                return ICR[index].value;
            return null;
        }

        return null;
    }


    // ------------------------------------------
    // ⚡ External helper to trigger an interrupt
    // ------------------------------------------
    public void raiseInterrupt(int group, int line) {
        if (group < 0 || group >= 64) return;

        IRR[group].value |= 1 << line;
        updateHighestPriority();
    }

    public void clearInterrupt(int group, int line) {
        if (group < 0 || group >= 64) return;

        IRR[group].value &= ~(1 << line);
        updateHighestPriority();
    }

    public void setInterruptCause(int cpu, int cause) {
        if (cpu >= 0 && cpu < 4)
            ICR[cpu].value = cause;
    }
    
    // ------------------------------------------
    // ⚡ External helper to trigger an interrupt
    // ------------------------------------------

    private void updateHighestPriority() {
        int bestPrio = -1;
    
        for (int irq = 0; irq < 64; irq++) {
            if (IRR[irq].value == 0)
                continue;
    
            int prio = IPR[irq].value >>> 0x36;
    
            if (prio > bestPrio ||
               (prio == bestPrio)) {
                bestPrio = prio;
            }
            
            ICR[prio].value = irq;
        }
    
        highestPrio = bestPrio;
    }
    
}

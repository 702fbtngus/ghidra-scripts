package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class SCIF extends MmioDevice {

    // Interrupt registers
    Register IER;       // 0x0000 WO
    Register IDR;       // 0x0004 WO
    Register IMR;       // 0x0008 RO
    Register ISR;       // 0x000C RO
    Register ICR;       // 0x0010 WO
    Register PCLKSR;    // 0x0014 RO
    Register UNLOCK;    // 0x0018 WO

    // PLL / OSC / BOD / VREG / RC
    Register PLL0;      // 0x001C
    Register PLL1;      // 0x0020
    Register OSCCTRL0;  // 0x0024
    Register OSCCTRL1;  // 0x0028
    Register BOD;       // 0x002C
    Register BGCR;      // 0x0030
    Register BOD33;     // 0x0034
    Register BOD50;     // 0x0038
    Register VREGCR;    // 0x003C
    Register VREGCTRL;  // 0x0040
    Register RCCR;      // 0x0044
    Register RCCR8;     // 0x0048
    Register OSCCTRL32; // 0x004C
    Register RC120MCR;  // 0x0050

    // GPLP registers
    Register GPLP0;     // 0x005C
    Register GPLP1;     // 0x0060

    // Generic clock control (0x0064~0x008C)
    Register[] GCCTRL = new Register[11];

    // Version registers (RO)
    Register PLLVERSION, OSCVERSION, BODVERSION, VREGVERSION;
    Register RCCVERSION, RCCR8VERSION, OSC32VERSION, RC120VERSION;
    Register GPLPVERSION, GCLKVERSION, VERSION;

    public SCIF(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);
        resetRegisters();
    }
    
    @Override
    public void link() {}

    private void resetRegisters() {

        IER = newRegister(0x0000, 0, AccessType.WRITE_ONLY);
        IDR = newRegister(0x0004, 0, AccessType.WRITE_ONLY);
        IMR = newRegister(0x0008, 0, AccessType.READ_ONLY);
        ISR = newRegister(0x000C, 0, AccessType.READ_ONLY);
        ICR = newRegister(0x0010, 0, AccessType.WRITE_ONLY);
        PCLKSR = newRegister(0x0014, 0, AccessType.READ_ONLY);
        UNLOCK = newRegister(0x0018, 0, AccessType.WRITE_ONLY);
        PLL0 = newRegister(0x001C, 0, AccessType.READ_WRITE);
        PLL1 = newRegister(0x0020, 0, AccessType.READ_WRITE);
        OSCCTRL0 = newRegister(0x0024, 0, AccessType.READ_WRITE);
        OSCCTRL1 = newRegister(0x0028, 0, AccessType.READ_WRITE);
        BOD = newRegister(0x002C, 0, AccessType.READ_WRITE);
        BGCR = newRegister(0x0030, 0, AccessType.READ_WRITE);
        BOD33 = newRegister(0x0034, 0, AccessType.READ_WRITE);
        BOD50 = newRegister(0x0038, 0, AccessType.READ_WRITE);
        VREGCR = newRegister(0x003C, 0, AccessType.READ_WRITE);
        VREGCTRL = newRegister(0x0040, 0, AccessType.READ_WRITE);
        RCCR = newRegister(0x0044, 0, AccessType.READ_WRITE);
        RCCR8 = newRegister(0x0048, 0, AccessType.READ_WRITE);
        OSCCTRL32 = newRegister(0x004C, 0, AccessType.READ_WRITE);
        RC120MCR = newRegister(0x0050, 0, AccessType.READ_WRITE);
        GPLP0 = newRegister(0x005C, 0, AccessType.READ_WRITE);
        GPLP1 = newRegister(0x0060, 0, AccessType.READ_WRITE);

        for (int i = 0; i < GCCTRL.length; i++)
            GCCTRL[i] = newRegister(0x0064 + i * 4, 0, AccessType.READ_WRITE);

        PLLVERSION = newRegister(0x03C8, 0, AccessType.READ_ONLY);
        OSCVERSION = newRegister(0x03CC, 0, AccessType.READ_ONLY);
        BODVERSION = newRegister(0x03D0, 0, AccessType.READ_ONLY);
        VREGVERSION = newRegister(0x03D4, 0, AccessType.READ_ONLY);
        RCCVERSION = newRegister(0x03DC, 0, AccessType.READ_ONLY);
        RCCR8VERSION = newRegister(0x03E0, 0, AccessType.READ_ONLY);
        OSC32VERSION = newRegister(0x03E4, 0, AccessType.READ_ONLY);
        RC120VERSION = newRegister(0x03F0, 0, AccessType.READ_ONLY);
        GPLPVERSION = newRegister(0x03F4, 0, AccessType.READ_ONLY);
        GCLKVERSION = newRegister(0x03F8, 0, AccessType.READ_ONLY);
        VERSION = newRegister(0x03FC, 0, AccessType.READ_ONLY);
    }

    @Override
    protected boolean onWrite(int ofs, int v) {
        if (!super.onWrite(ofs, v)) {
            return false;
        }

        switch (ofs) {
            case 0x001C:
                PCLKSR.value |= (v & 0x00000001) << 4;
                break;
            case 0x0020:
                PCLKSR.value |= (v & 0x00000001) << 5;
                break;
            case 0x0024:
                PCLKSR.value |= v >> 16 & 0x00000001;
                break;
            case 0x0028:
                PCLKSR.value |= v >> 16 & 0x00000002;
                break;
        }

        return true;
    }

    @Override
    protected Integer onRead(int ofs) {
        return super.onRead(ofs);
    }
}

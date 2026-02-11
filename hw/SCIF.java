package hw;

public class SCIF extends MmioDevice {

    // Interrupt registers
    int IER;       // 0x0000 WO
    int IDR;       // 0x0004 WO
    int IMR;       // 0x0008 RO
    int ISR;       // 0x000C RO
    int ICR;       // 0x0010 WO

    int PCLKSR;    // 0x0014 RO
    int UNLOCK;    // 0x0018 WO

    // PLL / OSC / BOD / VREG / RC
    int PLL0;      // 0x001C
    int PLL1;      // 0x0020
    int OSCCTRL0;  // 0x0024
    int OSCCTRL1;  // 0x0028
    int BOD;       // 0x002C
    int BGCR;      // 0x0030
    int BOD33;     // 0x0034
    int BOD50;     // 0x0038
    int VREGCR;    // 0x003C
    int VREGCTRL;  // 0x0040
    int RCCR;      // 0x0044
    int RCCR8;     // 0x0048
    int OSCCTRL32; // 0x004C
    int RC120MCR;  // 0x0050

    // GPLP registers
    int GPLP0;     // 0x005C
    int GPLP1;     // 0x0060

    // Generic clock control (0x0064~0x008C)
    int[] GCCTRL = new int[11];

    // Version registers (RO)
    int PLLVERSION, OSCVERSION, BODVERSION, VREGVERSION;
    int RCCVERSION, RCCR8VERSION, OSC32VERSION, RC120VERSION;
    int GPLPVERSION, GCLKVERSION, VERSION;

    public SCIF(long baseAddr, String name, int group) {

        super(baseAddr, name, group);
        resetRegisters();
    }
    
    @Override
    protected void link() {}

    private void resetRegisters() {

        IER = IDR = ICR = 0;
        IMR = ISR = 0;
        PCLKSR = 0;
        UNLOCK = 0;

        PLL0 = PLL1 = OSCCTRL0 = OSCCTRL1 = BOD = BGCR = 0;
        BOD33 = BOD50 = VREGCR = VREGCTRL = 0;
        RCCR = RCCR8 = OSCCTRL32 = RC120MCR = 0;

        GPLP0 = GPLP1 = 0;

        for (int i = 0; i < GCCTRL.length; i++)
            GCCTRL[i] = 0;

        PLLVERSION = OSCVERSION = BODVERSION = VREGVERSION = 0;
        RCCVERSION = RCCR8VERSION = OSC32VERSION = RC120VERSION = 0;
        GPLPVERSION = GCLKVERSION = VERSION = 0;
    }

    @Override
    protected boolean onWrite(int ofs, int v) {

        switch (ofs) {
            case 0x0000: IER = v; return true;
            case 0x0004: IDR = v; return true;
            case 0x0010: ICR = v; return true;
            case 0x0018: UNLOCK = v; return true;

            case 0x001C:
                PLL0 = v;
                PCLKSR |= (v & 0x00000001) << 4;
                return true;
            case 0x0020:
                PLL1 = v;
                PCLKSR |= (v & 0x00000001) << 5;
                return true;
            case 0x0024:
                OSCCTRL0 = v;
                PCLKSR |= v >> 16 & 0x00000001;
                return true;
            case 0x0028:
                OSCCTRL1 = v;
                PCLKSR |= v >> 16 & 0x00000002;
                return true;
            case 0x002C: BOD = v; return true;
            case 0x0030: BGCR = v; return true;
            case 0x0034: BOD33 = v; return true;
            case 0x0038: BOD50 = v; return true;
            case 0x003C: VREGCR = v; return true;
            case 0x0040: VREGCTRL = v; return true;
            case 0x0044: RCCR = v; return true;
            case 0x0048: RCCR8 = v; return true;
            case 0x004C: OSCCTRL32 = v; return true;
            case 0x0050: RC120MCR = v; return true;

            case 0x005C: GPLP0 = v; return true;
            case 0x0060: GPLP1 = v; return true;
        }

        // Generic Clock Control
        if (ofs >= 0x0064 && ofs <= 0x008C) {
            int idx = (ofs - 0x0064) >> 2;
            if (idx < GCCTRL.length) {
                GCCTRL[idx] = v;
                return true;
            }
        }

        // Read-only registers
        switch (ofs) {
            case 0x0008: case 0x000C: case 0x0014:
            case 0x03C8: case 0x03CC: case 0x03D0:
            case 0x03D4: case 0x03DC: case 0x03E0:
            case 0x03E4: case 0x03F0: case 0x03F4:
            case 0x03F8: case 0x03FC:
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {
            case 0x0008: return IMR;
            case 0x000C: return ISR;
            case 0x0014: return PCLKSR;

            case 0x001C: return PLL0;
            case 0x0020: return PLL1;
            case 0x0024: return OSCCTRL0;
            case 0x0028: return OSCCTRL1;
            case 0x002C: return BOD;
            case 0x0030: return BGCR;
            case 0x0034: return BOD33;
            case 0x0038: return BOD50;
            case 0x003C: return VREGCR;
            case 0x0040: return VREGCTRL;
            case 0x0044: return RCCR;
            case 0x0048: return RCCR8;
            case 0x004C: return OSCCTRL32;
            case 0x0050: return RC120MCR;

            case 0x005C: return GPLP0;
            case 0x0060: return GPLP1;
        }

        if (ofs >= 0x0064 && ofs <= 0x008C) {
            int idx = (ofs - 0x0064) >> 2;
            if (idx < GCCTRL.length)
                return GCCTRL[idx];
        }

        switch (ofs) {
            case 0x03C8: return PLLVERSION;
            case 0x03CC: return OSCVERSION;
            case 0x03D0: return BODVERSION;
            case 0x03D4: return VREGVERSION;
            case 0x03DC: return RCCVERSION;
            case 0x03E0: return RCCR8VERSION;
            case 0x03E4: return OSC32VERSION;
            case 0x03F0: return RC120VERSION;
            case 0x03F4: return GPLPVERSION;
            case 0x03F8: return GCLKVERSION;
            case 0x03FC: return VERSION;
        }

        // Write-only registers return null
        switch (ofs) {
            case 0x0000: case 0x0004:
            case 0x0010: case 0x0018:
                return null;
        }

        return null;
    }
}

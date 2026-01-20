package peripheral;

public class ADCIFA extends Peripheral {

    // ---- Registers ----
    int CR, CFG, SR, SCR, SSR;
    int SEQCFG0, SEQCFG1;
    int SHG0, SHG1;
    int INPSEL00, INPSEL01, INPSEL10, INPSEL11;
    int INNSEL00, INNSEL01, INNSEL10, INNSEL11;
    int CKDIV, ITIMER;
    int WCFG0, WCFG1;
    int LCV0, LCV1;
    int ADCCAL, SHCAL;
    int IER, IDR, IMR;
    int VERSION, PARAMETER, RES;

    public ADCIFA(long baseAddr, String name) {
        super(baseAddr, name, 0x400);

        // Reset values are device-specific but shown as 0 in datasheet
        CR = CFG = SR = SCR = SSR = 0;
        SR = 1 << 0xe | 1;
        SEQCFG0 = SEQCFG1 = 0;
        SHG0 = SHG1 = 0;
        INPSEL00 = INPSEL01 = INPSEL10 = INPSEL11 = 0;
        INNSEL00 = INNSEL01 = INNSEL10 = INNSEL11 = 0;
        CKDIV = ITIMER = 0;
        WCFG0 = WCFG1 = 0;
        LCV0 = LCV1 = 0;
        ADCCAL = SHCAL = 0;
        IER = IDR = IMR = 0;

        VERSION = 0;     // device-specific placeholder
        PARAMETER = 0;   // device-specific placeholder
        RES = 0;         // documentation shows reset undefined
    }

    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {

        switch (ofs) {

            // ---- Write-only registers ----
            case 0x0000: CR = val; return true;
            case 0x000C: SCR = val; return true;
            case 0x0010: SSR = val; return true;
            case 0x0070: IER = val; return true;
            case 0x0074: IDR = val; return true;

            // ---- Read/Write registers ----
            case 0x0004: CFG = val; return true;

            case 0x0014: SEQCFG0 = val; return true;
            case 0x0018: SEQCFG1 = val; return true;

            case 0x001C: SHG0 = val; return true;
            case 0x0020: SHG1 = val; return true;

            case 0x0024: INPSEL00 = val; return true;
            case 0x0028: INPSEL01 = val; return true;
            case 0x002C: INPSEL10 = val; return true;
            case 0x0030: INPSEL11 = val; return true;

            case 0x0034: INNSEL00 = val; return true;
            case 0x0038: INNSEL01 = val; return true;
            case 0x003C: INNSEL10 = val; return true;
            case 0x0040: INNSEL11 = val; return true;

            case 0x0044: CKDIV = val; return true;
            case 0x0048: ITIMER = val; return true;

            case 0x0058: WCFG0 = val; return true;
            case 0x005C: WCFG1 = val; return true;

            case 0x0068: ADCCAL = val; return true;
            case 0x006C: SHCAL = val; return true;

            // IMR is Read-only → cannot be written
            case 0x0078: return false;

            // Read-only registers → writes ignored
            case 0x0008:  // SR
            case 0x0060:  // LCV0
            case 0x0064:  // LCV1
            case 0x007C:  // VERSION
            case 0x0080:  // PARAMETER
            case 0x0084:  // RES
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {

            // ---- Write-only registers return null ----
            case 0x0000:
            case 0x000C:
            case 0x0010:
            case 0x0070:
            case 0x0074:
                return null;

            // ---- Read-only registers ----
            case 0x0008: return SR;
            case 0x0060: return LCV0;
            case 0x0064: return LCV1;
            case 0x0078: return IMR;
            case 0x007C: return VERSION;
            case 0x0080: return PARAMETER;
            case 0x0084: return RES;

            // ---- Read/Write registers ----
            case 0x0004: return CFG;

            case 0x0014: return SEQCFG0;
            case 0x0018: return SEQCFG1;

            case 0x001C: return SHG0;
            case 0x0020: return SHG1;

            case 0x0024: return INPSEL00;
            case 0x0028: return INPSEL01;
            case 0x002C: return INPSEL10;
            case 0x0030: return INPSEL11;

            case 0x0034: return INNSEL00;
            case 0x0038: return INNSEL01;
            case 0x003C: return INNSEL10;
            case 0x0040: return INNSEL11;

            case 0x0044: return CKDIV;
            case 0x0048: return ITIMER;

            case 0x0058: return WCFG0;
            case 0x005C: return WCFG1;

            case 0x0068: return ADCCAL;
            case 0x006C: return SHCAL;
        }

        return null;
    }
}

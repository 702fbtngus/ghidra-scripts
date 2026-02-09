package hw;

public class SDRAMC extends MmioDevice {

    int MR;       // 0x00
    int TR;       // 0x04
    int CR;       // 0x08
    int HSR;      // 0x0C
    int LPR;      // 0x10

    int IER;      // 0x14 (WO)
    int IDR;      // 0x18 (WO)
    int IMR;      // 0x1C (RO)
    int ISR;      // 0x20 (RO)

    int MDR;      // 0x24

    int VERSION;  // 0xFC (RO)

    public SDRAMC(long baseAddr, String name) {

        super(baseAddr, name, 0x400);
        resetRegisters();
    }
    
    @Override
    protected void link() {}

    protected void resetRegisters() {
            MR = 0x00000000;
            TR = 0x00000000;
            CR = 0x852372C0;
            HSR = 0x00000000;
            LPR = 0x00000000;
    
            IER = 0;
            IDR = 0;
    
            IMR = 0x00000000;
            ISR = 0x00000000;
    
            MDR = 0x00000000;
    
            VERSION = 0;  // device-specific
        }

    @Override
    protected boolean onWrite(int ofs, int v) {

        switch (ofs) {
            case 0x00: MR = v; return true;
            case 0x04: TR = v; return true;
            case 0x08: CR = v; return true;
            case 0x0C: HSR = v; return true;
            case 0x10: LPR = v; return true;

            case 0x14: IER = v; return true;   // WO
            case 0x18: IDR = v; return true;   // WO

            case 0x24: MDR = v; return true;

            // read-only registers
            case 0x1C:
            case 0x20:
            case 0xFC:
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {
            case 0x00: return MR;
            case 0x04: return TR;
            case 0x08: return CR;
            case 0x0C: return HSR;
            case 0x10: return LPR;

            case 0x1C: return IMR;  // RO
            case 0x20: return ISR;  // RO

            case 0x24: return MDR;

            case 0xFC: return VERSION;  // RO
        }

        // write-only registers → no read
        switch (ofs) {
            case 0x14:
            case 0x18:
                return null;
        }

        return null;
    }
}

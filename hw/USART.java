package hw;

public class USART extends MmioDevice {

    int CR, MR, IER, IDR, IMR;
    int CSR, RHR, THR;
    int BRGR, RTOR, TTGR;
    int FIDI, NER, IFR, MAN, LINMR, LINIR, LINBRR;
    int WPMR, WPSR;
    int VERSION;

    public USART(long baseAddr, String name) {
        super(baseAddr, name);

        // Reset values (from datasheet)
        CR = 0;       // Write-only
        MR = 0x00000000;
        IER = 0;
        IDR = 0;
        IMR = 0x00000000;

        CSR = 0x00000000;   // Read-only
        RHR = 0x00000000;   // Read-only
        THR = 0;            // Write-only

        BRGR = 0x00000000;
        RTOR = 0x00000000;
        TTGR = 0x00000000;

        FIDI = 0x00000174;
        NER = 0x00000000;
        IFR = 0x00000000;

        MAN = 0x30011004;
        LINMR = 0x00000000;
        LINIR = 0x00000000;
        LINBRR = 0x00000000;   // Read-only

        WPMR = 0x00000000;
        WPSR = 0x00000000;     // Read-only

        VERSION = 0;           // device-specific placeholder
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {

        switch (ofs) {

            case 0x00:  // CR - Write-only
                CR = val;
                CSR |= ((val >> 4) & 1);
                CSR |= ((val >> 6) & 1) << 1;
                return true;

            case 0x04:  // MR - Read/Write
                MR = val;
                return true;

            case 0x08:  // IER - Write-only
                IER = val;
                return true;

            case 0x0C:  // IDR - Write-only
                IDR = val;
                return true;

            case 0x1C:  // THR - Write-only
                THR = val;
                return true;

            case 0x20:  // BRGR
                BRGR = val;
                return true;

            case 0x24:  // RTOR
                RTOR = val;
                return true;

            case 0x28:  // TTGR
                TTGR = val;
                return true;

            case 0x40:  // FIDI
                FIDI = val;
                return true;

            case 0x4C:  // IFR
                IFR = val;
                return true;

            case 0x50:  // MAN
                MAN = val;
                return true;

            case 0x54:  // LINMR
                LINMR = val;
                return true;

            case 0x58:  // LINIR
                LINIR = val;
                return true;

            case 0xE4:  // WPMR
                WPMR = val;
                return true;

            // Read-only registers → writing not allowed
            case 0x10:  // IMR
            case 0x14:  // CSR
            case 0x18:  // RHR
            case 0x44:  // NER
            case 0x5C:  // LINBRR
            case 0xE8:  // WPSR
            case 0xFC:  // VERSION
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {

            // Read/Write registers
            case 0x04: return MR;
            case 0x20: return BRGR;
            case 0x24: return RTOR;
            case 0x28: return TTGR;
            case 0x40: return FIDI;
            case 0x4C: return IFR;
            case 0x50: return MAN;
            case 0x54: return LINMR;
            case 0x58: return LINIR;
            case 0xE4: return WPMR;

            // Read-only registers
            case 0x10: return IMR;
            case 0x14: return CSR;
            case 0x18: return RHR;
            case 0x44: return NER;
            case 0x5C: return LINBRR;
            case 0xE8: return WPSR;
            case 0xFC: return VERSION;

            // Write-only registers → read returns null
            case 0x00:  // CR
            case 0x08:  // IER
            case 0x0C:  // IDR
            case 0x1C:  // THR
                return null;
        }

        return null;
    }
}

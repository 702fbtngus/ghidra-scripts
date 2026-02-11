package hw;

public class SPI extends MmioDevice {

    // Registers
    int CR, MR, RDR, SR, IER, IDR, IMR;
    int TDR;
    int CSR0, CSR1, CSR2, CSR3;
    int WPCR, WPSR;
    int FEATURES, VERSION;

    public SPI(long baseAddr, String name, int group) {
        super(baseAddr, name, group);   // Nanomind A3200 SPI base address (확인했으면 수정 가능)

        // Reset values (datasheet says all zeros unless device-specific)
        CR = 0;
        MR = 0;
        RDR = 0;
        SR = 0;
        IER = 0;
        IDR = 0;
        IMR = 0;
        TDR = 0;

        CSR0 = CSR1 = CSR2 = CSR3 = 0;

        WPCR = 0;
        WPSR = 0;

        FEATURES = 0;   // device-specific placeholder
        VERSION  = 0;   // device-specific placeholder
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {

        switch (ofs) {

            case 0x00:  // CR - Write-only
                CR = val;
                SR |= (val & 0x00000001);
                SR |= (val & 0x00000001) << 1;
                SR |= (val & 0x00000001) << 9;
                return true;

            case 0x04:  // MR - Read/Write
                MR = val;
                return true;

            case 0x0C:  // TDR - Write-only
                TDR = val;
                return true;

            case 0x14:  // IER - Write-only
                IER = val;
                return true;

            case 0x18:  // IDR - Write-only
                IDR = val;
                return true;

            case 0x30:  // CSR0
                CSR0 = val;
                return true;

            case 0x34:  // CSR1
                CSR1 = val;
                return true;

            case 0x38:  // CSR2
                CSR2 = val;
                return true;

            case 0x3C:  // CSR3
                CSR3 = val;
                return true;

            case 0xE4:  // WPCR
                WPCR = val;
                return true;

            // Read-only registers
            case 0x08:  // RDR
            case 0x10:  // SR
            case 0x1C:  // IMR
            case 0xE8:  // WPSR
            case 0xF8:  // FEATURES
            case 0xFC:  // VERSION
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {

            case 0x04: return MR;
            case 0x08: return RDR;   // Read-only
            case 0x10: return SR;    // Read-only
            case 0x1C: return IMR;   // Read-only
            case 0x30: return CSR0;
            case 0x34: return CSR1;
            case 0x38: return CSR2;
            case 0x3C: return CSR3;
            case 0xE4: return WPCR;  // R/W
            case 0xE8: return WPSR;  // Read-only
            case 0xF8: return FEATURES;
            case 0xFC: return VERSION;

            // Write-only registers (return null)
            case 0x00:  // CR
            case 0x0C:  // TDR
            case 0x14:  // IER
            case 0x18:  // IDR
                return null;
        }

        return null;
    }
}

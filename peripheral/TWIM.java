package peripheral;

public class TWIM extends Peripheral {

    int CR, CWGR, SMBTR, CMDR, NCMDR;
    int RHR, THR, SR;
    int IER, IDR, IMR;
    int SCR, PR, VR;

    private INTC intc;

    public TWIM(long baseAddr, String name) {

        super(baseAddr, name);  // Nanomind A3200 TWIM0 base address

        // Reset values according to datasheet
        CR = 0x00000000;
        CWGR = 0x00000000;
        SMBTR = 0x00000000;
        CMDR = 0x00000000;
        NCMDR = 0x00000000;
        RHR = 0x00000000;
        THR = 0x00000000;
        SR = 0x00000002;     // Status Register reset = 0x2
        IER = 0x00000000;
        IDR = 0x00000000;
        IMR = 0x00000000;
        SCR = 0x00000000;

        // Device-specific (safe defaults)
        PR = 0x00000000;
        VR = 0x00000000;
    }

    @Override
    protected void link() {
        this.intc = (INTC) Peripheral.findPeripheral("INTC");
    }
    @Override
    protected boolean onWrite(int ofs, int val) {
        switch (ofs) {
            case 0x00:  // CR (write-only)
                CR = val;
                SR |= (val & 0x1) << 4; // turn on idle bit
                return true;

            case 0x04:  // CWGR (R/W)
                CWGR = val;
                return true;

            case 0x08:  // SMBTR (R/W)
                SMBTR = val;
                return true;

            case 0x0C:  // CMDR (R/W)
                CMDR = val;
                return true;

            case 0x10:  // NCMDR (R/W)
                NCMDR = val;
                return true;

            case 0x14:  // RHR (read-only)
                return false;

            case 0x18:  // THR (write-only)
                THR = val;
                return true;

            case 0x1C:  // SR (read-only)
                return false;

            case 0x20:  // IER (write-only)
                IER = val;
                return true;

            case 0x24:  // IDR (write-only)
                IDR = val;
                return true;

            case 0x28:  // IMR (read-only)
                return false;

            case 0x2C:  // SCR (write-only)
                SCR = val;
                return true;

            case 0x30:  // PR (read-only)
            case 0x34:  // VR (read-only)
                return false;
        }
        return false;
    }

    @Override
    protected Integer onRead(int ofs) {
        switch (ofs) {
            case 0x00:  // CR (write-only)
                return null;

            case 0x04:  return CWGR;
            case 0x08:  return SMBTR;
            case 0x0C:  return CMDR;
            case 0x10:  return NCMDR;

            case 0x14:  return RHR;     // read-only
            case 0x18:  return null;    // THR is write-only

            case 0x1C:  return SR;

            case 0x20:  return null;    // IER write-only
            case 0x24:  return null;    // IDR write-only

            case 0x28:  return IMR;

            case 0x2C:  return null;    // SCR write-only

            case 0x30:  return PR;
            case 0x34:  return VR;
        }
        return null;
    }
}

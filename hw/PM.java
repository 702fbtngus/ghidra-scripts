package hw;

public class PM extends MmioDevice {

    // -------------------------
    // Registers (Table 7-5)
    // -------------------------

    int MCCTRL;        // 0x0000 R/W
    int CPUSEL;        // 0x0004 R/W
    int HSBSEL;        // 0x0008 RO
    int PBSEL;         // 0x000C R/W
    int PBBSEL;        // 0x0010 R/W
    int PBCSEL;        // 0x0014 R/W

    int CPUMASK;       // 0x0020 R/W
    int HSBMASK;       // 0x0024 R/W
    int PBAMASK;       // 0x0028 R/W
    int PBBMASK;       // 0x002C R/W
    int PBCMASK;       // 0x0030 R/W

    int PBADIVMASK;    // 0x0040 R/W
    int PBBDIVMASK;    // 0x0044 R/W
    int PBCDIVMASK;    // 0x0048 R/W

    int CFCTRL;        // 0x0054 R/W
    int UNLOCK;        // 0x0058 WO

    int IER;           // 0x00C0 WO
    int IDR;           // 0x00C4 WO
    int IMR;           // 0x00C8 RO
    int ISR;           // 0x00CC RO
    int ICR;           // 0x00D0 WO

    int SR;            // 0x00D4 RO

    int RCAUSE;        // 0x0180 RO
    int WCAUSE;        // 0x0184 RO

    int AWEN;          // 0x0188 R/W

    int CONFIG;        // 0x03F8 RO (device-specific)
    int VERSION;       // 0x03FC RO (device-specific)

    public PM(long baseAddr, String name) {

        super(baseAddr, name, 0x400);
        resetRegisters();
    }
    
    @Override
    protected void link() {}

    // -------------------------
    // Reset Values from Table 7-5
    // -------------------------
    private void resetRegisters() {

        MCCTRL = 0x00000000;
        CPUSEL = 0x00000000;
        HSBSEL = 0x00000000;
        PBSEL  = 0x00000000;
        PBBSEL = 0x00000000;
        PBCSEL = 0x00000000;

        CPUMASK = 0x00000003;
        HSBMASK = 0x00003FFF;
        PBAMASK = 0x07FFFFFF;
        PBBMASK = 0x0000007F;
        PBCMASK = 0x000003FF;

        PBADIVMASK = 0x0000007F;
        PBBDIVMASK = 0x0000007F;
        PBCDIVMASK = 0x0000007F;

        CFCTRL = 0x00000000;
        UNLOCK = 0;  // WO register

        IER = 0x00000000;  // WO
        IDR = 0x00000000;  // WO
        IMR = 0x00000000;  // RO
        ISR = 0x00000000;  // RO
        ICR = 0x00000000;  // WO

        SR = 0x00000020;   // Read-only

        RCAUSE = 0;        // Latest reset source (external logic sets)
        WCAUSE = 0;        // Latest wake source
        AWEN   = 0x00000000;

        CONFIG  = 0;       // RO, device-specific (not defined)
        VERSION = 0;       // RO, device-specific (not defined)
    }


    // -------------------------
    // Write Handler
    // -------------------------
    @Override
    protected boolean onWrite(int ofs, int value) {

        switch (ofs) {

            case 0x0000: MCCTRL = value; return true;
            case 0x0004: CPUSEL = value; return true;

            case 0x0008: return false; // HSBSEL is RO

            case 0x000C: PBSEL  = value; return true;
            case 0x0010: PBBSEL = value; return true;
            case 0x0014: PBCSEL = value; return true;

            case 0x0020: CPUMASK = value; return true;
            case 0x0024: HSBMASK = value; return true;
            case 0x0028: PBAMASK = value; return true;
            case 0x002C: PBBMASK = value; return true;
            case 0x0030: PBCMASK = value; return true;

            case 0x0040: PBADIVMASK = value; return true;
            case 0x0044: PBBDIVMASK = value; return true;
            case 0x0048: PBCDIVMASK = value; return true;

            case 0x0054: CFCTRL = value; return true;

            case 0x0058: UNLOCK = value; return true; // write-only

            case 0x00C0: IER = value;  return true;  // write-only
            case 0x00C4: IDR = value;  return true;  // write-only
            case 0x00D0: ICR = value;  return true;  // write-only

            case 0x00C8: // IMR (RO)
            case 0x00CC: // ISR (RO)
            case 0x00D4: // SR (RO)
            case 0x0180: // RCAUSE (RO)
            case 0x0184: // WCAUSE (RO)
            case 0x03F8: // CONFIG (RO)
            case 0x03FC: // VERSION (RO)
                return false;

            case 0x0188: AWEN = value; return true; // R/W
        }

        return false;
    }


    // -------------------------
    // Read Handler
    // -------------------------
    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {

            case 0x0000: return MCCTRL;
            case 0x0004: return CPUSEL;
            case 0x0008: return HSBSEL;
            case 0x000C: return PBSEL;
            case 0x0010: return PBBSEL;
            case 0x0014: return PBCSEL;

            case 0x0020: return CPUMASK;
            case 0x0024: return HSBMASK;
            case 0x0028: return PBAMASK;
            case 0x002C: return PBBMASK;
            case 0x0030: return PBCMASK;

            case 0x0040: return PBADIVMASK;
            case 0x0044: return PBBDIVMASK;
            case 0x0048: return PBCDIVMASK;

            case 0x0054: return CFCTRL;

            case 0x00C8: return IMR;
            case 0x00CC: return ISR;
            case 0x00D4: return SR;

            case 0x0180: return RCAUSE;
            case 0x0184: return WCAUSE;

            case 0x0188: return AWEN;

            case 0x03F8: return CONFIG;
            case 0x03FC: return VERSION;
        }

        // write-only registers
        switch (ofs) {
            case 0x0058:  // UNLOCK
            case 0x00C0:  // IER
            case 0x00C4:  // IDR
            case 0x00D0:  // ICR
                return null;
        }

        return null;
    }


    //-------------------------
    // Helpers
    //-------------------------

    public void setResetCause(int cause) { RCAUSE = cause; }
    public void setWakeCause(int cause) { WCAUSE = cause; }
}

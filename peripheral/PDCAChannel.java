package peripheral;

public class PDCAChannel {

    int MAR, PSR, TCR, MARR, TCRR, CR, MR, SR, IMR, IER, IDR, ISR;
    public final int ch;

    public PDCAChannel(int ch) {
        this.ch = ch;

        MAR = 0;
        PSR = 0;
        TCR = 0;
        MARR = 0;
        TCRR = 0;

        CR = 0;
        MR = 0;
        SR = 0;
        IMR = 0;
        IER = 0;
        IDR = 0;
        ISR = 0;
    }

    // Called only by PDCA
    public boolean onWrite(int ofs, int val) {

        switch (ofs) {
            case 0x00: MAR = val; return true;
            case 0x04: PSR = val; return true;
            case 0x08: TCR = val; return true;
            case 0x0C: MARR = val; return true;
            case 0x10: TCRR = val; return true;

            case 0x14: CR = val; return true; // WO
            case 0x18: MR = val; return true; // RW

            case 0x20: IER = val; return true;
            case 0x24: IDR = val; return true;

            // RO
            case 0x1C:
            case 0x28:
            case 0x2C:
                return false;
        }
        return false;
    }

    public Integer onRead(int ofs) {

        switch (ofs) {
            case 0x00: return MAR;
            case 0x04: return PSR;
            case 0x08: return TCR;
            case 0x0C: return MARR;
            case 0x10: return TCRR;

            case 0x18: return MR;
            case 0x1C: return SR;
            case 0x28: return IMR;
            case 0x2C: return ISR;
        }

        // write-only registers → null
        return null;
    }
}

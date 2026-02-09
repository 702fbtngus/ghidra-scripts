package hw;

public class PDCAChannel {

    int MAR, PSR, TCR, MARR, TCRR, CR, MR, SR, IMR, IER, IDR, ISR;
    public final int ch;
    PDCA pdca;

    public PDCAChannel(int ch, PDCA pdca) {
        this.ch = ch;
        this.pdca = pdca;

        MAR = 0;
        PSR = ch;
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

            case 0x08:
                TCR = val;
                checkTransferData();
                return true;

            case 0x0C: MARR = val; return true;
            case 0x10: TCRR = val; return true;

            case 0x14:
                CR = val;
                
                if ((CR >> 8 & 1) == 1) {
                    // Clear ISR.TERR
                    ISR &= ~(1 << 2);
                };
                if ((CR >> 1 & 1) == 1) {
                    // Transfer Disable
                    SR &= ~1;
                };
                if ((CR & 1) == 1) {
                    // Transfer Enable
                    SR |= 1;
                };
                checkTransferData();
                return true;

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

    private void checkTransferData() {
        while (
            (CR & 1) == 1
            && TCR > 0
        ) {
            int size = 1 << (MR & 0b11);
            pdca.transferData(MAR, PSR, size);
            MAR += size;
            TCR -= 1;
        }
    }
}

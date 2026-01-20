package peripheral;

public class TC extends Peripheral {

    private static class Channel {
        int CCR, CMR, CV, RA, RB, RC, SR, IER, IDR, IMR;

        Channel() {
            CCR = CMR = CV = RA = RB = RC = SR = IER = IDR = IMR = 0;
        }
    }

    Channel[] ch = new Channel[3];

    // Block registers
    int BCR, BMR, FEATURES, VERSION;

    public TC(long baseAddr, String name) {
        super(baseAddr, name, 0x400);

        for (int i = 0; i < 3; i++)
            ch[i] = new Channel();

        BCR = 0;
        BMR = 0;
        FEATURES = 0;
        VERSION = 0;
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {

        // ---------- Channel registers ----------
        int channel = (ofs >> 6) & 0x3;   // 0x00~0x3F → 0, 0x40~0x7F → 1, 0x80~0xBF → 2
        int off = ofs & 0x3F;             // low 6 bits = register offset inside channel

        if (channel < 3) {
            Channel c = ch[channel];
            switch (off) {
                case 0x00: c.CCR = val; return true;
                case 0x04: c.CMR = val; return true;
                case 0x14: c.RA  = val; return true;
                case 0x18: c.RB  = val; return true;
                case 0x1C: c.RC  = val; return true;
                case 0x24: c.IER = val; return true;
                case 0x28: c.IDR = val; return true;

                // Read-only
                case 0x10: // CV
                case 0x20: // SR
                case 0x2C: // IMR
                    return false;
            }
        }

        // ---------- Block-level registers ----------
        switch (ofs) {
            case 0xC0: BCR = val; return true;
            case 0xC4: BMR = val; return true;

            case 0xF8: // read-only
            case 0xFC: // read-only
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        // ---------- Channel registers ----------
        int channel = (ofs >> 6) & 0x3;
        int off = ofs & 0x3F;

        if (channel < 3) {
            Channel c = ch[channel];
            switch (off) {
                case 0x00: return null;        // CCR write-only
                case 0x04: return c.CMR;
                case 0x10: return ++c.CV;
                case 0x14: return c.RA;
                case 0x18: return c.RB;
                case 0x1C: return c.RC;
                case 0x20: return c.SR;
                case 0x24: return null;        // IER write-only
                case 0x28: return null;        // IDR write-only
                case 0x2C: return c.IMR;
            }
        }

        // ---------- Block-level ----------
        switch (ofs) {
            case 0xC0: return null; // BCR write-only
            case 0xC4: return BMR;
            case 0xF8: return FEATURES;
            case 0xFC: return VERSION;
        }

        return null;
    }
}

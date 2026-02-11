package hw;

public class HMATRIX extends MmioDevice {

    // MCFG0~MCFG15 (0x0000 ~ 0x003C)
    int[] MCFG = new int[16];

    // SCFG0~SCFG15 (0x0040 ~ 0x007C)
    int[] SCFG = new int[16];

    // PRAS0~PRAS15 (0x0080 ~ 0x00BC)
    int[] PRAS = new int[16];

    // PRBS0~PRBS15 (0x0084 ~ 0x00C0)
    int[] PRBS = new int[16];

    // SFR0~SFR15 (0x0110 ~ 0x014C)
    int[] SFR = new int[16];

    public HMATRIX(long baseAddr, String name, int group) {

        super(baseAddr, name, group);
        resetRegisters();
    }
    
    @Override
    protected void link() {}

    private void resetRegisters() {

        // MCFG reset = 0x00000002
        for (int i = 0; i < 16; i++)
            MCFG[i] = 0x00000002;

        // SCFG reset = 0x00000010
        for (int i = 0; i < 16; i++)
            SCFG[i] = 0x00000010;

        // PRAS reset = 0
        for (int i = 0; i < 16; i++)
            PRAS[i] = 0;

        // PRBS reset = 0
        for (int i = 0; i < 16; i++)
            PRBS[i] = 0;

        // SFR reset = 0 (device specific)
        for (int i = 0; i < 16; i++)
            SFR[i] = 0;
    }

    @Override
    protected boolean onWrite(int ofs, int v) {

        // MCFG
        if (ofs >= 0x0000 && ofs <= 0x003C) {
            int idx = (ofs - 0x0000) >> 2;
            MCFG[idx] = v;
            return true;
        }

        // SCFG
        if (ofs >= 0x0040 && ofs <= 0x007C) {
            int idx = (ofs - 0x0040) >> 2;
            SCFG[idx] = v;
            return true;
        }

        // PRAS
        if (ofs >= 0x0080 && ofs <= 0x00BC && ((ofs & 0x4) == 0)) {
            int idx = (ofs - 0x0080) >> 2;
            PRAS[idx] = v;
            return true;
        }

        // PRBS
        if (ofs >= 0x0084 && ofs <= 0x00C0 && ((ofs & 0x4) == 0)) {
            int idx = (ofs - 0x0084) >> 2;
            PRBS[idx] = v;
            return true;
        }

        // SFR
        if (ofs >= 0x0110 && ofs <= 0x014C) {
            int idx = (ofs - 0x0110) >> 2;
            if (idx < 16) {
                SFR[idx] = v;
                return true;
            }
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        // MCFG
        if (ofs >= 0x0000 && ofs <= 0x003C) {
            int idx = (ofs - 0x0000) >> 2;
            return MCFG[idx];
        }

        // SCFG
        if (ofs >= 0x0040 && ofs <= 0x007C) {
            int idx = (ofs - 0x0040) >> 2;
            return SCFG[idx];
        }

        // PRAS
        if (ofs >= 0x0080 && ofs <= 0x00BC && ((ofs & 0x4) == 0)) {
            int idx = (ofs - 0x0080) >> 2;
            return PRAS[idx];
        }

        // PRBS
        if (ofs >= 0x0084 && ofs <= 0x00C0 && ((ofs & 0x4) == 0)) {
            int idx = (ofs - 0x0084) >> 2;
            return PRBS[idx];
        }

        // SFR
        if (ofs >= 0x0110 && ofs <= 0x014C) {
            int idx = (ofs - 0x0110) >> 2;
            if (idx < 16)
                return SFR[idx];
        }

        return null;
    }
}

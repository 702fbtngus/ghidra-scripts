package peripheral;

public class TWIS extends Peripheral {

    int CR, NBYTES, TR, RHR, THR, PECR, SR;
    int IER, IDR, IMR, SCR, PR, VR;

    public TWIS(long baseAddr, String name) {

        super(baseAddr, name);

        CR = 0;
        NBYTES = 0;
        TR = 0;

        RHR = 0;
        THR = 0;
        PECR = 0;

        SR = 0x02;
        IER = 0; IDR = 0;
        IMR = 0;

        SCR = 0;

        PR = 0;
        VR = 0;
    }

    @Override
    protected boolean onWrite(int ofs, int v) {

        switch (ofs) {
            // RW
            case 0x00: CR = v; return true;
            case 0x04: NBYTES = v; return true;
            case 0x08: TR = v; return true;

            // RO
            case 0x0C: case 0x14: case 0x18:
            case 0x24: case 0x2C: case 0x30:
                return false;

            // WO
            case 0x10: THR = v; return true;
            case 0x1C: IER = v; return true;
            case 0x20: IDR = v; return true;
            case 0x28: SCR = v; return true;
        }
        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {
            // RW
            case 0x00: return CR;
            case 0x04: return NBYTES;
            case 0x08: return TR;

            // RO
            case 0x0C: return RHR;
            case 0x14: return PECR;
            case 0x18: return SR;
            case 0x24: return IMR;
            case 0x2C: return PR;
            case 0x30: return VR;
        }

        // THR, IER, IDR, SCR are WO
        return null;
    }
}

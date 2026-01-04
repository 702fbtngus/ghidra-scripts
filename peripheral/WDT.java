package peripheral;

public class WDT extends Peripheral {

    int CTRL, CLR, ST, VERSION;

    public WDT(long baseAddr, String name) {

        super(baseAddr, name);
        CTRL = 0x00010080;
        CLR = 0;
        ST = 0x00000003;
        VERSION = 0x00000410;
    }

    @Override
    protected boolean onWrite(int ofs, int val) {
        switch (ofs) {
            case 0x00: CTRL = val; return true;
            case 0x04: CLR = val; return true;
            case 0x08: ST = val;  return true;
            case 0x3FC: return false; // read-only
        }
        return false;
    }

    @Override
    protected Integer onRead(int ofs) {
        switch (ofs) {
            case 0x00: return CTRL & 0x00ffffff;
            case 0x04: return CLR;
            case 0x08: return ST;
            case 0x3FC: return VERSION;
        }
        return null;
    }
}

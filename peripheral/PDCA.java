package peripheral;

public class PDCA extends Peripheral {

    public static final int NUM_CHANNELS = 16;

    PDCAChannel[] channels = new PDCAChannel[NUM_CHANNELS];
    PDCAPerfMonitor mon = new PDCAPerfMonitor();
    int VERSION;

    public PDCA(long baseAddr, String name) {

        super(baseAddr, name, 0x1000);

        for (int i = 0; i < NUM_CHANNELS; i++) {
            channels[i] = new PDCAChannel(i);
        }

        VERSION = 0;
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {

        // Channel area
        if (ofs < 0x800) {
            int ch = ofs / 0x40;
            int ro = ofs % 0x40;

            if (ch < NUM_CHANNELS) {
                return channels[ch].onWrite(ro, val);
            }
            return false;
        }

        // Perf monitor area
        if (ofs >= 0x800 && ofs <= 0x830) {
            return mon.onWrite(ofs - 0x800, val);
        }

        // Version is read-only
        if (ofs == 0x834) return false;

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        if (ofs < 0x800) {
            int ch = ofs / 0x40;
            int ro = ofs % 0x40;

            if (ch < NUM_CHANNELS) {
                return channels[ch].onRead(ro);
            }
            return null;
        }

        if (ofs >= 0x800 && ofs <= 0x830) {
            return mon.onRead(ofs - 0x800);
        }

        if (ofs == 0x834) return VERSION;

        return null;
    }
}

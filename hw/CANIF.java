package hw;

public class CANIF extends MmioDevice {

    int VERSION, PARAMETER;

    CANIFChannel[] channels;

    public CANIF(long baseAddr, String name, int group) {

        super(baseAddr, name, group);

        VERSION = 0x10200110;
        PARAMETER = 0x00000010;

        int chno = VERSION >> 20 & 0b111;
        int[] mnch = {
            VERSION >> 24 & 0x3f,
            PARAMETER & 0x3f,
            PARAMETER >> 8 & 0x3f,
            PARAMETER >> 16 & 0x3f,
            PARAMETER >> 24 & 0x3f,
        };

        channels = new CANIFChannel[chno];
        for (int i = 0; i < chno; i++) {
            channels[i] = new CANIFChannel(i, this, mnch[i]);
        }
    }

    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int v) {

        // Common registers
        switch (ofs) {
            case 0x00:
            case 0x04:
                return false;
        }

        // Channel area
        if (ofs < 0xa00) {
            int ch = ofs / 0x200;
            int ro = ofs % 0x200;

            if (ch < channels.length) {
                return channels[ch].onWrite(ro, v);
            }
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        // Common registers
        switch (ofs) {
            case 0x00: return VERSION;
            case 0x04: return PARAMETER;
        }

        // Channel area
        if (ofs < 0xa00) {
            int ch = ofs / 0x200;
            int ro = ofs % 0x200;

            if (ch < channels.length) {
                return channels[ch].onRead(ro);
            }
        }
        
        return null;
    }
}

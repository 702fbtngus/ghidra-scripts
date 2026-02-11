package hw;

public class GPIO extends MmioDevice {

    private final GPIOPort[] ports = new GPIOPort[4];

    public GPIO(long baseAddr, String name, int group) {

        super(baseAddr, name, group, 0x800l);   // 4 ports × 0x200

        ports[0] = new GPIOPort(0);
        ports[1] = new GPIOPort(1);
        ports[2] = new GPIOPort(2);
        ports[3] = new GPIOPort(3);
    }
    
    @Override
    protected void link() {}

    private GPIOPort decodePort(int offset) {
        int p = offset >>> 9;   // each port = 0x200
        if (p < 0 || p >= 4) return null;
        return ports[p];
    }

    private int decodeLocalOffset(int offset) {
        return offset & 0x1FF;
    }

    @Override
    protected boolean onWrite(int offset, int value) {

        GPIOPort port = decodePort(offset);
        if (port == null) return false;

        int ofs = decodeLocalOffset(offset);
        return port.writeReg(ofs, value);
    }

    @Override
    protected Integer onRead(int offset) {

        GPIOPort port = decodePort(offset);
        if (port == null) return null;

        int ofs = decodeLocalOffset(offset);
        return port.readReg(ofs);
    }
}

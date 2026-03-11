package hw;

import hw.MmioDevice.Register.AccessType;

public class WDT extends MmioDevice {

    Register CTRL, CLR, ST, VERSION;

    public WDT(long baseAddr, String name, int group) {

        super(baseAddr, name, group);
        CTRL = newRegister(0x00, 0x00010080, AccessType.READ_WRITE);
        CLR = newRegister(0x04, 0, AccessType.READ_WRITE);
        ST = newRegister(0x08, 0x00000003, AccessType.READ_WRITE);
        VERSION = newRegister(0x3FC, 0x00000410, AccessType.READ_ONLY);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {
        return super.onWrite(ofs, val);
    }

    @Override
    protected Integer onRead(int ofs) {
        switch (ofs) {
            case 0x00: return CTRL.value & 0x00ffffff;
            default: return super.onRead(ofs);
        }
    }
}

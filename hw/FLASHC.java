package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class FLASHC extends MmioDevice {

    Register FCR;        // 0x00 Read/Write
    Register FCMD;       // 0x04 Read/Write
    Register FSR;        // 0x08 Read/Write
    Register PR;         // 0x0C Read-only
    Register VR;         // 0x10 Read-only
    Register FGPFRHI;    // 0x14 Read-only
    Register FGPFRLO;    // 0x18 Read-only

    public FLASHC(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);
        resetRegisters();
    }
    
    @Override
    public void link() {}

    private void resetRegisters() {
        // RW registers reset to 0
        FCR = newRegister(0x00, 0x00000000, AccessType.READ_WRITE);
        FCMD = newRegister(0x04, 0x00000000, AccessType.READ_WRITE);
        FSR = newRegister(0x08, 0x00000000, AccessType.READ_WRITE);
        PR = newRegister(0x0C, 0, AccessType.READ_ONLY);
        VR = newRegister(0x10, 0, AccessType.READ_ONLY);
        FGPFRHI = newRegister(0x14, 0, AccessType.READ_ONLY);
        FGPFRLO = newRegister(0x18, 0, AccessType.READ_ONLY);
    }

    @Override
    protected boolean onWrite(int ofs, int v) {
        return super.onWrite(ofs, v);
    }

    @Override
    protected Integer onRead(int ofs) {
        return super.onRead(ofs);
    }
}

package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class TWIS extends MmioDevice {

    Register CR, NBYTES, TR, RHR, THR, PECR, SR;
    Register IER, IDR, IMR, SCR, PR, VR;

    public TWIS(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);

        CR = newRegister(0x00, 0, AccessType.READ_WRITE);
        NBYTES = newRegister(0x04, 0, AccessType.READ_WRITE);
        TR = newRegister(0x08, 0, AccessType.READ_WRITE);
        RHR = newRegister(0x0C, 0, AccessType.READ_ONLY);
        THR = newRegister(0x10, 0, AccessType.WRITE_ONLY);
        PECR = newRegister(0x14, 0, AccessType.READ_ONLY);
        SR = newRegister(0x18, 0x02, AccessType.READ_ONLY);
        IER = newRegister(0x1C, 0, AccessType.WRITE_ONLY);
        IDR = newRegister(0x20, 0, AccessType.WRITE_ONLY);
        IMR = newRegister(0x24, 0, AccessType.READ_ONLY);
        SCR = newRegister(0x28, 0, AccessType.WRITE_ONLY);
        PR = newRegister(0x2C, 0, AccessType.READ_ONLY);
        VR = newRegister(0x30, 0, AccessType.READ_ONLY);
    }
    
    @Override
    public void link() {}

    @Override
    protected boolean onWrite(int ofs, int v) {
        return super.onWrite(ofs, v);
    }

    @Override
    protected Integer onRead(int ofs) {
        return super.onRead(ofs);
    }
}

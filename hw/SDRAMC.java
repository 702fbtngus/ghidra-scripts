package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class SDRAMC extends MmioDevice {

    Register MR;       // 0x00
    Register TR;       // 0x04
    Register CR;       // 0x08
    Register HSR;      // 0x0C
    Register LPR;      // 0x10
    Register IER;      // 0x14 (WO)
    Register IDR;      // 0x18 (WO)
    Register IMR;      // 0x1C (RO)
    Register ISR;      // 0x20 (RO)
    Register MDR;      // 0x24
    Register VERSION;  // 0xFC (RO)

    public SDRAMC(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);
        resetRegisters();
    }
    
    @Override
    public void link() {}

    protected void resetRegisters() {
        MR = newRegister(0x00, 0x00000000, AccessType.READ_WRITE);
        TR = newRegister(0x04, 0x00000000, AccessType.READ_WRITE);
        CR = newRegister(0x08, 0x852372C0, AccessType.READ_WRITE);
        HSR = newRegister(0x0C, 0x00000000, AccessType.READ_WRITE);
        LPR = newRegister(0x10, 0x00000000, AccessType.READ_WRITE);
        IER = newRegister(0x14, 0, AccessType.WRITE_ONLY);
        IDR = newRegister(0x18, 0, AccessType.WRITE_ONLY);
        IMR = newRegister(0x1C, 0x00000000, AccessType.READ_ONLY);
        ISR = newRegister(0x20, 0x00000000, AccessType.READ_ONLY);
        MDR = newRegister(0x24, 0x00000000, AccessType.READ_WRITE);
        VERSION = newRegister(0xFC, 0, AccessType.READ_ONLY);
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

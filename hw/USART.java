package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class USART extends MmioDevice {

    Register CR, MR, IER, IDR, IMR;
    Register CSR, RHR, THR;
    Register BRGR, RTOR, TTGR;
    Register FIDI, NER, IFR, MAN, LINMR, LINIR, LINBRR;
    Register WPMR, WPSR;
    Register VERSION;

    public USART(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);

        // Reset values (from datasheet)
        CR = newRegister(0x00, 0, AccessType.WRITE_ONLY);
        MR = newRegister(0x04, 0x00000000, AccessType.READ_WRITE);
        IER = newRegister(0x08, 0, AccessType.WRITE_ONLY);
        IDR = newRegister(0x0C, 0, AccessType.WRITE_ONLY);
        IMR = newRegister(0x10, 0x00000000, AccessType.READ_ONLY);
        CSR = newRegister(0x14, 0x00000000, AccessType.READ_ONLY);
        RHR = newRegister(0x18, 0x00000000, AccessType.READ_ONLY);
        THR = newRegister(0x1C, 0, AccessType.WRITE_ONLY);
        BRGR = newRegister(0x20, 0x00000000, AccessType.READ_WRITE);
        RTOR = newRegister(0x24, 0x00000000, AccessType.READ_WRITE);
        TTGR = newRegister(0x28, 0x00000000, AccessType.READ_WRITE);
        FIDI = newRegister(0x40, 0x00000174, AccessType.READ_WRITE);
        NER = newRegister(0x44, 0x00000000, AccessType.READ_ONLY);
        IFR = newRegister(0x4C, 0x00000000, AccessType.READ_WRITE);
        MAN = newRegister(0x50, 0x30011004, AccessType.READ_WRITE);
        LINMR = newRegister(0x54, 0x00000000, AccessType.READ_WRITE);
        LINIR = newRegister(0x58, 0x00000000, AccessType.READ_WRITE);
        LINBRR = newRegister(0x5C, 0x00000000, AccessType.READ_ONLY);
        WPMR = newRegister(0xE4, 0x00000000, AccessType.READ_WRITE);
        WPSR = newRegister(0xE8, 0x00000000, AccessType.READ_ONLY);
        VERSION = newRegister(0xFC, 0, AccessType.READ_ONLY);
    }
    
    @Override
    public void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {
        if (!super.onWrite(ofs, val)) {
            return false;
        }

        switch (ofs) {
            case 0x00:  // CR - Write-only
                CSR.value |= ((val >> 4) & 1);
                CSR.value |= ((val >> 6) & 1) << 1;
                break;
        }

        return true;
    }

    @Override
    protected Integer onRead(int ofs) {
        return super.onRead(ofs);
    }
}

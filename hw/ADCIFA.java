package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class ADCIFA extends MmioDevice {

    // ---- Registers ----
    Register CR, CFG, SR, SCR, SSR;
    Register SEQCFG0, SEQCFG1;
    Register SHG0, SHG1;
    Register INPSEL00, INPSEL01, INPSEL10, INPSEL11;
    Register INNSEL00, INNSEL01, INNSEL10, INNSEL11;
    Register CKDIV, ITIMER;
    Register WCFG0, WCFG1;
    Register LCV0, LCV1;
    Register ADCCAL, SHCAL;
    Register IER, IDR, IMR;
    Register VERSION, PARAMETER, RES, RESERVED_A0;

    public ADCIFA(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);

        // Reset values are device-specific but shown as 0 in datasheet
        CR = newRegister(0x0000, 0, AccessType.WRITE_ONLY);
        CFG = newRegister(0x0004, 0, AccessType.READ_WRITE);
        SR = newRegister(0x0008, 1 << 0xe | 1, AccessType.READ_ONLY);
        SCR = newRegister(0x000C, 0, AccessType.WRITE_ONLY);
        SSR = newRegister(0x0010, 0, AccessType.WRITE_ONLY);
        SEQCFG0 = newRegister(0x0014, 0, AccessType.READ_WRITE);
        SEQCFG1 = newRegister(0x0018, 0, AccessType.READ_WRITE);
        SHG0 = newRegister(0x001C, 0, AccessType.READ_WRITE);
        SHG1 = newRegister(0x0020, 0, AccessType.READ_WRITE);
        INPSEL00 = newRegister(0x0024, 0, AccessType.READ_WRITE);
        INPSEL01 = newRegister(0x0028, 0, AccessType.READ_WRITE);
        INPSEL10 = newRegister(0x002C, 0, AccessType.READ_WRITE);
        INPSEL11 = newRegister(0x0030, 0, AccessType.READ_WRITE);
        INNSEL00 = newRegister(0x0034, 0, AccessType.READ_WRITE);
        INNSEL01 = newRegister(0x0038, 0, AccessType.READ_WRITE);
        INNSEL10 = newRegister(0x003C, 0, AccessType.READ_WRITE);
        INNSEL11 = newRegister(0x0040, 0, AccessType.READ_WRITE);
        CKDIV = newRegister(0x0044, 0, AccessType.READ_WRITE);
        ITIMER = newRegister(0x0048, 0, AccessType.READ_WRITE);
        WCFG0 = newRegister(0x0058, 0, AccessType.READ_WRITE);
        WCFG1 = newRegister(0x005C, 0, AccessType.READ_WRITE);
        LCV0 = newRegister(0x0060, 0, AccessType.READ_ONLY);
        LCV1 = newRegister(0x0064, 0, AccessType.READ_ONLY);
        ADCCAL = newRegister(0x0068, 0, AccessType.READ_WRITE);
        SHCAL = newRegister(0x006C, 0, AccessType.READ_WRITE);
        IER = newRegister(0x0070, 0, AccessType.WRITE_ONLY);
        IDR = newRegister(0x0074, 0, AccessType.WRITE_ONLY);
        IMR = newRegister(0x0078, 0, AccessType.READ_ONLY);
        VERSION = newRegister(0x007C, 0, AccessType.READ_ONLY);
        PARAMETER = newRegister(0x0080, 0, AccessType.READ_ONLY);
        RES = newRegister(0x0084, 0, AccessType.READ_ONLY);
        RESERVED_A0 = newRegister(0x00A0, 0, AccessType.READ_ONLY); // Temporarily bypassing error
    }

    @Override
    public void link() {}
}

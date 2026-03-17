package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class PM extends MmioDevice {

    // -------------------------
    // Registers (Table 7-5)
    // -------------------------

    Register MCCTRL;        // 0x0000 R/W
    Register CPUSEL;        // 0x0004 R/W
    Register HSBSEL;        // 0x0008 RO
    Register PBSEL;         // 0x000C R/W
    Register PBBSEL;        // 0x0010 R/W
    Register PBCSEL;        // 0x0014 R/W
    Register CPUMASK;       // 0x0020 R/W
    Register HSBMASK;       // 0x0024 R/W
    Register PBAMASK;       // 0x0028 R/W
    Register PBBMASK;       // 0x002C R/W
    Register PBCMASK;       // 0x0030 R/W
    Register PBADIVMASK;    // 0x0040 R/W
    Register PBBDIVMASK;    // 0x0044 R/W
    Register PBCDIVMASK;    // 0x0048 R/W
    Register CFCTRL;        // 0x0054 R/W
    Register UNLOCK;        // 0x0058 WO
    Register IER;           // 0x00C0 WO
    Register IDR;           // 0x00C4 WO
    Register IMR;           // 0x00C8 RO
    Register ISR;           // 0x00CC RO
    Register ICR;           // 0x00D0 WO
    Register SR;            // 0x00D4 RO
    Register RCAUSE;        // 0x0180 RO
    Register WCAUSE;        // 0x0184 RO
    Register AWEN;          // 0x0188 R/W
    Register CONFIG;        // 0x03F8 RO
    Register VERSION;       // 0x03FC RO

    public PM(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);
        resetRegisters();
    }
    
    @Override
    public void link() {}

    // -------------------------
    // Reset Values from Table 7-5
    // -------------------------
    private void resetRegisters() {

        MCCTRL = newRegister(0x0000, 0x00000000, AccessType.READ_WRITE);
        CPUSEL = newRegister(0x0004, 0x00000000, AccessType.READ_WRITE);
        HSBSEL = newRegister(0x0008, 0x00000000, AccessType.READ_ONLY);
        PBSEL = newRegister(0x000C, 0x00000000, AccessType.READ_WRITE);
        PBBSEL = newRegister(0x0010, 0x00000000, AccessType.READ_WRITE);
        PBCSEL = newRegister(0x0014, 0x00000000, AccessType.READ_WRITE);
        CPUMASK = newRegister(0x0020, 0x00000003, AccessType.READ_WRITE);
        HSBMASK = newRegister(0x0024, 0x00003FFF, AccessType.READ_WRITE);
        PBAMASK = newRegister(0x0028, 0x07FFFFFF, AccessType.READ_WRITE);
        PBBMASK = newRegister(0x002C, 0x0000007F, AccessType.READ_WRITE);
        PBCMASK = newRegister(0x0030, 0x000003FF, AccessType.READ_WRITE);
        PBADIVMASK = newRegister(0x0040, 0x0000007F, AccessType.READ_WRITE);
        PBBDIVMASK = newRegister(0x0044, 0x0000007F, AccessType.READ_WRITE);
        PBCDIVMASK = newRegister(0x0048, 0x0000007F, AccessType.READ_WRITE);
        CFCTRL = newRegister(0x0054, 0x00000000, AccessType.READ_WRITE);
        UNLOCK = newRegister(0x0058, 0, AccessType.WRITE_ONLY);
        IER = newRegister(0x00C0, 0x00000000, AccessType.WRITE_ONLY);
        IDR = newRegister(0x00C4, 0x00000000, AccessType.WRITE_ONLY);
        IMR = newRegister(0x00C8, 0x00000000, AccessType.READ_ONLY);
        ISR = newRegister(0x00CC, 0x00000000, AccessType.READ_ONLY);
        ICR = newRegister(0x00D0, 0x00000000, AccessType.WRITE_ONLY);
        SR = newRegister(0x00D4, 0x00000020, AccessType.READ_ONLY);
        RCAUSE = newRegister(0x0180, 0, AccessType.READ_ONLY);
        WCAUSE = newRegister(0x0184, 0, AccessType.READ_ONLY);
        AWEN = newRegister(0x0188, 0x00000000, AccessType.READ_WRITE);
        CONFIG = newRegister(0x03F8, 0, AccessType.READ_ONLY);
        VERSION = newRegister(0x03FC, 0, AccessType.READ_ONLY);
    }


    // -------------------------
    // Write Handler
    // -------------------------
    @Override
    protected boolean onWrite(int ofs, int value) {
        return super.onWrite(ofs, value);
    }


    // -------------------------
    // Read Handler
    // -------------------------
    @Override
    protected Integer onRead(int ofs) {
        return super.onRead(ofs);
    }


    //-------------------------
    // Helpers
    //-------------------------

    public void setResetCause(int cause) { RCAUSE.value = cause; }
    public void setWakeCause(int cause) { WCAUSE.value = cause; }
}

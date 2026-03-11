package hw;

import hw.MmioDevice.Register.AccessType;

public class SPI extends MmioDevice {

    // Registers
    Register CR, MR, RDR, SR, IER, IDR, IMR;
    Register TDR;
    Register CSR0, CSR1, CSR2, CSR3;
    Register WPCR, WPSR;
    Register FEATURES, VERSION;

    public SPI(long baseAddr, String name, int group) {
        super(baseAddr, name, group);   // Nanomind A3200 SPI base address (확인했으면 수정 가능)

        // Reset values (datasheet says all zeros unless device-specific)
        CR = newRegister(0x00, 0, AccessType.WRITE_ONLY);
        MR = newRegister(0x04, 0, AccessType.READ_WRITE);
        RDR = newRegister(0x08, 0, AccessType.READ_ONLY);
        TDR = newRegister(0x0C, 0, AccessType.WRITE_ONLY);
        SR = newRegister(0x10, 0, AccessType.READ_ONLY);
        IER = newRegister(0x14, 0, AccessType.WRITE_ONLY);
        IDR = newRegister(0x18, 0, AccessType.WRITE_ONLY);
        IMR = newRegister(0x1C, 0, AccessType.READ_ONLY);
        CSR0 = newRegister(0x30, 0, AccessType.READ_WRITE);
        CSR1 = newRegister(0x34, 0, AccessType.READ_WRITE);
        CSR2 = newRegister(0x38, 0, AccessType.READ_WRITE);
        CSR3 = newRegister(0x3C, 0, AccessType.READ_WRITE);
        WPCR = newRegister(0xE4, 0, AccessType.READ_WRITE);
        WPSR = newRegister(0xE8, 0, AccessType.READ_ONLY);
        FEATURES = newRegister(0xF8, 0, AccessType.READ_ONLY);
        VERSION = newRegister(0xFC, 0, AccessType.READ_ONLY);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {
        if (!super.onWrite(ofs, val)) {
            return false;
        }

        switch (ofs) {
            case 0x00:  // CR - Write-only
                SR.value |= (val & 0x00000001);
                SR.value |= (val & 0x00000001) << 1;
                SR.value |= (val & 0x00000001) << 9;
                break;
        }

        return true;
    }

    @Override
    protected Integer onRead(int ofs) {
        return super.onRead(ofs);
    }
}

package hw;

import helper.ByteUtil.DataSize;
import hw.MmioDevice.Register;
import hw.MmioDevice.Register.AccessType;

public class PDCAChannel extends MmioRegion {

    Register MAR, PSR, TCR, MARR, TCRR, CR, MR, SR, IMR, IER, IDR, ISR;
    public final int ch;
    PDCA pdca;

    public PDCAChannel(int ch, int base, PDCA pdca) {
        super(pdca, base, 0x40);
        this.ch = ch;
        this.pdca = pdca;

        MAR = newRegister(0x00, 0, AccessType.READ_WRITE);
        PSR = newRegister(0x04, ch, AccessType.READ_WRITE);
        TCR = newRegister(0x08, 0, AccessType.READ_WRITE);
        MARR = newRegister(0x0C, 0, AccessType.READ_WRITE);
        TCRR = newRegister(0x10, 0, AccessType.READ_WRITE);
        CR = newRegister(0x14, 0, AccessType.WRITE_ONLY);
        MR = newRegister(0x18, 0, AccessType.READ_WRITE);
        SR = newRegister(0x1C, 0, AccessType.READ_ONLY);
        IER = newRegister(0x20, 0, AccessType.WRITE_ONLY);
        IDR = newRegister(0x24, 0, AccessType.WRITE_ONLY);
        IMR = newRegister(0x28, 0, AccessType.READ_ONLY);
        ISR = newRegister(0x2C, 0, AccessType.READ_ONLY);
    }

    @Override
    protected void afterWrite(int ofs, int value) {
        switch (ofs) {
            case 0x08:
                pdca.serviceChannel(this);
                return;

            case 0x14:
                if ((CR.value >> 8 & 1) == 1) {
                    // Clear ISR.TERR
                    ISR.value &= ~(1 << 2);
                }
                if ((CR.value >> 1 & 1) == 1) {
                    // Transfer Disable
                    SR.value &= ~1;
                }
                if ((CR.value & 1) == 1) {
                    // Transfer Enable
                    SR.value |= 1;
                }
                pdca.serviceChannel(this);
                return;
        }
    }

    boolean isEnabled() {
        return (SR.value & 1) != 0;
    }

    DataSize getTransferSize() {
        switch (MR.value & 0b11) {
            case 0:
                return DataSize.BYTE_SIZE;
            case 1:
                return DataSize.HALFWORD_SIZE;
            case 2:
                return DataSize.WORD_SIZE;
            default:
                throw new IllegalArgumentException("MR.SIZE = 3 is reserved");
        }
    }
    
    void tryTransferData() {
        if (!isEnabled() || TCR.value <= 0) {
            println("tryTransferData called but PDCA not enabled");
            return;
        }
        println(String.format("tryTransferData called: MAR=0x%08X", MAR.value));
        while (
            (CR.value & 1) == 1
            && TCR.value > 0
        ) {
            DataSize size = getTransferSize();
            if (!pdca.transferData(MAR.value, PSR.value, size)) {
                return;
            }
            println(String.format("transferData done: MAR=0x%08X", MAR.value));
            MAR.value += size.numBytes();
            println(String.format("MAR incremented: MAR=0x%08X", MAR.value));
            TCR.value -= 1;
        }
    }
}
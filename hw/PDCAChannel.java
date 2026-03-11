package hw;

import etc.Util.DataSize;
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
                checkTransferData();
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
                checkTransferData();
                return;
        }
    }

    private void checkTransferData() {
        while (
            (CR.value & 1) == 1
            && TCR.value > 0
        ) {
            DataSize size;
            switch (MR.value & 0b11) {
                case 0:
                    size = DataSize.BYTE_SIZE;
                    break;
                case 1:
                    size = DataSize.HALFWORD_SIZE;
                    break;
                case 2:
                    size = DataSize.WORD_SIZE;
                    break;
                default:
                    throw new IllegalArgumentException("MR.SIZE = 3 is reserved");
            }
            pdca.transferData(MAR.value, PSR.value, size);
            MAR.value += size.numBytes();
            TCR.value -= 1;
        }
    }
}

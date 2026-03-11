package hw;

import hw.MmioDevice.Register;
import hw.MmioDevice.Register.AccessType;

public class CANIFChannel extends MmioRegion {

    Register CANRAMB, CANCFG, CANCTRL;
    Register CANSR, CANFC, CANIER, CANIDR;
    Register CANIMR, CANISCR, CANISR;
    Register MOBSCH, MOBER, MOBDR, MOBESR, MOBIER, MOBIDR, MOBIMR;
    Register MRXISCR, MRXISR, MTXISCR, MTXISR;
    Register[] MOBCTRL, MOBSCR, MOBSR;

    public final int ch;
    public final int mobn;

    public CANIFChannel(int ch, int baseOffset, CANIF canif, int mn) {
        super(canif, baseOffset, 0x200);
        this.ch = ch;
        this.mobn = mn;

        CANRAMB = newRegister(0x08, 0x0, AccessType.READ_WRITE);
        CANCFG = newRegister(0x0C, 0x1, AccessType.READ_WRITE);
        CANCTRL = newRegister(0x10, 0x0, AccessType.READ_WRITE);
        CANSR = newRegister(0x14, 0, AccessType.READ_ONLY);
        CANFC = newRegister(0x18, 0, AccessType.READ_ONLY);
        CANIER = newRegister(0x1C, 0, AccessType.READ_WRITE); // Temporary patch: keep readable
        CANIDR = newRegister(0x20, 0, AccessType.WRITE_ONLY);
        CANIMR = newRegister(0x24, 0, AccessType.READ_ONLY);
        CANISCR = newRegister(0x28, 0x00200000, AccessType.WRITE_ONLY);
        CANISR = newRegister(0x2C, 0x00200000, AccessType.READ_ONLY);
        MOBSCH = newRegister(0x30, 0x00202020, AccessType.READ_ONLY);
        MOBER = newRegister(0x34, 0, AccessType.WRITE_ONLY);
        MOBDR = newRegister(0x38, 0, AccessType.WRITE_ONLY);
        MOBESR = newRegister(0x3C, 0, AccessType.READ_ONLY);
        MOBIER = newRegister(0x40, 0, AccessType.WRITE_ONLY);
        MOBIDR = newRegister(0x44, 0, AccessType.WRITE_ONLY);
        MOBIMR = newRegister(0x48, 0, AccessType.READ_ONLY);
        MRXISCR = newRegister(0x4C, 0, AccessType.WRITE_ONLY);
        MRXISR = newRegister(0x50, 0, AccessType.READ_ONLY);
        MTXISCR = newRegister(0x54, 0, AccessType.WRITE_ONLY);
        MTXISR = newRegister(0x58, 0, AccessType.READ_ONLY);

        MOBCTRL = new Register[mn];
        MOBSCR  = new Register[mn];
        MOBSR   = new Register[mn];
        for (int i = 0; i < mn; i++) {
            int base = 0x5C + i * 0x0C;
            MOBCTRL[i] = newRegister(base + 0x00, 0, AccessType.READ_WRITE);
            MOBSCR[i] = newRegister(base + 0x04, 0, AccessType.WRITE_ONLY);
            MOBSR[i] = newRegister(base + 0x08, 0, AccessType.READ_ONLY);
        }
    }
}

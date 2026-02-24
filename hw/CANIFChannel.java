package hw;

public class CANIFChannel {

    int CANRAMB, CANCFG, CANCTRL;
    int CANSR, CANFC, CANIER, CANIDR;
    int CANIMR, CANISCR, CANISR;
    int MOBSCH, MOBER, MOBDR, MOBESR, MOBIER, MOBIDR, MOBIMR;
    int MRXISCR, MRXISR, MTXISCR, MTXISR;
    int[] MOBCTRL, MOBSCR, MOBSR;

    public final int ch;
    CANIF canif;
    public final int mobn;

    public CANIFChannel(int ch, CANIF canif, int mn) {
        this.ch = ch;
        this.canif = canif;
        this.mobn = mn;

        CANRAMB = 0x0;
        CANCFG = 0x1;
        CANCTRL = 0x0;
        CANSR = 0;
        CANFC = 0;

        CANIER = 0;
        CANIDR = 0;

        CANIMR = 0;
        CANISCR = 0x00200000;
        CANISR  = 0x00200000;

        MOBSCH = 0x00202020;
        MOBER = 0;
        MOBDR = 0;
        MOBESR = 0;

        MOBIER = 0;
        MOBIDR = 0;
        MOBIMR = 0;

        MRXISCR = 0;
        MRXISR = 0;
        MTXISCR = 0;
        MTXISR = 0;

        MOBCTRL = new int[mn];
        MOBSCR  = new int[mn];
        MOBSR   = new int[mn];
    }

    // Called only by CANIF
    public boolean onWrite(int ofs, int v) {

        switch (ofs) {
            // RO region
            case 0x14: case 0x18: case 0x24: case 0x2C:
            case 0x3C: case 0x48: case 0x50: case 0x58:
            case 0x64: return false;

            // RW
            case 0x08: CANRAMB = v; return true;
            case 0x0C: CANCFG = v; return true;
            case 0x10: CANCTRL = v; return true;

            // WO
            case 0x1C: CANIER = v; return true;
            case 0x20: CANIDR = v; return true;

            case 0x28: CANISCR = v; return true;
            case 0x34: MOBER = v; return true;
            case 0x38: MOBDR = v; return true;
            case 0x40: MOBIER = v; return true;
            case 0x44: MOBIDR = v; return true;
            case 0x4C: MRXISCR = v; return true;
            case 0x54: MTXISCR = v; return true;
        }

        // MOb area
        int mob = (ofs - 0x5C) / 0xc;
        int mof = (ofs - 0x5C) % 0xc;
        if (mob < mobn) {
            switch (mof) {
                case 0x00: MOBCTRL[mob] = v; return true;
                case 0x04: MOBSCR[mob] = v; return true;
                case 0x08: return false;
            }
        }

        return false;
    }

    public Integer onRead(int ofs) {

        switch (ofs) {
            case 0x08: return CANRAMB;
            case 0x0C: return CANCFG;
            case 0x10: return CANCTRL;
            case 0x14: return CANSR;
            case 0x18: return CANFC;
            
            // Temporary patch
            case 0x1C: return CANIER;

            case 0x24: return CANIMR;
            case 0x2C: return CANISR;

            case 0x30: return MOBSCH;
            case 0x3C: return MOBESR;

            case 0x48: return MOBIMR;

            case 0x50: return MRXISR;
            case 0x58: return MTXISR;
        }

        // MOb area
        int mob = (ofs - 0x5C) / 0xc;
        int mof = (ofs - 0x5C) % 0xc;
        if (mob < mobn) {
            switch (mof) {
                case 0x00: return MOBCTRL[mob];
                case 0x04: return null;
                case 0x08: return MOBSR[mob];
            }
        }

        return null;
    }
}

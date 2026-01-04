package peripheral;

public class GPIOPort {

    public final int port;

    // Registers
    int GPER, GPERS, GPERC, GPERT;

    int PMR0, PMR0S, PMR0C, PMR0T;
    int PMR1, PMR1S, PMR1C, PMR1T;
    int PMR2, PMR2S, PMR2C, PMR2T;

    int ODER, ODERS, ODERC, ODERT;
    int OVR, OVRS, OVRC, OVRT;

    int PVR;

    int PUER, PUERS, PUERC, PUERT;
    int PDER, PDERS, PDERC, PDERT;

    int IER, IERS, IERC, IERT;
    int IMR0, IMR0S, IMR0C, IMR0T;
    int IMR1, IMR1S, IMR1C, IMR1T;

    int GFER, GFERS, GFERC, GFERT;
    int IFR, IFRC;

    int ODCR0, ODCR0S, ODCR0C, ODCR0T;
    int ODCR1, ODCR1S, ODCR1C, ODCR1T;

    int LOCK, LOCKS, LOCKC, LOCKT;
    int UNLOCK;

    int ASR, PARAMETER, VERSION;


    public GPIOPort(int port) {
        this.port = port;
        resetRegisters();
    }

    private void resetRegisters() {

        switch (port) {

            case 0:
                GPER = 0x3FF9FFFF;
                PMR0 = 0x00000001;
                PMR1 = PMR2 = 0;
                ODER = OVR = 0;
                PUER = 0x00000001;
                PDER = 0;
                IER = IMR0 = IMR1 = IFR = 0;
                GFER = 0x3FF9FFFF;
                ODCR0 = 0;
                LOCK = 0;
                PARAMETER = 0x3FF9FFFF;
                VERSION = 0x00000212;
                break;

            case 1:
                GPER = 0xFFFFFFFF;
                PMR0 = 0x00000002;
                PMR1 = PMR2 = 0;
                ODER = OVR = 0;
                PUER = PDER = 0;
                IER = IMR0 = IMR1 = IFR = 0;
                GFER = 0xFFFFFFFF;
                ODCR0 = 0;
                LOCK = 0;
                PARAMETER = 0x3FFFFFFF;
                VERSION = 0x00000212;
                break;

            case 2:
                GPER = 0xFFFFFFFF;
                PMR0 = PMR1 = PMR2 = 0;
                ODER = OVR = 0;
                PUER = PDER = 0;
                IER = IMR0 = IMR1 = IFR = 0;
                GFER = 0xFFFFFFFF;
                ODCR0 = 0;
                LOCK = 0;
                PARAMETER = 0xFFFFFFFF;
                VERSION = 0x00000212;
                break;

            case 3:
                GPER = 0x7FFFFFFF;
                PMR0 = PMR1 = PMR2 = 0;
                ODER = OVR = 0;
                PUER = PDER = 0;
                IER = IMR0 = IMR1 = IFR = 0;
                GFER = 0x7FFFFFFF;
                ODCR0 = 0;
                LOCK = 0;
                PARAMETER = 0x7FFFFFFF;
                VERSION = 0x00000212;
                break;
        }
    }

    // --------------------------
    //    Register Read/Write
    // --------------------------

    public boolean writeReg(int ofs, int v) {
        switch (ofs) {

            case 0x000: GPER = v; return true;
            case 0x004: GPERS = v; return true;
            case 0x008: GPERC = v; return true;
            case 0x00C: GPERT = v; return true;

            case 0x010: PMR0 = v; return true;
            case 0x014: PMR0S = v; return true;
            case 0x018: PMR0C = v; return true;
            case 0x01C: PMR0T = v; return true;

            case 0x020: PMR1 = v; return true;
            case 0x024: PMR1S = v; return true;
            case 0x028: PMR1C = v; return true;
            case 0x02C: PMR1T = v; return true;

            case 0x030: PMR2 = v; return true;
            case 0x034: PMR2S = v; return true;
            case 0x038: PMR2C = v; return true;
            case 0x03C: PMR2T = v; return true;

            case 0x040: ODER = v; return true;
            case 0x044: ODERS = v; return true;
            case 0x048: ODERC = v; return true;
            case 0x04C: ODERT = v; return true;

            case 0x050: OVR = v; return true;
            case 0x054: OVRS = v; return true;
            case 0x058: OVRC = v; return true;
            case 0x05C: OVRT = v; return true;

            case 0x060: return false; // PVR is RO

            case 0x070: PUER = v; return true;
            case 0x074: PUERS = v; return true;
            case 0x078: PUERC = v; return true;
            case 0x07C: PUERT = v; return true;

            case 0x080: PDER = v; return true;
            case 0x084: PDERS = v; return true;
            case 0x088: PDERC = v; return true;
            case 0x08C: PDERT = v; return true;

            case 0x090: IER = v; return true;
            case 0x094: IERS = v; return true;
            case 0x098: IERC = v; return true;
            case 0x09C: IERT = v; return true;

            case 0x0A0: IMR0 = v; return true;
            case 0x0A4: IMR0S = v; return true;
            case 0x0A8: IMR0C = v; return true;
            case 0x0AC: IMR0T = v; return true;

            case 0x0B0: IMR1 = v; return true;
            case 0x0B4: IMR1S = v; return true;
            case 0x0B8: IMR1C = v; return true;
            case 0x0BC: IMR1T = v; return true;

            case 0x0C0: GFER = v; return true;
            case 0x0C4: GFERS = v; return true;
            case 0x0C8: GFERC = v; return true;
            case 0x0CC: GFERT = v; return true;

            case 0x0D0: return false;
            case 0x0D8: IFRC = v; return true;
            case 0x0DC: return false;

            case 0x100: ODCR0 = v; return true;
            case 0x104: ODCR0S = v; return true;
            case 0x108: ODCR0C = v; return true;
            case 0x10C: ODCR0T = v; return true;

            case 0x110: ODCR1 = v; return true;
            case 0x114: ODCR1S = v; return true;
            case 0x118: ODCR1C = v; return true;
            case 0x11C: ODCR1T = v; return true;

            case 0x1A0: LOCK = v; return true;
            case 0x1A4: LOCKS = v; return true;
            case 0x1A8: LOCKC = v; return true;
            case 0x1AC: LOCKT = v; return true;

            case 0x1E0: UNLOCK = v; return true;

            case 0x1E4:
            case 0x1F8:
            case 0x1FC:
                return false;

            // Unsupported model-specific features
            case 0x0E8:
                return true;
        }
        return false;
    }

    public Integer readReg(int ofs) {

        switch (ofs) {

            case 0x000: return GPER;
            case 0x010: return PMR0;
            case 0x020: return PMR1;
            case 0x030: return PMR2;

            case 0x040: return ODER;
            case 0x050: return OVR;

            case 0x060: return PVR;

            case 0x070: return PUER;
            case 0x080: return PDER;

            case 0x090: return IER;
            case 0x0A0: return IMR0;
            case 0x0B0: return IMR1;

            case 0x0C0: return GFER;
            case 0x0D0: return IFR;

            case 0x100: return ODCR0;
            case 0x110: return ODCR1;

            case 0x1A0: return LOCK;
            case 0x1E4: return ASR;
            case 0x1F8: return PARAMETER;
            case 0x1FC: return VERSION;
        }

        return null;
    }
}

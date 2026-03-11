package hw;

import hw.MmioDevice.Register;
import hw.MmioDevice.Register.AccessType;

public class GPIOPort extends MmioRegion {

    public final int port;

    // Registers
    Register GPER, GPERS, GPERC, GPERT;
    Register PMR0, PMR0S, PMR0C, PMR0T;
    Register PMR1, PMR1S, PMR1C, PMR1T;
    Register PMR2, PMR2S, PMR2C, PMR2T;
    Register ODER, ODERS, ODERC, ODERT;
    Register OVR, OVRS, OVRC, OVRT;
    Register PVR;
    Register PUER, PUERS, PUERC, PUERT;
    Register PDER, PDERS, PDERC, PDERT;
    Register IER, IERS, IERC, IERT;
    Register IMR0, IMR0S, IMR0C, IMR0T;
    Register IMR1, IMR1S, IMR1C, IMR1T;
    Register GFER, GFERS, GFERC, GFERT;
    Register IFR, IFRC;
    Register ODCR0, ODCR0S, ODCR0C, ODCR0T;
    Register ODCR1, ODCR1S, ODCR1C, ODCR1T;
    Register LOCK, LOCKS, LOCKC, LOCKT;
    Register UNLOCK;
    Register ASR, PARAMETER, VERSION, UNSUPPORTED_E8;


    public GPIOPort(int port, int base, GPIO gpio) {
        super(gpio, base, 0x200);
        this.port = port;
        initRegisters();
        resetRegisters();
    }

    private void initRegisters() {
        GPER = newRegister(0x000, 0, AccessType.READ_WRITE);
        GPERS = newRegister(0x004, 0, AccessType.WRITE_ONLY);
        GPERC = newRegister(0x008, 0, AccessType.WRITE_ONLY);
        GPERT = newRegister(0x00C, 0, AccessType.WRITE_ONLY);

        PMR0 = newRegister(0x010, 0, AccessType.READ_WRITE);
        PMR0S = newRegister(0x014, 0, AccessType.WRITE_ONLY);
        PMR0C = newRegister(0x018, 0, AccessType.WRITE_ONLY);
        PMR0T = newRegister(0x01C, 0, AccessType.WRITE_ONLY);
        PMR1 = newRegister(0x020, 0, AccessType.READ_WRITE);
        PMR1S = newRegister(0x024, 0, AccessType.WRITE_ONLY);
        PMR1C = newRegister(0x028, 0, AccessType.WRITE_ONLY);
        PMR1T = newRegister(0x02C, 0, AccessType.WRITE_ONLY);
        PMR2 = newRegister(0x030, 0, AccessType.READ_WRITE);
        PMR2S = newRegister(0x034, 0, AccessType.WRITE_ONLY);
        PMR2C = newRegister(0x038, 0, AccessType.WRITE_ONLY);
        PMR2T = newRegister(0x03C, 0, AccessType.WRITE_ONLY);

        ODER = newRegister(0x040, 0, AccessType.READ_WRITE);
        ODERS = newRegister(0x044, 0, AccessType.WRITE_ONLY);
        ODERC = newRegister(0x048, 0, AccessType.WRITE_ONLY);
        ODERT = newRegister(0x04C, 0, AccessType.WRITE_ONLY);
        OVR = newRegister(0x050, 0, AccessType.READ_WRITE);
        OVRS = newRegister(0x054, 0, AccessType.WRITE_ONLY);
        OVRC = newRegister(0x058, 0, AccessType.WRITE_ONLY);
        OVRT = newRegister(0x05C, 0, AccessType.WRITE_ONLY);
        PVR = newRegister(0x060, 0, AccessType.READ_ONLY);

        PUER = newRegister(0x070, 0, AccessType.READ_WRITE);
        PUERS = newRegister(0x074, 0, AccessType.WRITE_ONLY);
        PUERC = newRegister(0x078, 0, AccessType.WRITE_ONLY);
        PUERT = newRegister(0x07C, 0, AccessType.WRITE_ONLY);
        PDER = newRegister(0x080, 0, AccessType.READ_WRITE);
        PDERS = newRegister(0x084, 0, AccessType.WRITE_ONLY);
        PDERC = newRegister(0x088, 0, AccessType.WRITE_ONLY);
        PDERT = newRegister(0x08C, 0, AccessType.WRITE_ONLY);

        IER = newRegister(0x090, 0, AccessType.READ_WRITE);
        IERS = newRegister(0x094, 0, AccessType.WRITE_ONLY);
        IERC = newRegister(0x098, 0, AccessType.WRITE_ONLY);
        IERT = newRegister(0x09C, 0, AccessType.WRITE_ONLY);
        IMR0 = newRegister(0x0A0, 0, AccessType.READ_WRITE);
        IMR0S = newRegister(0x0A4, 0, AccessType.WRITE_ONLY);
        IMR0C = newRegister(0x0A8, 0, AccessType.WRITE_ONLY);
        IMR0T = newRegister(0x0AC, 0, AccessType.WRITE_ONLY);
        IMR1 = newRegister(0x0B0, 0, AccessType.READ_WRITE);
        IMR1S = newRegister(0x0B4, 0, AccessType.WRITE_ONLY);
        IMR1C = newRegister(0x0B8, 0, AccessType.WRITE_ONLY);
        IMR1T = newRegister(0x0BC, 0, AccessType.WRITE_ONLY);

        GFER = newRegister(0x0C0, 0, AccessType.READ_WRITE);
        GFERS = newRegister(0x0C4, 0, AccessType.WRITE_ONLY);
        GFERC = newRegister(0x0C8, 0, AccessType.WRITE_ONLY);
        GFERT = newRegister(0x0CC, 0, AccessType.WRITE_ONLY);
        IFR = newRegister(0x0D0, 0, AccessType.READ_ONLY);
        IFRC = newRegister(0x0D8, 0, AccessType.WRITE_ONLY);

        UNSUPPORTED_E8 = newRegister(0x0E8, 0, AccessType.WRITE_ONLY);

        ODCR0 = newRegister(0x100, 0, AccessType.READ_WRITE);
        ODCR0S = newRegister(0x104, 0, AccessType.WRITE_ONLY);
        ODCR0C = newRegister(0x108, 0, AccessType.WRITE_ONLY);
        ODCR0T = newRegister(0x10C, 0, AccessType.WRITE_ONLY);
        ODCR1 = newRegister(0x110, 0, AccessType.READ_WRITE);
        ODCR1S = newRegister(0x114, 0, AccessType.WRITE_ONLY);
        ODCR1C = newRegister(0x118, 0, AccessType.WRITE_ONLY);
        ODCR1T = newRegister(0x11C, 0, AccessType.WRITE_ONLY);

        LOCK = newRegister(0x1A0, 0, AccessType.READ_WRITE);
        LOCKS = newRegister(0x1A4, 0, AccessType.WRITE_ONLY);
        LOCKC = newRegister(0x1A8, 0, AccessType.WRITE_ONLY);
        LOCKT = newRegister(0x1AC, 0, AccessType.WRITE_ONLY);
        UNLOCK = newRegister(0x1E0, 0, AccessType.WRITE_ONLY);
        ASR = newRegister(0x1E4, 0, AccessType.READ_ONLY);
        PARAMETER = newRegister(0x1F8, 0, AccessType.READ_ONLY);
        VERSION = newRegister(0x1FC, 0, AccessType.READ_ONLY);
    }

    private void resetRegisters() {
        GPER.value = GPERS.value = GPERC.value = GPERT.value = 0;
        PMR0.value = PMR0S.value = PMR0C.value = PMR0T.value = 0;
        PMR1.value = PMR1S.value = PMR1C.value = PMR1T.value = 0;
        PMR2.value = PMR2S.value = PMR2C.value = PMR2T.value = 0;
        ODER.value = ODERS.value = ODERC.value = ODERT.value = 0;
        OVR.value = OVRS.value = OVRC.value = OVRT.value = 0;
        PVR.value = 0;
        PUER.value = PUERS.value = PUERC.value = PUERT.value = 0;
        PDER.value = PDERS.value = PDERC.value = PDERT.value = 0;
        IER.value = IERS.value = IERC.value = IERT.value = 0;
        IMR0.value = IMR0S.value = IMR0C.value = IMR0T.value = 0;
        IMR1.value = IMR1S.value = IMR1C.value = IMR1T.value = 0;
        GFER.value = GFERS.value = GFERC.value = GFERT.value = 0;
        IFR.value = IFRC.value = 0;
        ODCR0.value = ODCR0S.value = ODCR0C.value = ODCR0T.value = 0;
        ODCR1.value = ODCR1S.value = ODCR1C.value = ODCR1T.value = 0;
        LOCK.value = LOCKS.value = LOCKC.value = LOCKT.value = 0;
        UNLOCK.value = 0;
        ASR.value = UNSUPPORTED_E8.value = 0;
        PARAMETER.value = 0;
        VERSION.value = 0;

        switch (port) {

            case 0:
                GPER.value = 0x3FF9FFFF;
                PMR0.value = 0x00000001;
                PUER.value = 0x00000001;
                GFER.value = 0x3FF9FFFF;
                PARAMETER.value = 0x3FF9FFFF;
                VERSION.value = 0x00000212;
                break;

            case 1:
                GPER.value = 0xFFFFFFFF;
                PMR0.value = 0x00000002;
                GFER.value = 0xFFFFFFFF;
                PARAMETER.value = 0x3FFFFFFF;
                VERSION.value = 0x00000212;
                break;

            case 2:
                GPER.value = 0xFFFFFFFF;
                GFER.value = 0xFFFFFFFF;
                PARAMETER.value = 0xFFFFFFFF;
                VERSION.value = 0x00000212;
                break;

            case 3:
                GPER.value = 0x7FFFFFFF;
                GFER.value = 0x7FFFFFFF;
                PARAMETER.value = 0x7FFFFFFF;
                VERSION.value = 0x00000212;
                break;
        }
    }
}

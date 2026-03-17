package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class HMATRIX extends MmioDevice {

    // MCFG0~MCFG15 (0x0000 ~ 0x003C)
    Register[] MCFG = new Register[16];

    // SCFG0~SCFG15 (0x0040 ~ 0x007C)
    Register[] SCFG = new Register[16];

    // PRAS0~PRAS15 (0x0080 ~ 0x00BC)
    Register[] PRAS = new Register[16];

    // PRBS0~PRBS15 (0x0084 ~ 0x00C0)
    Register[] PRBS = new Register[16];

    // SFR0~SFR15 (0x0110 ~ 0x014C)
    Register[] SFR = new Register[16];

    public HMATRIX(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);
        resetRegisters();
    }
    
    @Override
    public void link() {}

    private void resetRegisters() {

        // MCFG reset = 0x00000002
        for (int i = 0; i < 16; i++)
            MCFG[i] = newRegister(0x0000 + i * 4, 0x00000002, AccessType.READ_WRITE);

        // SCFG reset = 0x00000010
        for (int i = 0; i < 16; i++)
            SCFG[i] = newRegister(0x0040 + i * 4, 0x00000010, AccessType.READ_WRITE);

        // PRAS reset = 0
        for (int i = 0; i < 16; i++)
            PRAS[i] = newRegister(0x0080 + i * 8, 0, AccessType.READ_WRITE);

        // PRBS reset = 0
        for (int i = 0; i < 16; i++)
            PRBS[i] = newRegister(0x0084 + i * 8, 0, AccessType.READ_WRITE);

        // SFR reset = 0 (device specific)
        for (int i = 0; i < 16; i++)
            SFR[i] = newRegister(0x0110 + i * 4, 0, AccessType.READ_WRITE);
    }

}

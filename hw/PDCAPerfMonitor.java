package hw;

import hw.MmioDevice.Register;
import hw.MmioDevice.Register.AccessType;

public class PDCAPerfMonitor extends MmioRegion {

    Register PCONTROL;

    Register[] PRDATA = new Register[2];
    Register[] PRSTALL = new Register[2];
    Register[] PRLAT = new Register[2];
    Register[] PWDATA = new Register[2];
    Register[] PWSTALL = new Register[2];
    Register[] PWLAT = new Register[2];

    public PDCAPerfMonitor(PDCA pdca) {
        super(pdca, 0x800, 0x34);

        PCONTROL = newRegister(0x00, 0, AccessType.READ_WRITE);

        PRDATA[0] = newRegister(0x04, 0, AccessType.READ_ONLY);
        PRSTALL[0] = newRegister(0x08, 0, AccessType.READ_ONLY);
        PRLAT[0] = newRegister(0x0C, 0, AccessType.READ_ONLY);
        PWDATA[0] = newRegister(0x10, 0, AccessType.READ_ONLY);
        PWSTALL[0] = newRegister(0x14, 0, AccessType.READ_ONLY);
        PWLAT[0] = newRegister(0x18, 0, AccessType.READ_ONLY);

        PRDATA[1] = newRegister(0x1C, 0, AccessType.READ_ONLY);
        PRSTALL[1] = newRegister(0x20, 0, AccessType.READ_ONLY);
        PRLAT[1] = newRegister(0x24, 0, AccessType.READ_ONLY);
        PWDATA[1] = newRegister(0x28, 0, AccessType.READ_ONLY);
        PWSTALL[1] = newRegister(0x2C, 0, AccessType.READ_ONLY);
        PWLAT[1] = newRegister(0x30, 0, AccessType.READ_ONLY);
    }
}

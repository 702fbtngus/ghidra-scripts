package hw;

public class FLASHC extends MmioDevice {

    int FCR;        // 0x00 Read/Write
    int FCMD;       // 0x04 Read/Write
    int FSR;        // 0x08 Read/Write
    int PR;         // 0x0C Read-only
    int VR;         // 0x10 Read-only
    int FGPFRHI;    // 0x14 Read-only
    int FGPFRLO;    // 0x18 Read-only

    public FLASHC(long baseAddr, String name) {
        super(baseAddr, name);
        resetRegisters();
    }
    
    @Override
    protected void link() {}

    private void resetRegisters() {
        // RW registers reset to 0
        FCR = 0x00000000;
        FCMD = 0x00000000;

        // FSR reset value depends on lock bits → set to 0
        FSR = 0x00000000;

        // Device-specific → set to 0
        PR = 0;
        VR = 0;

        // Fuse registers: N/A → set to 0
        FGPFRHI = 0;
        FGPFRLO = 0;
    }

    @Override
    protected boolean onWrite(int ofs, int v) {

        switch (ofs) {
            case 0x00: FCR = v; return true;
            case 0x04: FCMD = v; return true;
            case 0x08: FSR = v; return true;

            // read-only registers
            case 0x0C:
            case 0x10:
            case 0x14:
            case 0x18:
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        switch (ofs) {
            case 0x00: return FCR;
            case 0x04: return FCMD;
            case 0x08: return FSR;

            case 0x0C: return PR;
            case 0x10: return VR;
            case 0x14: return FGPFRHI;
            case 0x18: return FGPFRLO;
        }

        return null;
    }
}

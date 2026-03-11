package hw;

import hw.MmioDevice.Register.AccessType;

public class CANIF extends MmioDevice {

    Register VERSION, PARAMETER;

    CANIFChannel[] channels;

    public CANIF(long baseAddr, String name, int group) {

        super(baseAddr, name, group);

        VERSION = newRegister(0x00, 0x10200110, AccessType.READ_ONLY);
        PARAMETER = newRegister(0x04, 0x00000010, AccessType.READ_ONLY);

        int chno = VERSION.value >> 20 & 0b111;
        int[] mnch = {
            VERSION.value >> 24 & 0x3f,
            PARAMETER.value & 0x3f,
            PARAMETER.value >> 8 & 0x3f,
            PARAMETER.value >> 16 & 0x3f,
            PARAMETER.value >> 24 & 0x3f,
        };

        channels = new CANIFChannel[chno];
        for (int i = 0; i < chno; i++) {
            channels[i] = new CANIFChannel(i, i * 0x200, this, mnch[i]);
            addRegion(channels[i]);
        }
    }

    @Override
    protected void link() {}
}

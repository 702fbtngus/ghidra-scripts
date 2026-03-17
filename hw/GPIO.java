package hw;

import helper.DeviceManager;

public class GPIO extends MmioDevice {

    private final GPIOPort[] ports = new GPIOPort[4];

    public GPIO(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group, 0x800l);   // 4 ports × 0x200

        ports[0] = new GPIOPort(0, 0x000, this);
        ports[1] = new GPIOPort(1, 0x200, this);
        ports[2] = new GPIOPort(2, 0x400, this);
        ports[3] = new GPIOPort(3, 0x600, this);
        for (GPIOPort port : ports) {
            addRegion(port);
        }
    }
    
    @Override
    public void link() {}
}

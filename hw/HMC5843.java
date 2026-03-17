package hw;

import helper.DeviceManager;

public class HMC5843 extends I2CDevice {

    public HMC5843(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
    }
    
    @Override
    public void link() {}

    @Override
    public boolean tx(byte b) {
        return true;
    }
}

package hw;

import helper.DeviceManager;

public class MPU3300 extends I2CDevice {

    public MPU3300(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
    }
    
    @Override
    public void link() {}

    @Override
    public boolean tx(byte b) {
        return true;
    }
}

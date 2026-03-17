package hw;

import helper.DeviceManager;

public class EPS extends I2CDevice {

    public EPS(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
    }
    
    @Override
    public void link() {}

    @Override
    public boolean tx(byte b) {
        return true;
    }
}

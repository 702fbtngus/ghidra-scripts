package hw;

import helper.DeviceManager;
import helper.Logger;

public abstract class Device {
    public final String name;
    public final DeviceManager deviceManager;

    public Device(DeviceManager deviceManager, String name) {
        this.deviceManager = deviceManager;
        this.name = name;
        deviceManager.register(this);
    }

    // ------------------------------
    // Subclass responsibility
    // ------------------------------
    public abstract void link();

    public void println(String msg) {
        deviceManager.setCurrentDeviceName(this.name);
        Logger.printlnGlobal(String.format("%s: %s", name, msg), 2);
        deviceManager.setCurrentDeviceName(null);
    }
}

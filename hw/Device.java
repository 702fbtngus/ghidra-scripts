package hw;

import helper.DeviceManager;

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
}

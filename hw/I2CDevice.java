package hw;

import helper.DeviceManager;

public abstract class I2CDevice extends Device {

    public enum I2CEvent {
        START_SEND,
        START_RECV,
        FINISH,
        NACK
    }

    // ------------------------------
    // 🔥 자동 등록되는 I2CDevice 전역 리스트
    // ------------------------------
    public final int addr;
    public byte[] response;
    public int respIndex;

    public I2CDevice(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name);
        this.addr = addr;
    }

    // ------------------------------
    // Subclass responsibility
    // ------------------------------
    public abstract boolean tx(byte value);

    public Byte rx() {
        return response[respIndex++];
    };

    public void onI2CEvent(I2CEvent event) {}
}

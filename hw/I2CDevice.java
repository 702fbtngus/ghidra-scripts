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
    protected int responseLength = -1;

    public I2CDevice(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name);
        this.addr = addr;
    }

    // ------------------------------
    // Subclass responsibility
    // ------------------------------
    public abstract boolean tx(byte value);

    public Byte rx() {
        if (respIndex < getResponseLimit()) {
            return response[respIndex++];
        }
        return (byte) 0xFF;
    }

    protected int getResponseLimit() {
        if (response == null) {
            return 0;
        }
        if (responseLength >= 0) {
            return Math.min(responseLength, response.length);
        }
        return response.length;
    }

    public void onI2CEvent(I2CEvent event) {}
}

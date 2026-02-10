package hw;

import etc.Util;

public abstract class I2CDevice extends Device {

    // ------------------------------
    // 🔥 자동 등록되는 I2CDevice 전역 리스트
    // ------------------------------
    public final int addr;

    public I2CDevice(String name, int addr) {
        super(name);
        this.addr = addr;

        // 🔥 생성되면 자동으로 registry에 등록
        Device.registry.add(this);
    }

    public static final I2CDevice findI2CDevice(int addr) {
        for (Device dv : Device.registry) {
            if (dv instanceof I2CDevice idv) {
                if (!(idv.addr == addr)) continue;
                Util.println("findI2CDevice " + Util.intToHex(addr) + ": " + idv.name);
                return idv;
            }
        }
        Util.println("findI2CDevice " + Util.intToHex(addr) + ": null");
        return null;
    }

    public static final Integer sendToI2CDevice(int addr, int value) {
        I2CDevice mdv = findI2CDevice(addr);
        if (mdv == null) return null;
        Util.println("Send to I2CDevice " + mdv.name + " @ " + Util.intToHex(addr), 2);
        if (!mdv.tx(value)) {
            Util.println(mdv.getClass().getSimpleName() +
                ": invalid tx value =0x" + Integer.toHexString(value));
            return null;
        }
        return 0;
    }

    public static final Integer recvFromI2CDevice(int addr) {
        I2CDevice mdv = findI2CDevice(addr);
        if (mdv == null) return null;
        Util.println("Recv from " + mdv.name + " @ " + Util.intToHex(addr), 2);
        Integer value = mdv.rx();
        if (value == null) {
            Util.println(mdv.getClass().getSimpleName() + ": invalid rx");
            return null;
        }
        return value;
    }

    // ------------------------------
    // Subclass responsibility
    // ------------------------------
    protected abstract boolean tx(int value);
    protected abstract Integer rx();
}

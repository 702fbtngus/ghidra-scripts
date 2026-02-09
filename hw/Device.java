package hw;

import java.util.ArrayList;
import java.util.List;

public abstract class Device {

    // ------------------------------
    // 🔥 자동 등록되는 Device 전역 리스트
    // ------------------------------
    public static final List<Device> registry = new ArrayList<>();
    public final String name;

    public Device(String name) {
        this.name = name;

        // 🔥 생성되면 자동으로 registry에 등록
        registry.add(this);
    }

    public static final void linkAllDevices() {
        for (Device dv : registry) {
            dv.link();
        }
    }

    public static final Device findDevice(String name) {
        for (Device dv : registry) {
            if (dv.name.equals(name)) {
                return dv;
            }
        }
        return null;
    }

    // ------------------------------
    // Subclass responsibility
    // ------------------------------
    protected abstract void link();
}

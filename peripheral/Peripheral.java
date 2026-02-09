package peripheral;

import java.util.ArrayList;
import java.util.List;
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.pcode.Varnode;

import etc.Util;

public abstract class Peripheral {

    // ------------------------------
    // 🔥 자동 등록되는 Peripheral 전역 리스트
    // ------------------------------
    public static final List<Peripheral> registry = new ArrayList<>();
    public static PcodeThread<byte[]> curThread;

    public final long base;
    public final String name;
    public final long size;

    public Peripheral(long base, String name, long size) {
        this.base = base;
        this.name = name;
        this.size = size;

        // 🔥 생성되면 자동으로 registry에 등록
        registry.add(this);
    }

    public Peripheral(long base, String name) {
        this(base, name, 0x400l);
    }

    public static final void linkAllPeripherals() {
        for (Peripheral peripheral : registry) {
            peripheral.link();
        }
    }

    public static final Peripheral findPeripheral(String name) {
        for (Peripheral peripheral : registry) {
            if (peripheral.name.equals(name)) {
                return peripheral;
            }
        }
        return null;
    }

    public static final Peripheral findPeriperal(long addr) {
        for (Peripheral p : Peripheral.registry) {
            if (!p.contains(addr)) continue;
            Util.println("findperipheral " + Util.intToHex(addr) + ": " + p.name);
            return p;
        }
        Util.println("findperipheral " + Util.intToHex(addr) + ": null");
        return null;
    }

    public static final Integer storeToPeripheralAddr(long addr, Varnode node) {
        Peripheral p = findPeriperal(addr);
        if (p == null) return null;
        int off = (int)(addr - p.base);
        Util.println("Store to " + p.name + " @ " + Util.intToHex(addr), 2);
        return p.store(off, node);
    }
    public static final Integer storeToPeripheralAddr(long addr, long src) {
        Peripheral p = findPeriperal(addr);
        if (p == null) return null;
        int off = (int)(addr - p.base);
        Util.println("Store to " + p.name + " @ " + Util.intToHex(addr), 2);
        return p.store(off, src);
    }
    public static final Integer storeToPeripheralAddr(long addr, long src, int size) {
        Peripheral p = findPeriperal(addr);
        if (p == null) return null;
        int off = (int)(addr - p.base);
        Util.println("Store to " + p.name + " @ " + Util.intToHex(addr), 2);
        return p.store(off, src, size);
    }
    
    public static final Integer loadFromPeripheralAddr(long addr, Varnode node) {
        Peripheral p = findPeriperal(addr);
        if (p == null) return null;
        int off = (int)(addr - p.base);
        Util.println("Load from " + p.name + " @ " + Util.intToHex(addr), 2);
        return p.load(off, node);
    }
    public static final Integer loadFromPeripheralAddr(long addr, long dest) {
        Peripheral p = findPeriperal(addr);
        if (p == null) return null;
        int off = (int)(addr - p.base);
        Util.println("Load from " + p.name + " @ " + Util.intToHex(addr), 2);
        return p.load(off, dest);
    }
    public static final Integer loadFromPeripheralAddr(long addr, long dest, int size) {
        Peripheral p = findPeriperal(addr);
        if (p == null) return null;
        int off = (int)(addr - p.base);
        Util.println("Load from " + p.name + " @ " + Util.intToHex(addr), 2);
        return p.load(off, dest, size);
    }
    
    // ------------------------------
    // Concrete store()
    // ------------------------------
    public final Integer write(int offset, int value) {
        Util.println("offset = " + String.format("%02x", offset) + ", value = " + String.format("%08x", value), 2);
        if (!onWrite(offset, value)) {
            Util.println(getClass().getSimpleName() +
                ": invalid write offset=0x" + Integer.toHexString(offset));
            return null;
        }
        return 0;
    }

    public final Integer store(int offset, long addr) {
        int value = Util.getVar(addr);
        return write(offset, value);
    }
    public final Integer store(int offset, long addr, int size) {
        int value = Util.getVar(addr);
        value >>>= (4 - size) * 8;
        return write(offset, value);
    }
    public final Integer store(int offset, Varnode node) {
        int value = Util.getVar(node);
        return write(offset, value);
    }

    // ------------------------------
    // Concrete load()
    // ------------------------------
    public final Integer read(int offset) {
        Integer value = onRead(offset);

        if (value == null) {
            Util.println(getClass().getSimpleName() +
            ": invalid read offset=0x" + Integer.toHexString(offset));
            return null;
        }
        
        Util.println("offset = " + String.format("%02x", offset) + ", value = " + String.format("%08x", value), 2);
        return value;
    }

    public final Integer load(int offset, long addr) {
        Integer value = read(offset);

        if (value == null) {
            return null;
        }
        Util.setVar(addr, value);
        return 0;
    }
    public final Integer load(int offset, long addr, int size) {
        Integer value = read(offset);

        if (value == null) {
            return null;
        }
        value >>>= (4 - size) * 8;
        Util.setVar(addr, value);
        return 0;
    }
    public final Integer load(int offset, Varnode node) {
        Integer value = read(offset);

        if (value == null) {
            return null;
        }
        Util.setVar(node, value);
        return 0;
    }

    // ------------------------------
    // Subclass responsibility
    // ------------------------------
    protected abstract void link();
    protected abstract boolean onWrite(int offset, int value);
    protected abstract Integer onRead(int offset);

    public boolean contains(long addr) {
        return addr >= base && addr < base + size;
    }
}

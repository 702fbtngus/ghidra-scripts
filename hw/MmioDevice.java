package hw;

import ghidra.program.model.pcode.Varnode;

import etc.Util;

public abstract class MmioDevice extends Device {

    // ------------------------------
    // 🔥 자동 등록되는 MmioDevice 전역 리스트
    // ------------------------------
    public final long base;
    public final long size;
    public final int group;

    public MmioDevice(long base, String name, int group, long size) {
        super(name);
        this.base = base;
        this.size = size;
        this.group = group;

        // 🔥 생성되면 자동으로 registry에 등록
        Device.registry.add(this);
    }

    public MmioDevice(long base, String name, int group) {
        this(base, name, group, 0x400l);
    }

    public MmioDevice(long base, String name) {
        this(base, name, -1, 0x400l);
    }

    public static final MmioDevice findMmioDevice(long addr) {
        for (Device dv : Device.registry) {
            if (dv instanceof MmioDevice mdv) {
                if (!mdv.contains(addr)) continue;
                Util.println("findMmioDevice " + Util.intToHex(addr) + ": " + mdv.name);
                return mdv;
            }
        }
        Util.println("findMmioDevice " + Util.intToHex(addr) + ": null");
        return null;
    }

    public static final Integer storeToMmioDeviceAddr(long addr, Varnode node) {
        MmioDevice mdv = findMmioDevice(addr);
        if (mdv == null) return null;
        int off = (int)(addr - mdv.base);
        Util.println("Store to " + mdv.name + " @ " + Util.intToHex(addr), 2);
        return mdv.store(off, node);
    }
    public static final Integer storeToMmioDeviceAddr(long addr, long src) {
        MmioDevice mdv = findMmioDevice(addr);
        if (mdv == null) return null;
        int off = (int)(addr - mdv.base);
        Util.println("Store to " + mdv.name + " @ " + Util.intToHex(addr), 2);
        return mdv.store(off, src);
    }
    public static final Integer storeToMmioDeviceAddr(long addr, long src, int size) {
        MmioDevice mdv = findMmioDevice(addr);
        if (mdv == null) return null;
        int off = (int)(addr - mdv.base);
        Util.println("Store to " + mdv.name + " @ " + Util.intToHex(addr), 2);
        return mdv.store(off, src, size);
    }
    
    public static final Integer loadFromMmioDeviceAddr(long addr, Varnode node) {
        MmioDevice mdv = findMmioDevice(addr);
        if (mdv == null) return null;
        int off = (int)(addr - mdv.base);
        Util.println("Load from " + mdv.name + " @ " + Util.intToHex(addr), 2);
        return mdv.load(off, node);
    }
    public static final Integer loadFromMmioDeviceAddr(long addr, long dest) {
        MmioDevice mdv = findMmioDevice(addr);
        if (mdv == null) return null;
        int off = (int)(addr - mdv.base);
        Util.println("Load from " + mdv.name + " @ " + Util.intToHex(addr), 2);
        return mdv.load(off, dest);
    }
    public static final Integer loadFromMmioDeviceAddr(long addr, long dest, int size) {
        MmioDevice mdv = findMmioDevice(addr);
        if (mdv == null) return null;
        int off = (int)(addr - mdv.base);
        Util.println("Load from " + mdv.name + " @ " + Util.intToHex(addr), 2);
        return mdv.load(off, dest, size);
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
    protected abstract boolean onWrite(int offset, int value);
    protected abstract Integer onRead(int offset);

    public boolean contains(long addr) {
        return addr >= base && addr < base + size;
    }
}

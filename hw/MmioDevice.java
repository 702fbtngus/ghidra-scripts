package hw;

import hw.MmioDevice.Register.AccessType;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import helper.DeviceManager;
import helper.ByteUtil.DataSize;
import helper.Logger;

public abstract class MmioDevice extends Device {

    // ------------------------------
    // 🔥 자동 등록되는 MmioDevice 전역 리스트
    // ------------------------------
    public final long base;
    public final long size;
    public final int group;
    public final Map<Integer, Register> registersByOffset;
    protected final List<MmioRegion> regions;
    // public final Map<String, Register> registersByName;

    public MmioDevice(DeviceManager deviceManager, long base, String name, int group, long size) {
        super(deviceManager, name);
        this.base = base;
        this.size = size;
        this.group = group;
        this.registersByOffset = new HashMap<>();
        this.regions = new ArrayList<>();
    }

    public MmioDevice(DeviceManager deviceManager, long base, String name, int group) {
        this(deviceManager, base, name, group, 0x400l);
    }

    public static class Register {
        // public String name;
        public int value;
        public int offset;
        public AccessType at;

        public enum AccessType {
            READ_ONLY,
            WRITE_ONLY,
            READ_WRITE,
        }

        public Register(int value, int offset, AccessType at) {
            // this.name = name;
            this.value = value;
            this.offset = offset;
            this.at = at;
        }
    }

    public Register newRegister(int offset, int value, Register.AccessType at) {
        Register reg = new Register(value, offset, at);
        this.registersByOffset.put(offset, reg);
        return reg;
        // this.registersByName.put(name, reg);
    }

    // ------------------------------
    // Concrete store()
    // ------------------------------
    public final Integer write(int offset, int value) {
        println(String.format("offset = %02x, value = %08x", offset, value));
        if (!onWrite(offset, value)) {
            println(getClass().getSimpleName() +
                ": invalid write offset=0x" + Integer.toHexString(offset));
            return null;
        }
        return 0;
    }

    public final Integer writeSized(int offset, int value, DataSize size) {
        println(String.format("offset = %02x, value = %08x", offset, value));
        int regOffset = offset & ~0x3;
        int lane = offset & 0x3;
        if (!((size == DataSize.BYTE_SIZE)
            || (size == DataSize.HALFWORD_SIZE && (lane == 0 || lane == 2))
            || (size == DataSize.WORD_SIZE && lane == 0))) {
            println(String.format(
                "%s: invalid write alignment offset=0x%X size=%s",
                getClass().getSimpleName(),
                offset,
                size
            ));
            return null;
        }

        // Can get value from write-only registers
        Register reg = registersByOffset.get(regOffset);
        if (reg == null) {
            println(getClass().getSimpleName() +
                ": invalid write offset=0x" + Integer.toHexString(regOffset));
            return null;
        }

        int mergedValue = mergeValue(reg.value, value, lane, size);
        if (!onWrite(regOffset, mergedValue)) {
            println(getClass().getSimpleName() +
                ": invalid write offset=0x" + Integer.toHexString(regOffset));
            return null;
        }
        return 0;
    }

    public final Integer store(int offset, long addr) {
        int value = deviceManager.cpuState.getVar(addr);
        return write(offset, value);
    }
    public final Integer store(int offset, long addr, DataSize size) {
        int value = deviceManager.cpuState.getVar(addr, size.numBytes());
        return writeSized(offset, value, size);
    }
    public final Integer store(int offset, Varnode node) {
        int value = deviceManager.cpuState.getVar(node);
        return write(offset, value);
    }

    // ------------------------------
    // Concrete load()
    // ------------------------------
    public final Integer read(int offset) {
        Integer value = onRead(offset);

        if (value == null) {
            println(getClass().getSimpleName() +
            ": invalid read offset=0x" + Integer.toHexString(offset));
            return null;
        }
        
        println(String.format("offset = %02x, value = %08x", offset, value));
        return value;
    }

    public final Integer readSized(int offset, DataSize size) {
        int regOffset = offset & ~0x3;
        int lane = offset & 0x3;
        if (!((size == DataSize.BYTE_SIZE)
            || (size == DataSize.HALFWORD_SIZE && (lane == 0 || lane == 2))
            || (size == DataSize.WORD_SIZE && lane == 0))) {
            println(String.format(
                "%s: invalid read alignment offset=0x%X size=%s",
                getClass().getSimpleName(),
                offset,
                size
            ));
            return null;
        }

        Integer value = onRead(regOffset);
        if (value == null) {
            println(getClass().getSimpleName() +
            ": invalid read offset=0x" + Integer.toHexString(regOffset));
            return null;
        }

        int narrowedValue = extractValue(value, lane, size);
        println(String.format("offset = %02x, value = %08x", offset, narrowedValue));
        return narrowedValue;
    }

    public final Integer load(int offset, long addr) {
        Integer value = read(offset);

        if (value == null) {
            return null;
        }
        deviceManager.cpuState.setVar(addr, value);
        return 0;
    }
    public final Integer load(int offset, long addr, DataSize size) {
        println(String.format("Load addr: 0x%08X", addr));
        Integer value = readSized(offset, size);
        println(String.format("Load value: 0x%X", value));
        
        if (value == null) {
            return null;
        }
        deviceManager.cpuState.setVar(addr, value, size.numBytes());
        return 0;
    }
    public final Integer load(int offset, Varnode node) {
        Integer value = read(offset);

        if (value == null) {
            return null;
        }
        deviceManager.cpuState.setVar(node, value);
        return 0;
    }
    public final Integer load(int offset, Varnode node, DataSize size) {
        Integer value = readSized(offset, size);

        if (value == null) {
            return null;
        }
        deviceManager.cpuState.setVar(node, value, size.numBytes());
        return 0;
    }

    // ------------------------------
    // Subclass responsibility
    // ------------------------------
    protected final void addRegion(MmioRegion region) {
        int regionStart = region.baseOffset;
        int regionEnd = region.baseOffset + region.size;

        if (regionStart < 0 || regionEnd > size || regionStart >= regionEnd) {
            throw new IllegalArgumentException(String.format(
                "%s: region out of bounds offset=0x%X size=0x%X",
                getClass().getSimpleName(),
                region.baseOffset,
                region.size
            ));
        }

        for (MmioRegion existing : regions) {
            int existingStart = existing.baseOffset;
            int existingEnd = existing.baseOffset + existing.size;
            if (regionStart < existingEnd && existingStart < regionEnd) {
                throw new IllegalArgumentException(String.format(
                    "%s: overlapping regions at 0x%X and 0x%X",
                    getClass().getSimpleName(),
                    region.baseOffset,
                    existing.baseOffset
                ));
            }
        }

        regions.add(region);
    }

    protected MmioRegion findRegion(int offset) {
        for (MmioRegion child : regions) {
            MmioRegion region = child.findRegion(offset);
            if (region != null) {
                return region;
            }
        }
        return null;
    }

    // protected abstract boolean onWrite(int offset, int value);
    protected boolean onWrite(int offset, int value) {
        Register r = registersByOffset.get(offset);
        if (r == null || r.at == AccessType.READ_ONLY) return false;

        r.value = value;
        MmioRegion region = findRegion(offset);
        if (region != null) {
            region.afterWrite(offset - region.baseOffset, value);
        }
        return true;
    }

    protected Integer onRead(int offset) {
        MmioRegion region = findRegion(offset);
        if (region != null) {
            region.beforeRead(offset - region.baseOffset);
        }
        Register r = registersByOffset.get(offset);
        if (r == null || r.at == AccessType.WRITE_ONLY) return null;

        return r.value;
    }

    public boolean contains(long addr) {
        return addr >= base && addr < base + size;
    }

    private int mergeValue(int currentValue, int incomingValue, int lane, DataSize size) {
        int shift = lane * Byte.SIZE;
        int mask = size.valueMask() << shift;
        int maskedIncoming = (incomingValue & size.valueMask()) << shift;
        return (currentValue & ~mask) | maskedIncoming;
    }

    private int extractValue(int value, int lane, DataSize size) {
        int shift = lane * Byte.SIZE;
        return (value >>> shift) & size.valueMask();
    }
}

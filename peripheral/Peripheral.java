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
        this.base = base;
        this.name = name;
        this.size = 0x400;

        // 🔥 생성되면 자동으로 registry에 등록
        registry.add(this);
    }

    // ------------------------------
    // Concrete store()
    // ------------------------------
    public final int store(int offset, Varnode node, PcodeThread<byte[]> thread) {
        int value = Util.byteArrayToInt(
            thread.getState().getVar(node,
                ghidra.pcode.exec.PcodeExecutorStatePiece.Reason.INSPECT));

        Util.println("offset = " + String.format("%02x", offset) + ", value = " + String.format("%08x", value), 2);
        if (!onWrite(offset, value)) {
            Util.println(getClass().getSimpleName() +
                ": invalid write offset=0x" + Integer.toHexString(offset));
            return -1;
        }
        return 0;
    }

    // ------------------------------
    // Concrete load()
    // ------------------------------
    public final int load(int offset, Varnode node, PcodeThread<byte[]> thread) {
        Integer value = onRead(offset);

        if (value == null) {
            value = 0;
            // Util.println.apply(getClass().getSimpleName() +
            //     ": invalid read offset=0x" + Integer.toHexString(offset));
            // return -1;
        }
        
        Util.println("offset = " + String.format("%02x", offset) + ", value = " + String.format("%08x", value), 2);
        thread.getState().setVar(node, Util.intToByteArray(value));
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

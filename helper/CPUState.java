package helper;

import java.util.function.BiConsumer;

import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

public final class CPUState {
    private final ProgramUtil programUtil;
    private final Context context;
    private final BiConsumer<String, Integer> logger;

    public CPUState(ProgramUtil programUtil, Context context, BiConsumer<String, Integer> logger) {
        this.programUtil = programUtil;
        this.context = context;
        this.logger = logger;
    }

    public enum RegisterName {
        SR   (0x0000L, 4),
        EVBA (0x0004L, 4),
        R0   (0x1000L, 4),
        C    (0x1100L, 1),
        Z    (0x1101L, 1),
        N    (0x1102L, 1),
        V    (0x1103L, 1),
        R1   (0x1004L, 4),
        R2   (0x1008L, 4),
        R3   (0x100CL, 4),
        R4   (0x1010L, 4),
        R5   (0x1014L, 4),
        R6   (0x1018L, 4),
        R7   (0x101CL, 4),
        R8   (0x1020L, 4),
        R9   (0x1024L, 4),
        R10  (0x1028L, 4),
        R11  (0x102CL, 4),
        R12  (0x1030L, 4),
        SP   (0x1034L, 4),
        LR   (0x1038L, 4),
        PC   (0x103CL, 4);

        private final long memoryAddress;
        private final int numBytes;

        RegisterName(long memoryAddress, int numBytes) {
            this.memoryAddress = memoryAddress;
            this.numBytes = numBytes;
        }

        public long memoryAddress() {
            return memoryAddress;
        }

        public int numBytes() {
            return numBytes;
        }

        public static RegisterName fromMnemonic(String mnemonic) {
            return RegisterName.valueOf(mnemonic);
        }
    }

    public int loadFromAddr(int addr) {
        int result = getVar(addr);
        logger.accept(String.format("[loadFromAddr] *0x%08X = %d (0x%08X)", addr, result, result), 5);
        return result;
    }

    public void storeToAddr(int addr, int value) {
        logger.accept(String.format("[storeToAddr] *0x%08X <- %d (0x%08X)", addr, value, value), 5);
        setVar(addr, value);
    }

    public Address toAddr(long addr) {
        return programUtil.toAddr(addr);
    }

    private ThreadPcodeExecutorState<byte[]> getState() {
        return context.currentThread.getState();
    }

    public int getVar(long addr) {
        return ByteUtil.byteArrayToInt(getState().getVar(toAddr(addr), 4, true, Reason.INSPECT));
    }

    public int getVar(long addr, int size) {
        return ByteUtil.byteArrayToInt(getState().getVar(toAddr(addr), size, true, Reason.INSPECT));
    }

    public int getVar(String addrSpace, long addr) {
        return getVar(addrSpace, addr, 4);
    }

    public int getVar(String addrSpace, long addr, int numbytes) {
        var regAddrSpace = programUtil.getAddressSpace(addrSpace);
        return ByteUtil.byteArrayToInt(getState().getVar(regAddrSpace, addr, numbytes, true, Reason.INSPECT));
    }

    public int getVar(Varnode node) {
        return ByteUtil.byteArrayToInt(getState().getVar(node, Reason.INSPECT));
    }

    public void setVar(long addr, int value, int size) {
        getState().setVar(toAddr(addr), size, true, ByteUtil.intToByteArray(value, size));
    }

    public void setVar(long addr, int value) {
        getState().setVar(toAddr(addr), 4, true, ByteUtil.intToByteArray(value));
    }

    public void setVar(String addrSpace, long addr, int value) {
        setVar(addrSpace, addr, 4, value);
    }

    public void setVar(String addrSpace, long addr, int numbytes, int value) {
        var regAddrSpace = programUtil.getAddressSpace(addrSpace);
        getState().setVar(regAddrSpace, addr, numbytes, true, ByteUtil.intToByteArray(value, numbytes));
    }

    public void setVar(Varnode node, int value) {
        getState().setVar(node, ByteUtil.intToByteArray(value, node.getSize()));
    }

    public void setVar(Varnode node, int value, int numbytes) {
        getState().setVar(node, ByteUtil.intToByteArray(value, numbytes));
    }

    public int getRegisterValue(String name) {
        RegisterName regname = RegisterName.fromMnemonic(name);
        return getVar("register", regname.memoryAddress(), regname.numBytes());
    }

    public int getRAMValue(int offset) {
        return getVar("RAM", offset);
    }
    public int getRAMValue(int offset, int numbytes) {
        return getVar("RAM", offset, numbytes);
    }

    public String getRAMValues(int offset, int numbytes) {
        var regAddrSpace = programUtil.getAddressSpace("RAM");
        return ByteUtil.byteArrayToHexString(getState().getVar(regAddrSpace, offset, numbytes, true, Reason.INSPECT));
    }

    public String readString(int offset) {
        StringBuilder s = new StringBuilder();
        while (true) {
            int c = getVar("RAM", offset, 1);
            if (c == 0) {
                break;
            }
            offset += 1;
            s.append((char) c);
        }
        return s.toString();
    }

    public void setCounter(int addr){
        context.currentThread.setCounter(programUtil.toAddr(addr));
    }

    public void finishFrame(){
        setCounter(getRegisterValue("PC"));
        context.currentFrame.finishAsBranch();
    }

    public void setRegisterValue(String name, int value) {
        RegisterName regname = RegisterName.fromMnemonic(name);
        setVar("register", regname.memoryAddress(), regname.numBytes(), value);
        if ("SR".equals(name)) {
            setRegisterValue("C", value >> 0 & 1);
            setRegisterValue("Z", value >> 1 & 1);
            setRegisterValue("N", value >> 2 & 1);
            setRegisterValue("V", value >> 3 & 1);
        }
    }

    public int nextInstructionAddr(int addr) {
        return (int) programUtil.getInstructionAfter(programUtil.toAddr(addr)).getAddress().getOffset();
    }
}

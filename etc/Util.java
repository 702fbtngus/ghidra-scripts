package etc;

import java.util.function.BiFunction;
import java.util.function.Function;

import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.ThreadPcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

public class Util {

    private static Function<String, Void> println;
    private static BiFunction<String, Integer, Void> println_alt;
    public static GhidraScript currentScript;
    public static PcodeThread<byte[]> currentThread;

    private Util() {
        // Util is a utility class
        throw new AssertionError("No instances");
    }

    public static void println(String s) {
        println.apply(s);
    }

    public static void println(String s, int i) {
        println_alt.apply(s, i);
    }

    public static void setFunctions(Function<String, Void> pln, BiFunction<String, Integer, Void> pln_alt) {
        println = pln;
        println_alt = pln_alt;
    }

    public static byte[] intToByteArray(int a, int size) {
        if (size < 1 || size > 4) {
            throw new IllegalArgumentException("size must be between 1 and 4");
        }
    
        // a를 표현하는 데 필요한 최소 바이트 수 계산
        int neededBytes = 0;
        int temp = a;
        do {
            neededBytes++;
            temp >>>= 8;
        } while (temp != 0);
    
        if (neededBytes > size) {
            throw new IllegalArgumentException(
                "Integer " + a + " does not fit in " + size + " bytes"
            );
        }
    
        byte[] result = new byte[size];
    
        // big endian으로 채우기
        for (int i = 0; i < neededBytes; i++) {
            result[size - 1 - i] = (byte) (a & 0xFF);
            a >>>= 8;
        }
    
        return result;
    }
    

    public static byte[] intToByteArray(int a) {
        return intToByteArray(a, 4);
        // return new byte[] {
        //     (byte) (a >> 24),
        //     (byte) (a >> 16),
        //     (byte) (a >> 8),
        //     (byte) a
        // };
    }

    public static int byteArrayToInt(byte[] b) {
        int result = 0;
        for (int i = 0; i < b.length; i++) {
            result |= (b[i] & 0xFF) << (8 * (3-i));
        }
        return result;
    }

    public static Address toAddr(long addr) {
        return currentScript.toAddr(addr);
    }

    public static ThreadPcodeExecutorState<byte[]> getState() {
        return currentThread.getState();
    }

    public static int getVar(long addr) {
        return byteArrayToInt(getState().getVar(toAddr(addr), 4, true, Reason.INSPECT));
    }
    public static int getVar(String addrSpace, long addr) {
        return getVar(addrSpace, addr, 4);
    }

    public static int getVar(String addrSpace, long addr, int numbytes) {
        var regAddrSpace = currentScript.getCurrentProgram().getAddressFactory().getAddressSpace(addrSpace);
        return byteArrayToInt(getState().getVar(regAddrSpace, addr, numbytes, true, Reason.INSPECT));
    }

    public static int getVar(Varnode node) {
        return byteArrayToInt(getState().getVar(node, Reason.INSPECT));
    }

    public static void setVar(long addr, int value) {
        getState().setVar(toAddr(addr), 4, true, intToByteArray(value));
    }

    public static void setVar(String addrSpace, long addr, int value) {
        setVar(addrSpace, addr, 4, value);
    }

    public static void setVar(String addrSpace, long addr, int numbytes, int value) {
        var regAddrSpace = currentScript.getCurrentProgram().getAddressFactory().getAddressSpace(addrSpace);
        getState().setVar(regAddrSpace, addr, numbytes, true, Util.intToByteArray(value, numbytes));
    }

    public static void setVar(Varnode node, int value) {
        getState().setVar(node, Util.intToByteArray(value, node.getSize()));
    }
}

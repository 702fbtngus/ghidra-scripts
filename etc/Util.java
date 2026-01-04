package etc;

import java.util.function.BiFunction;
import java.util.function.Function;

public class Util {

    private static Function<String, Void> println;
    private static BiFunction<String, Integer, Void> println_alt;

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

    public static byte[] intToByteArray(int a) {
        return new byte[] {
            (byte) (a >> 24),
            (byte) (a >> 16),
            (byte) (a >> 8),
            (byte) a
        };
    }

    public static byte[] intToByteArray(int a, int size) {
        if (size == 1) {
            return new byte[] {
                (byte) a
            };
        } else {
            return intToByteArray(a);
        }
    }

    public static int byteArrayToInt(byte[] b) {

        int result = 0;
        for (int i = 0; i < b.length; i++) {
            result |= (b[i] & 0xFF) << (8 * (3-i));
        }
        return result;
    }
}

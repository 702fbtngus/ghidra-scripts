package helper;

public final class ByteUtil {

    public enum Endianness {
        BIG_ENDIAN,
        LITTLE_ENDIAN,
    }

    public enum DataSize {
        BYTE_SIZE(1),
        HALFWORD_SIZE(2),
        WORD_SIZE(4);

        private final int numBytes;

        DataSize(int numBytes) {
            this.numBytes = numBytes;
        }

        public int numBytes() {
            return numBytes;
        }

        public int valueMask() {
            if (numBytes == Integer.BYTES) {
                return -1;
            }
            return (1 << (numBytes * 8)) - 1;
        }
    }

    private ByteUtil() {
        throw new AssertionError("No instances");
    }

    public static byte[] intToByteArray(int value) {
        return intToByteArray(value, 4);
    }

    public static byte[] intToByteArray(int value, int size) {
        return intToByteArray(value, size, Endianness.BIG_ENDIAN);
    }

    public static byte[] intToByteArray(int value, int size, Endianness endianness) {
        if (size < 1 || size > 4) {
            throw new IllegalArgumentException("size must be between 1 and 4");
        }

        int neededBytes = 0;
        int temp = value;
        do {
            neededBytes++;
            temp >>>= 8;
        } while (temp != 0);

        if (neededBytes > size) {
            throw new IllegalArgumentException(String.format(
                "Integer %d does not fit in %d bytes",
                value,
                size
            ));
        }

        byte[] result = new byte[size];
        switch (endianness) {
            case BIG_ENDIAN:
                for (int i = 0; i < neededBytes; i++) {
                    result[size - 1 - i] = (byte) (value & 0xFF);
                    value >>>= 8;
                }
                break;
            case LITTLE_ENDIAN:
                for (int i = 0; i < neededBytes; i++) {
                    result[i] = (byte) (value & 0xFF);
                    value >>>= 8;
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported endianness: " + endianness);
        }

        return result;
    }

    public static int byteArrayToInt(byte[] bytes) {
        return byteArrayToInt(bytes, Endianness.BIG_ENDIAN);
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        sb.append("]");
        return sb.toString();
    }

    public static int byteArrayToInt(byte[] bytes, Endianness endianness) {
        int result = 0;
        switch (endianness) {
            case BIG_ENDIAN:
                for (int i = 0; i < bytes.length; i++) {
                    result |= (bytes[i] & 0xFF) << (8 * (bytes.length - 1 - i));
                }
                break;
            case LITTLE_ENDIAN:
                for (int i = 0; i < bytes.length; i++) {
                    result |= (bytes[i] & 0xFF) << (8 * i);
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported endianness: " + endianness);
        }
        return result;
    }

    public static String intToHex(int addr) {
        return String.format("%08X", addr);
    }

    public static String longToHex(long addr) {
        return String.format("%08X", addr);
    }
}

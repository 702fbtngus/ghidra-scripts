package hw;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

import helper.DeviceManager;
import helper.ByteUtil;
import helper.ByteUtil.Endianness;

public class VRX extends I2CDevice {

    private static final int RF_QUEUE_SIZE = 100;
    private static final int VRX_MAX_PACKET_LENGTH = 200;

    private static final byte TRXUV_RESET_WATCHDOG = (byte) 0xCC;
    private static final byte TRXUV_RESET_SOFTWARE = (byte) 0xAA;
    private static final byte TRXUV_RESET_HARDWARE = (byte) 0xAB;
    private static final byte TRXUV_GET_UPTIME = 0x40;

    private static final byte VRX_GET_FRAMES = 0x21;
    private static final byte VRX_GET_FRAME = 0x22;
    private static final byte VRX_REMOVE_FRAME = 0x24;
    private static final byte VRX_GET_TELEMETRIES = 0x1A;

    private static final int GET_FRAME_DOPPLER_FREQ = 0xDEAD;
    private static final int GET_FRAME_SIGNAL_STRENGTH = 0xBEEF;
    private static final int TRXUV_UPTIME = 0xCAFEBABE;
    private static final int[] TELEMETRIES = {
        0x4141, 0x4242, 0x4343, 0x4444, 0x4545,
        0x4646, 0x4747, 0x4848, 0x4949
    };

    private final Deque<byte[]> packetQueue = new ArrayDeque<>();

    public VRX(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
        response = new byte[0];
        respIndex = 0;
    }
    
    @Override
    public void link() {}

    public void enqueueRadioPacket(byte[] packet) {
        if (packet == null) {
            throw new IllegalArgumentException("packet must not be null");
        }
        if (packetQueue.size() >= RF_QUEUE_SIZE) {
            return;
        }
        packetQueue.addLast(Arrays.copyOf(packet, packet.length));
    }

    @Override
    public boolean tx(byte value) {
        respIndex = 0;
        response = new byte[0];

        switch (value) {
            case VRX_GET_FRAMES:
                response = ByteUtil.intToByteArray(packetQueue.size(), 2, Endianness.LITTLE_ENDIAN);
                return true;
            case VRX_GET_FRAME:
                response = buildFrameResponse();
                return true;
            case VRX_REMOVE_FRAME:
                if (!packetQueue.isEmpty()) {
                    packetQueue.removeFirst();
                }
                return true;
            case VRX_GET_TELEMETRIES:
                response = buildTelemetryResponse();
                return true;
            case TRXUV_GET_UPTIME:
                response = ByteUtil.intToByteArray(TRXUV_UPTIME, 4, Endianness.LITTLE_ENDIAN);
                return true;
            case TRXUV_RESET_SOFTWARE:
            case TRXUV_RESET_HARDWARE:
            case TRXUV_RESET_WATCHDOG:
                return true;

            default:
                break;
        }
        return false;
    }

    @Override
    public Byte rx() {
        if (response == null || respIndex >= response.length) {
            return (byte) 0xFF;
        }
        return response[respIndex++];
    }

    private byte[] buildFrameResponse() {
        byte[] packet = packetQueue.peekFirst();
        int packetLength = packet == null ? 0 : Math.min(packet.length, VRX_MAX_PACKET_LENGTH);
        byte[] payload = new byte[6 + packetLength];

        System.arraycopy(ByteUtil.intToByteArray(packetLength, 2, Endianness.LITTLE_ENDIAN), 0, payload, 0, 2);
        System.arraycopy(ByteUtil.intToByteArray(GET_FRAME_DOPPLER_FREQ, 2, Endianness.LITTLE_ENDIAN), 0, payload, 2, 2);
        System.arraycopy(ByteUtil.intToByteArray(GET_FRAME_SIGNAL_STRENGTH, 2, Endianness.LITTLE_ENDIAN), 0, payload, 4, 2);
        if (packetLength > 0) {
            System.arraycopy(packet, 0, payload, 6, packetLength);
        }

        return payload;
    }

    private byte[] buildTelemetryResponse() {
        byte[] payload = new byte[TELEMETRIES.length * 2];
        for (int i = 0; i < TELEMETRIES.length; i++) {
            System.arraycopy(
                ByteUtil.intToByteArray(TELEMETRIES[i], 2, Endianness.LITTLE_ENDIAN),
                0,
                payload,
                i * 2,
                2
            );
        }
        return payload;
    }
}

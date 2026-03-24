package hw;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;

import helper.DeviceManager;
import helper.ByteUtil;
import helper.ByteUtil.Endianness;
import hw.I2CDevice.I2CEvent;

public class UTX extends I2CDevice {

    private static final int RF_QUEUE_SIZE = 100;
    private static final int UTX_MAX_PACKET_LENGTH = 235;
    private static final int CALLSIGN_LENGTH = 7;

    private static final byte TRXUV_RESET_WATCHDOG = (byte) 0xCC;
    private static final byte TRXUV_RESET_SOFTWARE = (byte) 0xAA;
    private static final byte TRXUV_RESET_HARDWARE = (byte) 0xAB;
    private static final byte TRXUV_GET_UPTIME = 0x40;

    private static final byte UTX_SEND_FRAME = 0x10;
    private static final byte UTX_SEND_FRAME_OVER = 0x11;
    private static final byte UTX_SET_BEACON = 0x14;
    private static final byte UTX_SET_BEACON_OVER = 0x15;
    private static final byte UTX_CLEAR_BEACON = 0x1F;
    private static final byte UTX_SET_TO_CALLSIGN = 0x22;
    private static final byte UTX_SET_FROM_CALLSIGN = 0x23;
    private static final byte UTX_SET_IDLE = 0x24;
    private static final byte UTX_GET_TELEMETRIES = 0x25;
    private static final byte UTX_GET_STORED_TM = 0x26;
    private static final byte UTX_SET_BITRATE = 0x28;
    private static final byte UTX_GET_STATE = 0x41;

    private static final int TRXUV_UPTIME = 0xCAFEBABE;
    private static final byte UTX_STATE = (byte) 0x99;
    private static final int[] TELEMETRIES = {
        0x4141, 0x4242, 0x4343, 0x4444, 0x4545,
        0x4646, 0x4747, 0x4848, 0x4949
    };

    private final Deque<byte[]> packetQueue = new ArrayDeque<>();
    private final byte[] beaconTxBuf = new byte[UTX_MAX_PACKET_LENGTH];
    private final byte[] toCallsign = new byte[CALLSIGN_LENGTH];
    private final byte[] fromCallsign = new byte[CALLSIGN_LENGTH];

    private byte lastCmd = (byte) -1;
    private int txLength = 0;
    private int beaconRepeatInterval = 0;
    private int beaconTxLen = 0;
    private byte idleData = 0;
    private byte bitrate = 0;

    private byte[] pendingPacket;
    private int pendingPacketLength = 0;
    private boolean pendingPacketActive = false;

    public UTX(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
        response = new byte[0];
        respIndex = 0;
    }

    @Override
    public void link() {}

    public byte[] dequeueOutgoingRadioPacket() {
        waitUntilFinalizePendingPacket();
        byte[] packet = packetQueue.pollFirst();
        if (packet == null) {
            return null;
        }
        return Arrays.copyOf(packet, packet.length);
    }

    @Override
    public boolean tx(byte value) {
        if (lastCmd == (byte) -1) {
            println("Received command byte: 0x" + String.format("%02X", value));
            return handleCommand(value);
        }
        
        println("Received payload byte: 0x" + String.format("%02X", value) + " for command 0x" + String.format("%02X", lastCmd));
        handlePayload(value);
        txLength++;
        return true;
    }

    @Override
    public void onI2CEvent(I2CEvent event) {
        switch (event) {
            case START_SEND:
                txLength = 0;
                break;
            case START_RECV:
                break;
            case FINISH:
                if (lastCmd == (byte) -1) {
                    return;
                }

                println("Completing transaction for command 0x" + String.format("%02X", lastCmd));
                if (lastCmd == UTX_SEND_FRAME || lastCmd == UTX_SEND_FRAME_OVER) {
                    finalizePendingPacket();
                }

                lastCmd = (byte) -1;
                txLength = 0;
                break;
            case NACK:
                lastCmd = (byte) -1;
                txLength = 0;
                pendingPacket = null;
                pendingPacketLength = 0;
                pendingPacketActive = false;
                break;
            default:
                break;
        }
    }

    private boolean handleCommand(byte command) {
        respIndex = 0;
        response = new byte[0];
        txLength = 1;
        lastCmd = command;

        switch (command) {
            case UTX_SEND_FRAME:
            case UTX_SEND_FRAME_OVER:
                response = new byte[] { remainingCapacityByte() };
                beginPendingPacket();
                return true;
            case UTX_SET_BEACON:
            case UTX_SET_BEACON_OVER:
            case UTX_SET_TO_CALLSIGN:
            case UTX_SET_FROM_CALLSIGN:
            case UTX_SET_IDLE:
            case UTX_SET_BITRATE:
                return true;
            case UTX_GET_STATE:
                response = new byte[] { UTX_STATE };
                lastCmd = (byte) -1;
                txLength = 0;
                return true;
            case UTX_GET_TELEMETRIES:
            case UTX_GET_STORED_TM:
                response = buildTelemetryResponse();
                lastCmd = (byte) -1;
                txLength = 0;
                return true;
            case TRXUV_GET_UPTIME:
                response = ByteUtil.intToByteArray(TRXUV_UPTIME, 4, Endianness.LITTLE_ENDIAN);
                lastCmd = (byte) -1;
                txLength = 0;
                return true;
            case UTX_CLEAR_BEACON:
                beaconTxLen = 0;
                lastCmd = (byte) -1;
                txLength = 0;
                return true;
            case TRXUV_RESET_SOFTWARE:
            case TRXUV_RESET_HARDWARE:
            case TRXUV_RESET_WATCHDOG:
                resetState();
                return true;
            default:
                lastCmd = (byte) -1;
                txLength = 0;
                return false;
        }
    }

    private void handlePayload(byte value) {
        int payloadIndex = txLength - 1;
        println("handlePayload: value=0x" + String.format("%02X", value) + ", payloadIndex=" + payloadIndex);

        switch (lastCmd) {
            case UTX_SEND_FRAME:
                appendPendingPacketByte(payloadIndex, value);
                break;
            case UTX_SEND_FRAME_OVER:
                if (payloadIndex < CALLSIGN_LENGTH) {
                    toCallsign[payloadIndex] = value;
                } else if (payloadIndex < CALLSIGN_LENGTH * 2) {
                    fromCallsign[payloadIndex - CALLSIGN_LENGTH] = value;
                } else {
                    appendPendingPacketByte(payloadIndex - (CALLSIGN_LENGTH * 2), value);
                }
                break;
            case UTX_SET_BEACON:
                if (payloadIndex < 2) {
                    writeBeaconRepeatIntervalByte(payloadIndex, value);
                } else {
                    writeBeaconPayloadByte(payloadIndex - 2, value);
                }
                break;
            case UTX_SET_BEACON_OVER:
                if (payloadIndex < 2) {
                    writeBeaconRepeatIntervalByte(payloadIndex, value);
                } else if (payloadIndex < 2 + CALLSIGN_LENGTH) {
                    toCallsign[payloadIndex - 2] = value;
                } else if (payloadIndex < 2 + (CALLSIGN_LENGTH * 2)) {
                    fromCallsign[payloadIndex - 2 - CALLSIGN_LENGTH] = value;
                } else {
                    writeBeaconPayloadByte(payloadIndex - 2 - (CALLSIGN_LENGTH * 2), value);
                }
                break;
            case UTX_SET_TO_CALLSIGN:
                if (payloadIndex < CALLSIGN_LENGTH) {
                    toCallsign[payloadIndex] = value;
                }
                break;
            case UTX_SET_FROM_CALLSIGN:
                if (payloadIndex < CALLSIGN_LENGTH) {
                    fromCallsign[payloadIndex] = value;
                }
                break;
            case UTX_SET_IDLE:
                if (payloadIndex == 0) {
                    idleData = value;
                }
                break;
            case UTX_SET_BITRATE:
                if (payloadIndex == 0) {
                    bitrate = value;
                }
                break;
            default:
                break;
        }
    }

    private void beginPendingPacket() {
        if (packetQueue.size() >= RF_QUEUE_SIZE) {
            pendingPacket = null;
            pendingPacketLength = 0;
            pendingPacketActive = false;
            return;
        }
        pendingPacket = new byte[UTX_MAX_PACKET_LENGTH];
        pendingPacketLength = 0;
        pendingPacketActive = true;
    }

    private void appendPendingPacketByte(int packetIndex, byte value) {
        if (!pendingPacketActive || pendingPacket == null) {
            println("Cannot append to pending packet: no active packet");
            return;
        }
        if (packetIndex < 0 || packetIndex >= UTX_MAX_PACKET_LENGTH) {
            println("Invalid packet index: " + packetIndex);
            return;
        }
        pendingPacket[packetIndex] = value;
        if (packetIndex + 1 > pendingPacketLength) {
            pendingPacketLength = packetIndex + 1;
        }
        println("pendingPacketLength: " + pendingPacketLength);
    }

    private void finalizePendingPacket() {
        if (!pendingPacketActive) {
            return;
        }
        if (pendingPacket != null && packetQueue.size() < RF_QUEUE_SIZE) {
            packetQueue.addLast(Arrays.copyOf(pendingPacket, pendingPacketLength));
        }
        pendingPacket = null;
        pendingPacketLength = 0;
        pendingPacketActive = false;
    }

    private void waitUntilFinalizePendingPacket() {
        while (pendingPacketActive) {
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void writeBeaconRepeatIntervalByte(int offset, byte value) {
        if (offset == 0) {
            beaconRepeatInterval = (beaconRepeatInterval & 0xFF00) | (value & 0xFF);
        } else if (offset == 1) {
            beaconRepeatInterval = (beaconRepeatInterval & 0x00FF) | ((value & 0xFF) << 8);
        }
    }

    private void writeBeaconPayloadByte(int offset, byte value) {
        if (offset < 0 || offset >= UTX_MAX_PACKET_LENGTH) {
            return;
        }
        beaconTxBuf[offset] = value;
        if (offset + 1 > beaconTxLen) {
            beaconTxLen = offset + 1;
        }
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

    private void resetState() {
        txLength = 0;
        beaconRepeatInterval = 0;
        Arrays.fill(beaconTxBuf, (byte) 0);
        beaconTxLen = 0;
        Arrays.fill(toCallsign, (byte) 0);
        Arrays.fill(fromCallsign, (byte) 0);
        idleData = 0;
        bitrate = 0;
        response = new byte[0];
        respIndex = 0;
        lastCmd = (byte) -1;
        pendingPacket = null;
        pendingPacketLength = 0;
        pendingPacketActive = false;
    }

    private byte remainingCapacityByte() {
        int remaining = RF_QUEUE_SIZE - packetQueue.size() - (pendingPacketActive ? 1 : 0) - 1;
        if (remaining < 0) {
            return 0;
        }
        return (byte) remaining;
    }
}

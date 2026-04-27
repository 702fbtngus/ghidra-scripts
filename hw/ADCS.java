package hw;

import java.util.Arrays;

import helper.DeviceManager;
import hw.I2CDevice.I2CEvent;

public class ADCS extends I2CDevice {

    private static final int MAX_TRANSFER_LENGTH = 0x100;
    private static final int TM_GET_IDENT = 0x80;
    private static final int TM_GET_IDENT_ALT = 0x84;
    private static final int TM_GET_CURRENT_TIME = 0x8C;
    private static final int TM_GET_TC_ACK = 0xF0;
    private static final int TM_GET_STATUS_A = 0x92;
    private static final int TM_GET_STATUS_B = 0x93;
    private static final int TM_GET_STATUS_C = 0xDA;
    private static final int TC_RESET = 0x01;
    private static final int TC_ENABLE_CACHE = 0x03;
    private static final int TC_RESET_BOOT_REGISTER = 0x06;
    private static final int TC_GET_ERROR = 0xE0;

    private final byte[] i2cData = new byte[MAX_TRANSFER_LENGTH];

    private int i2cLen;
    private int lastCmd;

    public ADCS(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
        response = new byte[MAX_TRANSFER_LENGTH];
        resetState();
    }

    @Override
    public void link() {}

    @Override
    public boolean tx(byte value) {
        if (i2cLen >= i2cData.length) {
            println(String.format("too long message (%d bytes)", i2cLen));
            return false;
        }

        int data = Byte.toUnsignedInt(value);
        i2cData[i2cLen++] = value;
        if (i2cLen == 1) {
            lastCmd = data;
            respIndex = 0;
            responseLength = 0;
            handleCommandStart(data);
            return true;
        }

        switch (lastCmd) {
            case TC_ENABLE_CACHE:
                // The firmware only sends a single configuration byte here.
                responseLength = 0;
                break;
            default:
                break;
        }

        return true;
    }

    @Override
    public void onI2CEvent(I2CEvent event) {
        switch (event) {
            case START_RECV:
                respIndex = 0;
                break;
            case START_SEND:
                lastCmd = -1;
                i2cLen = 0;
                break;
            case FINISH:
                lastCmd = -1;
                i2cLen = 0;
                println("Finished");
                break;
            case NACK:
            default:
                break;
        }
    }

    private void handleCommandStart(int command) {
        switch (command) {
            case TM_GET_IDENT:
                fillResponse(8, 0xFF);
                break;
            case TM_GET_IDENT_ALT:
            case TM_GET_CURRENT_TIME:
            case TM_GET_STATUS_A:
            case TM_GET_STATUS_B:
            case TM_GET_STATUS_C:
                fillResponse(6, 0xFF);
                break;
            case TC_GET_ERROR:
                fillResponse(3, 0xFF);
                break;
            case TM_GET_TC_ACK:
            case TC_RESET:
            case TC_ENABLE_CACHE:
            case TC_RESET_BOOT_REGISTER:
                responseLength = 0;
                break;
            default:
                responseLength = 0;
                break;
        }
    }

    private void fillResponse(int length, int value) {
        Arrays.fill(response, 0, length, (byte) value);
        responseLength = length;
    }

    private void resetState() {
        Arrays.fill(i2cData, (byte) 0);
        i2cLen = 0;
        lastCmd = -1;
        Arrays.fill(response, (byte) 0xFF);
        responseLength = 0;
        respIndex = 0;
    }
}

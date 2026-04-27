package hw;

import java.util.Arrays;

import helper.DeviceManager;
import hw.I2CDevice.I2CEvent;

public class EPS extends I2CDevice {

    private static final int MAX_TRANSFER_LENGTH = 0x100;

    private static final int GET_STATUS = 0x01;
    private static final int GET_LAST_ERR = 0x03;
    private static final int GET_VER = 0x04;
    private static final int GET_CHECKSUM = 0x05;
    private static final int GET_TELEMETRY = 0x10;
    private static final int GET_WATCHDOG_PERIOD = 0x20;
    private static final int GET_NUM_BOR = 0x31;
    private static final int GET_NUM_SW_RESET = 0x32;
    private static final int GET_NUM_MANUAL_RESET = 0x33;
    private static final int GET_NUM_WATCHDOG_RESET = 0x34;
    private static final int GET_PDM_ACTUAL_STATE = 0x42;
    private static final int GET_PDM_EXPECTED_STATE = 0x43;
    private static final int GET_PDM_INIT_STATE = 0x44;
    private static final int GET_PDM_N_ACTUAL_STATE = 0x54;
    private static final int GET_PDM_N_TIMER_LIMIT = 0x61;
    private static final int GET_PDM_N_TIMER_VALUE = 0x62;

    private static final int SET_WATCHDOG_PERIOD = 0x21;
    private static final int SET_WATCHDOG_PERIOD_RESET = 0x22;
    private static final int SET_ALL_PDM_ON = 0x40;
    private static final int SET_ALL_PDM_OFF = 0x41;
    private static final int SET_ALL_PDM_INIT = 0x45;
    private static final int SET_PDM_N_SWITCH_ON = 0x50;
    private static final int SET_PDM_N_SWITCH_OFF = 0x51;
    private static final int SET_PDM_N_INIT_STATE_ON = 0x52;
    private static final int SET_PDM_N_INIT_STATE_OFF = 0x53;
    private static final int SET_PDM_N_TIMER_LIMIT = 0x60;
    private static final int RESET_PCM = 0x70;
    private static final int RESET_MANUAL = 0x80;

    private int lastCmd;
    private int txLength;
    private int brownOutResetCount;
    private int softwareResetCount;
    private int manualResetCount;
    private int watchdogResetCount;
    private int watchdogPeriod;
    public EPS(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
        response = new byte[MAX_TRANSFER_LENGTH];
        resetState();
    }

    @Override
    public void link() {}

    @Override
    public boolean tx(byte value) {
        int data = Byte.toUnsignedInt(value);

        if (txLength == 0) {
            lastCmd = data;
            respIndex = 0;
            responseLength = 0;
            if (!isSupportedCommand(data)) {
                lastCmd = -1;
            }
        } else {
            handleDataByte(data);
        }

        txLength++;
        return true;
    }

    @Override
    public void onI2CEvent(I2CEvent event) {
        switch (event) {
            case START_RECV:
                break;
            case START_SEND:
                txLength = 0;
                break;
            case FINISH:
                lastCmd = -1;
                break;
            case NACK:
            default:
                break;
        }
    }

    private boolean isSupportedCommand(int command) {
        switch (command) {
            case GET_STATUS:
            case GET_LAST_ERR:
            case GET_VER:
            case GET_CHECKSUM:
            case GET_TELEMETRY:
            case GET_WATCHDOG_PERIOD:
            case GET_NUM_BOR:
            case GET_NUM_SW_RESET:
            case GET_NUM_MANUAL_RESET:
            case GET_NUM_WATCHDOG_RESET:
            case GET_PDM_ACTUAL_STATE:
            case GET_PDM_EXPECTED_STATE:
            case GET_PDM_INIT_STATE:
            case GET_PDM_N_ACTUAL_STATE:
            case GET_PDM_N_TIMER_LIMIT:
            case GET_PDM_N_TIMER_VALUE:
            case SET_WATCHDOG_PERIOD:
            case SET_WATCHDOG_PERIOD_RESET:
            case SET_ALL_PDM_ON:
            case SET_ALL_PDM_OFF:
            case SET_ALL_PDM_INIT:
            case SET_PDM_N_SWITCH_ON:
            case SET_PDM_N_SWITCH_OFF:
            case SET_PDM_N_INIT_STATE_ON:
            case SET_PDM_N_INIT_STATE_OFF:
            case SET_PDM_N_TIMER_LIMIT:
            case RESET_PCM:
            case RESET_MANUAL:
                return true;
            default:
                return false;
        }
    }

    private void handleDataByte(int data) {
        switch (lastCmd) {
            case GET_STATUS:
                if (txLength == 1) {
                    writeLe16(0xAAAA);
                }
                break;
            case GET_LAST_ERR:
                if (txLength == 1) {
                    writeLe16(0xBBBB);
                }
                break;
            case GET_VER:
                if (txLength == 1) {
                    writeLe16(0xCCCC);
                }
                break;
            case GET_CHECKSUM:
                if (txLength == 1) {
                    writeLe16(0xDDDD);
                }
                break;
            case GET_TELEMETRY:
                if (txLength < 3) {
                    response[txLength - 1] = (byte) data;
                }
                if (txLength == 2) {
                    readLe16();
                    writeLe16(0x9999);
                }
                break;
            case GET_WATCHDOG_PERIOD:
                if (txLength == 1) {
                    writeLe16(watchdogPeriod);
                }
                break;
            case GET_NUM_BOR:
                if (txLength == 1) {
                    writeLe16(brownOutResetCount);
                }
                break;
            case GET_NUM_SW_RESET:
                if (txLength == 1) {
                    writeLe16(softwareResetCount);
                }
                break;
            case GET_NUM_MANUAL_RESET:
                if (txLength == 1) {
                    writeLe16(manualResetCount);
                }
                break;
            case GET_NUM_WATCHDOG_RESET:
                if (txLength == 1) {
                    writeLe16(watchdogResetCount);
                }
                break;
            case GET_PDM_ACTUAL_STATE:
                if (txLength == 1) {
                    writeLe32(0xCAFE0001);
                }
                break;
            case GET_PDM_EXPECTED_STATE:
                if (txLength == 1) {
                    writeLe32(0xCAFE0002);
                }
                break;
            case GET_PDM_INIT_STATE:
                if (txLength == 1) {
                    writeLe32(0xCAFE0003);
                }
                break;
            case GET_PDM_N_ACTUAL_STATE:
                if (txLength == 1) {
                    writeLe16(0xCA04);
                }
                break;
            case GET_PDM_N_TIMER_LIMIT:
                if (txLength == 1) {
                    writeLe16(0xCA05);
                }
                break;
            case GET_PDM_N_TIMER_VALUE:
                if (txLength == 1) {
                    writeLe16(0xCA06);
                }
                break;
            case SET_WATCHDOG_PERIOD:
                if (txLength == 1) {
                    watchdogPeriod = data;
                }
                break;
            case SET_WATCHDOG_PERIOD_RESET:
                if (txLength == 1) {
                    watchdogPeriod = 0;
                }
                break;
            case SET_ALL_PDM_ON:
            case SET_ALL_PDM_OFF:
            case SET_ALL_PDM_INIT:
            case SET_PDM_N_SWITCH_ON:
            case SET_PDM_N_SWITCH_OFF:
            case SET_PDM_N_INIT_STATE_ON:
            case SET_PDM_N_INIT_STATE_OFF:
            case RESET_PCM:
                break;
            case SET_PDM_N_TIMER_LIMIT:
                if (txLength == 1) {
                    break;
                } else if (txLength == 1) {
                    break;
                }
                break;
            case RESET_MANUAL:
                if (txLength == 1) {
                    manualResetCount++;
                }
                break;
            default:
                lastCmd = -1;
                break;
        }
    }

    private void writeLe16(int value) {
        response[0] = (byte) (value & 0xFF);
        response[1] = (byte) ((value >>> 8) & 0xFF);
        responseLength = 2;
    }

    private void writeLe32(int value) {
        response[0] = (byte) (value & 0xFF);
        response[1] = (byte) ((value >>> 8) & 0xFF);
        response[2] = (byte) ((value >>> 16) & 0xFF);
        response[3] = (byte) ((value >>> 24) & 0xFF);
        responseLength = 4;
    }

    private int readLe16() {
        return Byte.toUnsignedInt(response[0]) | (Byte.toUnsignedInt(response[1]) << 8);
    }

    private void resetState() {
        lastCmd = -1;
        txLength = 0;
        brownOutResetCount = 0;
        softwareResetCount = 0;
        manualResetCount = 0;
        watchdogResetCount = 0;
        watchdogPeriod = 0;
        Arrays.fill(response, (byte) 0);
        responseLength = 0;
        respIndex = 0;
    }
}

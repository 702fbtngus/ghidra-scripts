package hw;

import java.util.Arrays;

import helper.DeviceManager;
import hw.I2CDevice.I2CEvent;

public class HSTX extends I2CDevice {

    private static final int HSTX_CONTROL = 0x00;
    private static final int HSTX_ENCODER = 0x01;
    private static final int HSTX_PA_POWER = 0x03;
    private static final int HSTX_SYNTH_OFFSET = 0x04;
    private static final int HSTX_RESET_REGISTER = 0x05;

    private static final int HSTX_FIRMWARE_VERSION = 0x11;
    private static final int HSTX_STATUS = 0x12;
    private static final int HSTX_READY_REGISTER = 0x13;
    private static final int HSTX_BUFF_UNDERRUN1 = 0x14;
    private static final int HSTX_BUFF_UNDERRUN2 = 0x15;
    private static final int HSTX_BUFF_OVERRUN1 = 0x16;
    private static final int HSTX_BUFF_OVERRUN2 = 0x17;
    private static final int HSTX_BUFF_COUNT1 = 0x18;
    private static final int HSTX_BUFF_COUNT2 = 0x19;
    private static final int HSTX_RF_POWER1 = 0x1A;
    private static final int HSTX_RF_POWER2 = 0x1B;
    private static final int HSTX_PA_TEMP1 = 0x1C;
    private static final int HSTX_PA_TEMP2 = 0x1D;
    private static final int HSTX_BOARD_TOPTEMP1 = 0x1E;
    private static final int HSTX_BOARD_TOPTEMP2 = 0x1F;
    private static final int HSTX_BOARD_BOTTEMP1 = 0x20;
    private static final int HSTX_BOARD_BOTTEMP2 = 0x21;
    private static final int HSTX_BAT_CURRENT1 = 0x22;
    private static final int HSTX_BAT_CURRENT2 = 0x23;
    private static final int HSTX_BAT_VOLTAGE1 = 0x24;
    private static final int HSTX_BAT_VOLTAGE2 = 0x25;
    private static final int HSTX_PA_CURRENT1 = 0x26;
    private static final int HSTX_PA_CURRENT2 = 0x27;
    private static final int HSTX_PA_VOLTAGE1 = 0x28;
    private static final int HSTX_PA_VOLTAGE2 = 0x29;

    private static final int HSTX_CONTROL_PA_MASK = 0x80;
    private static final int HSTX_CONTROL_MODE_MASK = 0x03;

    private static final int HSTX_DISABLE_PA = 0x00;
    private static final int HSTX_ENABLE_PA = 0x01;
    private static final int HSTX_MODE_CONFIG = 0x00;
    private static final int HSTX_MODE_SYNC = 0x01;
    private static final int HSTX_MODE_DATA = 0x02;
    private static final int HSTX_MODE_TESTDATA = 0x03;

    private static final int MAX_TRANSFER_LENGTH = 0x100;

    private final byte[] i2cData = new byte[MAX_TRANSFER_LENGTH];

    private int currCmd;
    private int i2cLen;
    private int controlRegister;
    private int encoderDataRate;
    private int encoderModulation;
    private int encoderFilter;
    private int encoderScrambler;
    private int encoderOrder;
    private int paPower;
    private int synthOffset;

    public HSTX(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
        response = new byte[MAX_TRANSFER_LENGTH];
        resetState();
    }

    @Override
    public void link() {}

    @Override
    public boolean tx(byte value) {
        int unsignedValue = Byte.toUnsignedInt(value);

        if (currCmd == -1) {
            startCommand(unsignedValue);
        } else {
            if (i2cLen >= i2cData.length) {
                println(String.format("too long message (%d bytes)", i2cLen));
                return true;
            }
            i2cData[i2cLen++] = value;
        }

        boolean done = false;
        switch (currCmd) {
            case HSTX_CONTROL:
                done = handleControlCommand();
                break;
            case HSTX_FIRMWARE_VERSION:
                done = handleReadOnlyCommand(0xAA);
                break;
            case HSTX_STATUS:
                done = handleReadOnlyCommand(0xAB);
                break;
            case HSTX_READY_REGISTER:
                done = handleReadOnlyCommand(0xAC);
                break;
            case HSTX_BUFF_UNDERRUN1:
                done = handleReadOnlyCommand(0xAD);
                break;
            case HSTX_BUFF_UNDERRUN2:
                done = handleReadOnlyCommand(0xAE);
                break;
            case HSTX_BUFF_OVERRUN1:
                done = handleReadOnlyCommand(0xAF);
                break;
            case HSTX_BUFF_OVERRUN2:
                done = handleReadOnlyCommand(0xBA);
                break;
            case HSTX_BUFF_COUNT1:
                done = handleReadOnlyCommand(0xBB);
                break;
            case HSTX_BUFF_COUNT2:
                done = handleReadOnlyCommand(0xBC);
                break;
            case HSTX_RF_POWER1:
                done = handleReadOnlyCommand(0xBD);
                break;
            case HSTX_RF_POWER2:
                done = handleReadOnlyCommand(0xBE);
                break;
            case HSTX_PA_TEMP1:
                done = handleReadOnlyCommand(0xBF);
                break;
            case HSTX_PA_TEMP2:
                done = handleReadOnlyCommand(0xCA);
                break;
            case HSTX_BOARD_TOPTEMP1:
                done = handleReadOnlyCommand(0xCB);
                break;
            case HSTX_BOARD_TOPTEMP2:
                done = handleReadOnlyCommand(0xCC);
                break;
            case HSTX_BOARD_BOTTEMP1:
                done = handleReadOnlyCommand(0xCD);
                break;
            case HSTX_BOARD_BOTTEMP2:
                done = handleReadOnlyCommand(0xCE);
                break;
            case HSTX_BAT_CURRENT1:
                done = handleReadOnlyCommand(0xCF);
                break;
            case HSTX_BAT_CURRENT2:
                done = handleReadOnlyCommand(0xDA);
                break;
            case HSTX_BAT_VOLTAGE1:
                done = handleReadOnlyCommand(0xDB);
                break;
            case HSTX_BAT_VOLTAGE2:
                done = handleReadOnlyCommand(0xDC);
                break;
            case HSTX_PA_CURRENT1:
                done = handleReadOnlyCommand(0xDD);
                break;
            case HSTX_PA_CURRENT2:
                done = handleReadOnlyCommand(0xDE);
                break;
            case HSTX_PA_VOLTAGE1:
                done = handleReadOnlyCommand(0xDF);
                break;
            case HSTX_PA_VOLTAGE2:
                done = handleReadOnlyCommand(0xEA);
                break;
            case HSTX_ENCODER:
                if (i2cLen == 1) {
                    int input = Byte.toUnsignedInt(i2cData[0]);
                    encoderDataRate = input & 0x03;
                    encoderModulation = (input >> 2) & 0x01;
                    encoderFilter = (input >> 3) & 0x01;
                    encoderScrambler = (input >> 4) & 0x01;
                    encoderOrder = (input >> 5) & 0x01;
                    paPower = input & 0x03;
                    done = true;
                }
                break;
            case HSTX_SYNTH_OFFSET:
                if (i2cLen == 1) {
                    synthOffset = Byte.toUnsignedInt(i2cData[0]);
                    done = true;
                }
                break;
            case HSTX_RESET_REGISTER:
                if (i2cLen == 1) {
                    resetRegisters();
                    done = true;
                }
                break;
            case HSTX_PA_POWER:
            default:
                break;
        }

        if (done) {
            currCmd = -1;
            i2cLen = 0;
        }

        return true;
    }

    @Override
    public Byte rx() {
        // CONTROL is a two-step transaction: write 0x00, then read the latched value.
        if (currCmd == HSTX_CONTROL) {
            currCmd = -1;
        }
        return super.rx();
    }

    @Override
    public void onI2CEvent(I2CEvent event) {
        switch (event) {
            case START_SEND:
            case START_RECV:
                i2cLen = 0;
                break;
            case FINISH:
                println("Finished");
                break;
            case NACK:
            default:
                break;
        }
    }

    private void startCommand(int command) {
        responseLength = 0;
        respIndex = 0;
        currCmd = command;
    }

    private boolean handleControlCommand() {
        if (i2cLen == 0) {
            response[0] = (byte) controlRegister;
            responseLength = 1;
            return false;
        }

        if (i2cLen != 1) {
            return false;
        }

        responseLength = 0;
        respIndex = 0;

        int paStatus = (controlRegister & HSTX_CONTROL_PA_MASK) >>> 7;
        int mode = controlRegister & HSTX_CONTROL_MODE_MASK;
        switch (Byte.toUnsignedInt(i2cData[0])) {
            case 0x00:
                paStatus = HSTX_DISABLE_PA;
                mode = HSTX_MODE_CONFIG;
                break;
            case 0x01:
                paStatus = HSTX_DISABLE_PA;
                mode = HSTX_MODE_SYNC;
                break;
            case 0x81:
                paStatus = HSTX_ENABLE_PA;
                mode = HSTX_MODE_SYNC;
                break;
            case 0x82:
                paStatus = HSTX_ENABLE_PA;
                mode = HSTX_MODE_DATA;
                break;
            case 0x83:
                paStatus = HSTX_ENABLE_PA;
                mode = HSTX_MODE_TESTDATA;
                break;
            default:
                break;
        }

        controlRegister = (paStatus << 7) | mode;
        return true;
    }

    private boolean handleReadOnlyCommand(int value) {
        if (i2cLen != 0) {
            return false;
        }

        response[0] = (byte) value;
        responseLength = 1;
        return true;
    }

    private void resetState() {
        currCmd = -1;
        Arrays.fill(i2cData, (byte) 0);
        Arrays.fill(response, (byte) 0);
        i2cLen = 0;
        responseLength = 0;
        respIndex = 0;
        resetRegisters();
    }

    private void resetRegisters() {
        controlRegister = 0;
        encoderDataRate = 0;
        encoderModulation = 0;
        encoderFilter = 0;
        encoderScrambler = 0;
        encoderOrder = 0;
        paPower = 0;
        synthOffset = 0;
    }
}

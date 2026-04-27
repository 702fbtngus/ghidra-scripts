package hw;

import java.util.Arrays;

import helper.DeviceManager;
import hw.I2CDevice.I2CEvent;

public class UVANT extends I2CDevice {

    private static final int MAX_TRANSFER_LENGTH = 0x100;
    private static final int ANT_NOT_DEPLOYED = 0;
    private static final int ANT_TIME_LIMIT_REACHED = 1;
    private static final int ANT_DEPLOYMENT_ACTIVE = 2;
    private static final int ANT_ACTIVATION_COUNT = 3;
    private static final int ANT_ACTIVATION_TIME_LO = 4;
    private static final int ANT_ACTIVATION_TIME_HI = 5;

    private static final int CMD_RESET = 0xAA;
    private static final int CMD_ARM = 0xAD;
    private static final int CMD_DISARM = 0xAC;
    private static final int CMD_DEPLOY_1 = 0xA1;
    private static final int CMD_DEPLOY_2 = 0xA2;
    private static final int CMD_DEPLOY_3 = 0xA3;
    private static final int CMD_DEPLOY_4 = 0xA4;
    private static final int CMD_DEPLOY_AUTO = 0xA5;
    private static final int CMD_DEPLOY_CANCEL = 0xA9;
    private static final int CMD_O_DEPLOY_1 = 0xBA;
    private static final int CMD_O_DEPLOY_2 = 0xBB;
    private static final int CMD_O_DEPLOY_3 = 0xBC;
    private static final int CMD_O_DEPLOY_4 = 0xBD;
    private static final int CMD_TEMP = 0xC0;
    private static final int CMD_STATUS_DEPLOY = 0xC3;
    private static final int CMD_COUNT_1 = 0xB0;
    private static final int CMD_COUNT_2 = 0xB1;
    private static final int CMD_COUNT_3 = 0xB2;
    private static final int CMD_COUNT_4 = 0xB3;
    private static final int CMD_TIME_1 = 0xB4;
    private static final int CMD_TIME_2 = 0xB5;
    private static final int CMD_TIME_3 = 0xB6;
    private static final int CMD_TIME_4 = 0xB7;

    private final byte[] i2cData = new byte[MAX_TRANSFER_LENGTH];
    private final byte[] ant0 = new byte[6];
    private final byte[] ant1 = new byte[6];
    private final byte[] ant2 = new byte[6];
    private final byte[] ant3 = new byte[6];

    private int lastCmd;
    private int i2cLen;
    private int armed;
    private int switchIgnore;
    private int independentBurn;
    private int maxDeployTimeSeconds;

    public UVANT(DeviceManager deviceManager, String name, int addr) {
        super(deviceManager, name, addr);
        response = new byte[MAX_TRANSFER_LENGTH];
        resetState();
    }

    @Override
    public void link() {}

    @Override
    public boolean tx(byte value) {
        if (lastCmd == -1) {
            lastCmd = Byte.toUnsignedInt(value);
            responseLength = 0;
            respIndex = 0;
        } else {
            if (i2cLen >= i2cData.length) {
                println(String.format("too long message (%d bytes)", i2cLen));
                return false;
            }
            i2cData[i2cLen++] = value;
        }

        int activationTime;
        switch (lastCmd) {
            case CMD_TEMP:
                writeLe16(0x1111);
                break;
            case CMD_STATUS_DEPLOY:
                writeStatusDeployResponse();
                break;
            case CMD_COUNT_1:
                writeAntennaCountResponse(0);
                break;
            case CMD_COUNT_2:
                writeAntennaCountResponse(1);
                break;
            case CMD_COUNT_3:
                writeAntennaCountResponse(2);
                break;
            case CMD_COUNT_4:
                writeAntennaCountResponse(3);
                break;
            case CMD_TIME_1:
                writeAntennaTimeResponse(0);
                break;
            case CMD_TIME_2:
                writeAntennaTimeResponse(1);
                break;
            case CMD_TIME_3:
                writeAntennaTimeResponse(2);
                break;
            case CMD_TIME_4:
                writeAntennaTimeResponse(3);
                break;
            case CMD_DEPLOY_1:
            case CMD_DEPLOY_2:
            case CMD_DEPLOY_3:
            case CMD_DEPLOY_4:
            case CMD_DEPLOY_AUTO:
            case CMD_O_DEPLOY_1:
            case CMD_O_DEPLOY_2:
            case CMD_O_DEPLOY_3:
            case CMD_O_DEPLOY_4:
                if (i2cLen == 1) {
                    maxDeployTimeSeconds = Byte.toUnsignedInt(i2cData[0]);
                    activationTime = maxDeployTimeSeconds;
                    applyDeployCommand(lastCmd, activationTime);
                    lastCmd = -1;
                    i2cLen = 0;
                }
                responseLength = 0;
                break;
            case CMD_RESET:
                armed = 0;
                switchIgnore = 0;
                independentBurn = 0;
                maxDeployTimeSeconds = 0;
                clearAntennaState();
                responseLength = 0;
                break;
            case CMD_ARM:
                armed = 1;
                responseLength = 0;
                break;
            case CMD_DISARM:
                armed = 0;
                independentBurn = 0;
                switchIgnore = 0;
                responseLength = 0;
                break;
            case CMD_DEPLOY_CANCEL:
                clearDeploymentActiveFlags();
                switchIgnore = 0;
                independentBurn = 0;
                responseLength = 0;
                break;
            default:
                lastCmd = -1;
                i2cLen = 0;
                break;
        }

        return true;
    }

    @Override
    public void onI2CEvent(I2CEvent event) {
        switch (event) {
            case START_RECV:
                i2cLen = 0;
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

    private void writeLe16(int value) {
        response[0] = (byte) (value & 0xFF);
        response[1] = (byte) ((value >>> 8) & 0xFF);
        responseLength = 2;
    }

    private void writeByte(int value) {
        response[0] = (byte) (value & 0xFF);
        responseLength = 1;
    }

    private void writeStatusDeployResponse() {
        int status0 = 0;
        int status1 = 0;

        if ((armed & 0x01) != 0) {
            status0 |= 0x01;
        }
        if ((independentBurn & 0x01) != 0) {
            status0 |= 0x10;
        }
        if ((switchIgnore & 0x01) != 0) {
            status1 |= 0x01;
        }

        // Match the 2-byte bitmap unpacked by isis_ants_driver.c.
        status1 = setStatusBits(status1, ant0, 0x80, 0x40, 0x20);
        status1 = setStatusBits(status1, ant1, 0x08, 0x04, 0x02);
        status0 = setStatusBits(status0, ant2, 0x80, 0x40, 0x20);
        status0 = setStatusBits(status0, ant3, 0x08, 0x04, 0x02);

        response[0] = (byte) status0;
        response[1] = (byte) status1;
        responseLength = 2;
    }

    private int setStatusBits(int status, byte[] antenna, int notDeployedMask,
                              int timeLimitMask, int deploymentActiveMask) {
        if (antenna[ANT_NOT_DEPLOYED] != 0) {
            status |= notDeployedMask;
        }
        if (antenna[ANT_TIME_LIMIT_REACHED] != 0) {
            status |= timeLimitMask;
        }
        if (antenna[ANT_DEPLOYMENT_ACTIVE] != 0) {
            status |= deploymentActiveMask;
        }
        return status;
    }

    private void writeAntennaCountResponse(int antennaIndex) {
        writeByte(Byte.toUnsignedInt(getAntenna(antennaIndex)[ANT_ACTIVATION_COUNT]));
    }

    private void writeAntennaTimeResponse(int antennaIndex) {
        byte[] antenna = getAntenna(antennaIndex);
        response[0] = antenna[ANT_ACTIVATION_TIME_LO];
        response[1] = antenna[ANT_ACTIVATION_TIME_HI];
        responseLength = 2;
    }

    private byte[] getAntenna(int antennaIndex) {
        switch (antennaIndex) {
            case 0:
                return ant0;
            case 1:
                return ant1;
            case 2:
                return ant2;
            case 3:
                return ant3;
            default:
                throw new IllegalArgumentException("invalid antenna index: " + antennaIndex);
        }
    }

    private void applyDeployCommand(int command, int activationTimeSeconds) {
        switch (command) {
            case CMD_DEPLOY_1:
                switchIgnore = 0;
                independentBurn = 1;
                markAntennaDeployed(ant0, activationTimeSeconds);
                break;
            case CMD_DEPLOY_2:
                switchIgnore = 0;
                independentBurn = 1;
                markAntennaDeployed(ant1, activationTimeSeconds);
                break;
            case CMD_DEPLOY_3:
                switchIgnore = 0;
                independentBurn = 1;
                markAntennaDeployed(ant2, activationTimeSeconds);
                break;
            case CMD_DEPLOY_4:
                switchIgnore = 0;
                independentBurn = 1;
                markAntennaDeployed(ant3, activationTimeSeconds);
                break;
            case CMD_O_DEPLOY_1:
                switchIgnore = 1;
                independentBurn = 1;
                markAntennaDeployed(ant0, activationTimeSeconds);
                break;
            case CMD_O_DEPLOY_2:
                switchIgnore = 1;
                independentBurn = 1;
                markAntennaDeployed(ant1, activationTimeSeconds);
                break;
            case CMD_O_DEPLOY_3:
                switchIgnore = 1;
                independentBurn = 1;
                markAntennaDeployed(ant2, activationTimeSeconds);
                break;
            case CMD_O_DEPLOY_4:
                switchIgnore = 1;
                independentBurn = 1;
                markAntennaDeployed(ant3, activationTimeSeconds);
                break;
            case CMD_DEPLOY_AUTO:
                switchIgnore = 0;
                independentBurn = 0;
                markAntennaDeployed(ant0, activationTimeSeconds);
                markAntennaDeployed(ant1, activationTimeSeconds);
                markAntennaDeployed(ant2, activationTimeSeconds);
                markAntennaDeployed(ant3, activationTimeSeconds);
                break;
            default:
                break;
        }
    }

    private void markAntennaDeployed(byte[] antenna, int activationTimeSeconds) {
        antenna[ANT_NOT_DEPLOYED] = 0;
        antenna[ANT_TIME_LIMIT_REACHED] = 0;
        antenna[ANT_DEPLOYMENT_ACTIVE] = 0;
        antenna[ANT_ACTIVATION_COUNT] = (byte) ((Byte.toUnsignedInt(antenna[ANT_ACTIVATION_COUNT]) + 1) & 0xFF);
        antenna[ANT_ACTIVATION_TIME_LO] = (byte) (activationTimeSeconds & 0xFF);
        antenna[ANT_ACTIVATION_TIME_HI] = (byte) ((activationTimeSeconds >>> 8) & 0xFF);
    }

    private void clearDeploymentActiveFlags() {
        ant0[ANT_DEPLOYMENT_ACTIVE] = 0;
        ant1[ANT_DEPLOYMENT_ACTIVE] = 0;
        ant2[ANT_DEPLOYMENT_ACTIVE] = 0;
        ant3[ANT_DEPLOYMENT_ACTIVE] = 0;
    }

    private void clearAntennaState() {
        clearAntennaState(ant0);
        clearAntennaState(ant1);
        clearAntennaState(ant2);
        clearAntennaState(ant3);
    }

    private void clearAntennaState(byte[] antenna) {
        Arrays.fill(antenna, (byte) 0);
        antenna[ANT_NOT_DEPLOYED] = 1;
    }

    private void resetState() {
        lastCmd = -1;
        Arrays.fill(i2cData, (byte) 0);
        i2cLen = 0;
        Arrays.fill(response, (byte) 0);
        responseLength = 0;
        respIndex = 0;
        armed = 0;
        switchIgnore = 0;
        independentBurn = 0;
        clearAntennaState();
    }
}

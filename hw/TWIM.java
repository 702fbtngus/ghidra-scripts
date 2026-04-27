package hw;

import helper.DeviceManager;
import hw.I2CDevice.I2CEvent;
import hw.MmioDevice.Register.AccessType;

public class TWIM extends MmioDevice {

    Register CR, CWGR, SMBTR, CMDR, NCMDR;
    Register RHR, THR, SR;
    Register IER, IDR, IMR;
    Register SCR, PR, VR;

    static final int CR_MEN = 1 << 0;
    static final int CR_MDIS = 1 << 1;
    static final int CR_SMEN = 1 << 4;
    static final int CR_SMDIS = 1 << 5;
    static final int CR_SWRST = 1 << 7;
    static final int CR_STOP = 1 << 8;

    static final int CMDR_READ = 1 << 0;
    static final int CMDR_SADR_MASK = 0x3ff << 1;
    static final int CMDR_TENBIT = 1 << 11;
    static final int CMDR_REPSAME = 1 << 12;
    static final int CMDR_START = 1 << 13;
    static final int CMDR_STOP = 1 << 14;
    static final int CMDR_VALID = 1 << 15;
    static final int CMDR_NBYTES_MASK = 0xff << 16;
    static final int CMDR_PECEN = 1 << 24;
    static final int CMDR_ACKLAST = 1 << 25;

    static final int SR_RXRDY = 1 << 0;
    static final int SR_TXRDY = 1 << 1;
    static final int SR_CRDY = 1 << 2;
    static final int SR_CCOMP = 1 << 3;
    static final int SR_IDLE = 1 << 4;
    static final int SR_BUSFREE = 1 << 5;
    static final int SR_ANAK = 1 << 8;
    static final int SR_DNAK = 1 << 9;
    static final int SR_ARBLST = 1 << 10;
    static final int SR_SMBALERT = 1 << 11;
    static final int SR_TOUT = 1 << 12;
    static final int SR_PECERR = 1 << 13;
    static final int SR_STOP = 1 << 14;
    static final int SR_MENB = 1 << 16;

    static final int SCR_MASK = SR_CCOMP | SR_ANAK | SR_DNAK | SR_ARBLST
            | SR_SMBALERT | SR_TOUT | SR_PECERR | SR_STOP;

    static final int SR_RESET_VALUE = SR_TXRDY;
    static final int PR_RESET_VALUE = 0x00000000;
    static final int VR_RESET_VALUE = 0x00000101;

    // Internal state mirroring control/status exposed by the hardware.
    private boolean masterEnabled;
    private boolean smbusEnabled;
    private boolean commandActive;
    private boolean busBusy;
    private int remainingBytes;

    private INTC intc;
    private PDCA pdca;

    public TWIM(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);

        CR = newRegister(0x00, 0x00, AccessType.WRITE_ONLY);
        CWGR = newRegister(0x04, 0x00, AccessType.READ_WRITE);
        SMBTR = newRegister(0x08, 0x00, AccessType.READ_WRITE);
        CMDR = newRegister(0x0C, 0x00, AccessType.READ_WRITE);
        NCMDR = newRegister(0x10, 0x00, AccessType.READ_WRITE);
        RHR = newRegister(0x14, 0x00, AccessType.READ_ONLY);
        THR = newRegister(0x18, 0x00, AccessType.WRITE_ONLY);
        SR = newRegister(0x1c, SR_RESET_VALUE, AccessType.READ_ONLY);
        IER = newRegister(0x20, 0x00, AccessType.WRITE_ONLY);
        IDR = newRegister(0x24, 0x00, AccessType.WRITE_ONLY);
        IMR = newRegister(0x28, 0x00, AccessType.READ_ONLY);
        SCR = newRegister(0x2c, 0x00, AccessType.WRITE_ONLY);
        PR = newRegister(0x30, PR_RESET_VALUE, AccessType.READ_ONLY);
        VR = newRegister(0x34, VR_RESET_VALUE, AccessType.READ_ONLY);

        reset();
    }

    @Override
    public void link() {
        this.intc = (INTC) deviceManager.findDevice("INTC");
        this.pdca = (PDCA) deviceManager.findDevice("PDCA");
    }

    /*
     * =========================
     * Register Write Handling
     * =========================
     */
    @Override
    protected boolean onWrite(int ofs, int val) {
        if (!super.onWrite(ofs, val)) {
            return false;
        }

        switch (ofs) {
            case 0x00: // CR
                if ((val & CR_MEN) != 0) {
                    masterEnabled = true;
                    SR.value |= SR_MENB;
                }
                if ((val & CR_MDIS) != 0) {
                    masterEnabled = false;
                    SR.value &= ~SR_MENB;
                }
                if ((val & CR_SMEN) != 0) {
                    smbusEnabled = true;
                }
                if ((val & CR_SMDIS) != 0) {
                    smbusEnabled = false;
                }
                if ((val & CR_SWRST) != 0) {
                    reset();
                }
                if ((val & CR_STOP) != 0) {
                    requestStop();
                }
                evaluateInterrupt();
                break;

            case 0x0C: // CMDR
                if (!commandActive) {
                    tryStartPendingCommand();
                }
                updateState();
                evaluateInterrupt();
                break;

            case 0x10: // NCMDR
                if (!commandActive && (CMDR.value & CMDR_VALID) == 0) {
                    moveNextCommandToCurrent();
                    tryStartPendingCommand();
                }
                updateState();
                evaluateInterrupt();
                break;

            case 0x18: // THR
                // write to THR assumes TXRDY
                if (!isTxReady()) {
                    return false;
                }
                processTransmitByte();
                break;

            case 0x20: // IER
                IMR.value |= val;
                evaluateInterrupt();
                break;

            case 0x24: // IDR
                IMR.value &= ~val;
                evaluateInterrupt();
                break;

            case 0x2C: // SCR
                SR.value &= ~(val & SCR_MASK);
                if (!commandActive) {
                    tryStartPendingCommand();
                    updateState();
                }
                evaluateInterrupt();
                break;
        }
        return true;
    }

    /*
     * =========================
     * Register Read Handling
     * =========================
     */
    @Override
    protected Integer onRead(int ofs) {
        switch (ofs) {
            case 0x14: {
                // read from RHR assumes RXRDY
                if (!isRxReady()) {
                    return null;
                }
                Integer value = super.onRead(ofs);
                // Prepare data for next RX
                consumeReceiveByte();
                return value;
            }
            case 0x1c: {
                // read from SR.CRDY assumes IMR.CRDY
                if ((IMR.value & SR_CRDY) == 0) {
                    SR.value &= ~SR_CRDY;
                }
            }
        }
        return super.onRead(ofs);
    }

    /*
     * =========================
     * Internal Logic
     * =========================
     */

    private void reset() {
        masterEnabled = false;
        smbusEnabled = false;
        commandActive = false;
        busBusy = false;
        remainingBytes = 0;
        CMDR.value = 0;
        NCMDR.value = 0;
        RHR.value = 0;
        THR.value = 0;
        IMR.value = 0;
        SR.value = SR_RESET_VALUE | SR_IDLE | SR_BUSFREE | SR_CRDY;
        evaluateInterrupt();
    }

    private void requestStop() {
        if (!commandActive) {
            return;
        }

        busBusy = false;
        commandActive = false;
        remainingBytes = 0;
        SR.value &= ~(SR_RXRDY | SR_TXRDY);
        println("SR.TXRDY cleared (requestStop)");
        SR.value |= SR_IDLE | SR_BUSFREE | SR_CCOMP;
        SR.value |= SR_STOP;
        NCMDR.value &= ~CMDR_VALID;
        updateState();
        evaluateInterrupt();
    }

    private void tryStartPendingCommand() {
        if (commandActive || !masterEnabled || hasBlockingError()) {
            updateState();
            return;
        }

        if ((CMDR.value & CMDR_VALID) == 0) {
            moveNextCommandToCurrent();
        }
        if ((CMDR.value & CMDR_VALID) == 0) {
            SR.value |= SR_IDLE | SR_BUSFREE;
            updateState();
            return;
        }

        commandActive = true;
        busBusy = true;
        remainingBytes = getCommandByteCount(CMDR.value);
        SR.value &= ~(SR_IDLE | SR_BUSFREE | SR_CCOMP | SR_STOP | SR_RXRDY | SR_TXRDY);
        println("SR.TXRDY cleared (tryStartPendingCommand)");
        deviceManager.emitI2CEvent(
            getSlaveAddress(),
            isReadCommand(CMDR.value) ? I2CEvent.START_RECV : I2CEvent.START_SEND
        );

        if (isReadCommand(CMDR.value)) {
            fillReceiveHoldingRegister();
            requestPdcaTransfer(getRxPdcaPsr());
        } else {
            SR.value |= SR_TXRDY;
            println("SR.TXRDY set (tryStartPendingCommand)");
            // processTransmitByte();
            requestPdcaTransfer(getTxPdcaPsr());
        }

        if (remainingBytes == 0) {
            finishCurrentCommand(true);
            return;
        }

        updateState();
        evaluateInterrupt();
    }

    private void moveNextCommandToCurrent() {
        if ((NCMDR.value & CMDR_VALID) == 0) {
            return;
        }

        CMDR.value = NCMDR.value;
        NCMDR.value &= ~CMDR_VALID;
    }

    private void processTransmitByte() {
        if (!commandActive || isReadCommand(CMDR.value) || remainingBytes <= 0) {
            evaluateInterrupt();
            return;
        }

        if (!addressExists()) {
            failCurrentCommand(SR_ANAK);
            return;
        }

        byte thrv = (byte) (THR.value & 0xff);
        Integer tx = deviceManager.sendToI2CDevice(getSlaveAddress(), thrv);
        if (tx == null) {
            failCurrentCommand(SR_DNAK);
            return;
        }

        remainingBytes--;
        println("remainingBytes = " + remainingBytes);

        SR.value &= ~SR_TXRDY;
        println("SR.TXRDY cleared (processTransmitByte)");
        if (remainingBytes > 0) {
            SR.value |= SR_TXRDY;
            println("SR.TXRDY set (processTransmitByte)");
        } else {
            finishCurrentCommand(true);
        }
        updateState();
        evaluateInterrupt();
    }

    private void consumeReceiveByte() {
        if (!commandActive || !isReadCommand(CMDR.value)) {
            return;
        }

        SR.value &= ~SR_RXRDY;
        if (remainingBytes > 0) {
            fillReceiveHoldingRegister();
        } else {
            finishCurrentCommand(true);
        }
        updateState();
        evaluateInterrupt();
    }

    private void fillReceiveHoldingRegister() {
        if (!commandActive || !isReadCommand(CMDR.value) || remainingBytes <= 0) {
            return;
        }

        if (!addressExists()) {
            failCurrentCommand(SR_ANAK);
            return;
        }

        Byte res = deviceManager.recvFromI2CDevice(getSlaveAddress());
        if (res == null) {
            failCurrentCommand(SR_DNAK);
            return;
        }

        RHR.value = Byte.toUnsignedInt(res);
        remainingBytes--;
        SR.value |= SR_RXRDY;
        evaluateInterrupt();
    }

    private void finishCurrentCommand(boolean success) {
        int slaveAddress = getSlaveAddress();
        commandActive = false;
        busBusy = false;
        remainingBytes = 0;
        SR.value &= ~(SR_RXRDY | SR_TXRDY);
        println("SR.TXRDY cleared (finishCurrentCommand)");
        SR.value |= SR_IDLE | SR_BUSFREE;

        if (success) {
            SR.value |= SR_CCOMP;
            deviceManager.emitI2CEvent(slaveAddress, I2CEvent.FINISH);
        }

        CMDR.value &= ~CMDR_VALID;
        moveNextCommandToCurrent();
        updateState();
        if ((CMDR.value & CMDR_VALID) != 0 && !hasBlockingError()) {
            tryStartPendingCommand();
        } else {
            evaluateInterrupt();
        }
    }

    private void failCurrentCommand(int errorBit) {
        int slaveAddress = getSlaveAddress();
        commandActive = false;
        busBusy = false;
        remainingBytes = 0;
        SR.value &= ~(SR_RXRDY | SR_TXRDY | SR_CCOMP);
        println("SR.TXRDY cleared (failCurrentCommand)");
        SR.value |= SR_IDLE | SR_BUSFREE | errorBit;
        deviceManager.emitI2CEvent(slaveAddress, I2CEvent.NACK);
        updateState();
        evaluateInterrupt();
    }

    private void updateState() {
        boolean currentReady = !commandActive || (CMDR.value & CMDR_VALID) == 0;
        boolean nextReady = (NCMDR.value & CMDR_VALID) == 0;
        if (currentReady || nextReady) {
            SR.value |= SR_CRDY;
        } else {
            SR.value &= ~SR_CRDY;
        }

        if (currentReady && nextReady) {
            SR.value |= SR_IDLE;
        } else {
            SR.value &= ~SR_IDLE;
        }
    }

    private boolean hasBlockingError() {
        return (SR.value & (SR_ANAK | SR_DNAK | SR_ARBLST | SR_TOUT | SR_PECERR)) != 0;
    }

    private boolean isReadCommand(int command) {
        return (command & CMDR_READ) != 0;
    }

    private int getSlaveAddress() {
        return (CMDR.value & CMDR_SADR_MASK) >>> 1;
    }

    private int getCommandByteCount(int command) {
        return (command & CMDR_NBYTES_MASK) >>> 16;
    }

    private boolean addressExists() {
        int address = getSlaveAddress();
        if ((CMDR.value & CMDR_TENBIT) != 0) {
            return false;
        }
        return deviceManager.findI2CDevice(address) != null;
    }

    public boolean isRxReady() {
        return (SR.value & SR_RXRDY) != 0;
    }

    public boolean isTxReady() {
        return (SR.value & SR_TXRDY) != 0;
    }

    private int getTxPdcaPsr() {
        return switch (name) {
            case "TWIM0" -> 17;
            case "TWIM1" -> 18;
            case "TWIM2" -> 35;
            default -> -1;
        };
    }

    private int getRxPdcaPsr() {
        return switch (name) {
            case "TWIM0" -> 6;
            case "TWIM1" -> 7;
            case "TWIM2" -> 32;
            default -> -1;
        };
    }

    private void requestPdcaTransfer(int psr) {
        println(String.format("requesting PDCA transfer: PSR=0x%X", psr));
        if (pdca == null || psr < 0) {
            return;
        }
        pdca.requestTransfer(psr);
    }

    private void evaluateInterrupt() {
        if (intc == null) {
            return;
        }
        if ((SR.value & IMR.value) != 0) {
            println(String.format("Interrupt raised: SR=0x%X IMR=0x%X", SR.value, IMR.value));
            intc.raiseInterrupt(group, 0);
        } else {
            intc.clearInterrupt(group, 0);
        }
    }

}

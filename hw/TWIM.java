package hw;

import helper.DeviceManager;
import hw.MmioDevice.Register.AccessType;

public class TWIM extends MmioDevice {

    Register CR, CWGR, SMBTR, CMDR, NCMDR;
    Register RHR, THR, SR;
    Register IER, IDR, IMR;
    Register SCR, PR, VR;

    // enum State { IDLE, START, TX, RX, STOP }
    // State state = State.IDLE;

    static final int SR_RXRDY  = 1 << 0;
    static final int SR_TXRDY  = 1 << 1;
    static final int SR_CCOMP  = 1 << 3;
    static final int SR_IDLE   = 1 << 4;
    static final int SR_ANAK   = 1 << 8;
    static final int SR_DNAK   = 1 << 9;

    private INTC intc;

    public TWIM(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);

        CR = newRegister(0x00, 0x00, AccessType.WRITE_ONLY);
        CWGR = newRegister(0x04, 0x00, AccessType.READ_WRITE);
        SMBTR = newRegister(0x08, 0x00, AccessType.READ_WRITE);
        CMDR = newRegister(0x0C, 0x00, AccessType.READ_WRITE);
        NCMDR = newRegister(0x10, 0x00, AccessType.READ_WRITE);
        RHR = newRegister(0x14, 0x00, AccessType.READ_ONLY );
        THR = newRegister(0x18, 0x00, AccessType.WRITE_ONLY);
        SR = newRegister(0x1c, 0x02, AccessType.READ_ONLY );
        IER = newRegister(0x20, 0x00, AccessType.WRITE_ONLY);
        IDR = newRegister(0x24, 0x00, AccessType.WRITE_ONLY);
        IMR = newRegister(0x28, 0x00, AccessType.READ_ONLY );
        SCR = newRegister(0x2c, 0x00, AccessType.WRITE_ONLY);
        PR = newRegister(0x30, 0x00, AccessType.READ_ONLY );
        VR = newRegister(0x34, 0x00, AccessType.READ_ONLY );
    }

    @Override
    public void link() {
        this.intc = (INTC) deviceManager.findDevice("INTC");
    }

    /* =========================
     * Register Write Handling
     * ========================= */
    @Override
    protected boolean onWrite(int ofs, int val) {
        if (!super.onWrite(ofs, val)) {
            return false;
        }

        switch (ofs) {
            case 0x00: // CR
                if ((val & 0x1) != 0) {   // SWRST
                    reset();
                }
                break;

            case 0x18: // THR
                checkTransfer();
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
                SR.value &= ~(val & 0x00007f08);   // clear-on-write
                evaluateInterrupt();
                break;
        }
        return true;
    }

    /* =========================
     * Register Read Handling
     * ========================= */
    @Override
    protected Integer onRead(int ofs) {
        switch (ofs) {
            case 0x14:
                completeRx();
        }
        return super.onRead(ofs);
    }

    /* =========================
     * Internal Logic
     * ========================= */

    private void reset() {
        // state = State.IDLE;
        SR.value = SR_IDLE | SR_TXRDY;
    }

    private void checkTransfer() {
        SR.value &= ~(SR_CCOMP | SR_IDLE);
        // state = State.START;
        if ((SR.value & SR_TXRDY) != 0) {
            SR.value &= ~SR_TXRDY;
            completeTx();
        }
        // stepFSM();
        evaluateInterrupt();
    }

    private void completeTx() {
        int sadr = (CMDR.value & 0b111111111) >>> 1;
        byte thrv = (byte) (THR.value & 0xff);
        int tx = deviceManager.sendToI2CDevice(sadr, thrv);
        SR.value |= SR_TXRDY;
        // state = State.STOP;
        // stepFSM();
    }

    private void completeRx() {
        int sadr = (CMDR.value & 0b111111111) >>> 1;
        // SR |= SR_TXRDY;
        byte res = deviceManager.recvFromI2CDevice(sadr);
        RHR.value = 0xff & res;
        // state = State.STOP;
        // stepFSM();
    }

    private void evaluateInterrupt() {
        if ((SR.value & IMR.value) != 0) {
            intc.raiseInterrupt(group, 0);
        } else {
            intc.clearInterrupt(group, 0);
        }
    }
    
}

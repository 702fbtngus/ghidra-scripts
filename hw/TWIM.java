package hw;

public class TWIM extends MmioDevice {

    int CR, CWGR, SMBTR, CMDR, NCMDR;
    int RHR, THR, SR;
    int IER, IDR, IMR;
    int SCR, PR, VR;

    enum State { IDLE, START, TX, RX, STOP }
    State state = State.IDLE;

    static final int SR_RXRDY  = 1 << 0;
    static final int SR_TXRDY  = 1 << 1;
    static final int SR_CCOMP  = 1 << 3;
    static final int SR_IDLE   = 1 << 4;
    static final int SR_ANAK   = 1 << 8;
    static final int SR_DNAK   = 1 << 9;

    private INTC intc;
    private final int irqNumber;

    public TWIM(long baseAddr, String name, int irqNumber) {
        super(baseAddr, name);
        this.irqNumber = irqNumber;

        CR = CWGR = SMBTR = CMDR = NCMDR = 0;
        RHR = THR = 0;
        SR  = SR_TXRDY;   // datasheet reset state
        IER = IDR = IMR = 0;
        SCR = 0;
        PR = VR = 0;
    }

    @Override
    protected void link() {
        this.intc = (INTC) Device.findDevice("INTC");
    }

    /* =========================
     * Register Write Handling
     * ========================= */
    @Override
    protected boolean onWrite(int ofs, int val) {
        switch (ofs) {

            case 0x00: // CR
                CR = val;
                if ((val & 0x1) != 0) {   // SWRST
                    reset();
                }
                return true;

            case 0x04: CWGR = val; return true;
            case 0x08: SMBTR = val; return true;

            case 0x0C: // CMDR
                CMDR = val;
                startCommand();
                return true;

            case 0x10: // NCMDR
                NCMDR = val;
                return true;

            case 0x18: // THR
                THR = val & 0xFF;
                SR &= ~SR_TXRDY;
                return true;

            case 0x20: // IER
                IMR |= val;
                evaluateInterrupt();
                return true;

            case 0x24: // IDR
                IMR &= ~val;
                evaluateInterrupt();
                return true;

            case 0x2C: // SCR
                SR &= ~(val & 0x00007f08);   // clear-on-write
                evaluateInterrupt();
                return true;
        }
        return false;
    }

    /* =========================
     * Register Read Handling
     * ========================= */
    @Override
    protected Integer onRead(int ofs) {
        switch (ofs) {
            case 0x04: return CWGR;
            case 0x08: return SMBTR;
            case 0x0C: return CMDR;
            case 0x10: return NCMDR;
            case 0x14: return RHR;
            case 0x1C: return SR;
            case 0x28: return IMR;
            case 0x30: return PR;
            case 0x34: return VR;
        }
        return null;
    }

    /* =========================
     * Internal Logic
     * ========================= */

    private void reset() {
        state = State.IDLE;
        SR = SR_IDLE | SR_TXRDY;
    }

    private void startCommand() {
        SR &= ~(SR_CCOMP | SR_IDLE);
        state = State.START;
        stepFSM();
        evaluateInterrupt();
    }

    private void stepFSM() {
        switch (state) {
            case START:
                if ((CMDR & (1 << 0)) != 0) {   // READ
                    state = State.RX;
                } else {
                    state = State.TX;
                }
                stepFSM();
                break;

            case TX:
                completeTx();
                break;

            case RX:
                completeRx();
                break;

            case STOP:
                SR |= SR_CCOMP | SR_IDLE | SR_TXRDY;
                state = State.IDLE;
                evaluateInterrupt();
                break;

            default:
                break;
        }
    }

    private void completeTx() {
        int sadr = (CMDR & 0b111111111) >>> 1;
        int thr = THR & 0xff;
        SR |= SR_TXRDY;
        int tx = I2CDevice.sendToI2CDevice(sadr, thr);
        state = State.STOP;
        stepFSM();
    }

    private void completeRx() {
        int sadr = (CMDR & 0b111111111) >>> 1;
        SR |= SR_TXRDY;
        int res = I2CDevice.recvFromI2CDevice(sadr);
        RHR = res;
        state = State.STOP;
        stepFSM();
    }

    private void evaluateInterrupt() {
        if ((SR & IMR) != 0) {
            intc.raiseInterrupt(irqNumber);
        } else {
            intc.clearInterrupt(irqNumber);
        }
    }
    
}

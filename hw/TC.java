package hw;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import etc.Util;

public class TC extends MmioDevice {

    private static class Channel {
        int CCR, CMR, CV, RA, RB, RC, SR, IER, IDR, IMR;
        boolean clk;
        TC tc;
        int num;

        Channel() {
            CCR = CMR = CV = RA = RB = RC = SR = IER = IDR = IMR = 0;
        }

        public void checkInterrupt() {
            if ((SR & 0xff) == 0) {
                tc.intc.clearInterrupt(tc.group, num);
            } else {
                tc.intc.raiseInterrupt(tc.group, num);
            }
        }
    }

    Channel[] ch = new Channel[3];

    // Block registers
    int BCR, BMR, FEATURES, VERSION;

    private INTC intc;
    private ScheduledExecutorService scheduler;
    public boolean manual_tick;

    public TC(long baseAddr, String name, int group) {
        super(baseAddr, name, group);

        for (int i = 0; i < 3; i++) {
            ch[i] = new Channel();
            ch[i].num = i;
            ch[i].tc = this;
        }

        BCR = 0;
        BMR = 0;
        FEATURES = 0;
        VERSION = 0;
    }

    public void startClockThread() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "osc-32khz");
            t.setDaemon(true); // 핵심: main이 죽으면 JVM이 종료될 수 있게
            return t;
        });
        Runnable task = () -> tick();
        scheduler.scheduleAtFixedRate(task, 0, 31, TimeUnit.MICROSECONDS); // 32KHz oscillator
    }

    public void exitClockThread() {
        scheduler.shutdown();
    }

    private void tick() {
        for (int i = 0; i < ch.length; i++) {
            Channel c = ch[i];
            if ((c.SR >> 16 & 1) == 1) {
                if (c.CV == 0xffff) {
                    c.SR |= 1;
                    Util.println("[TC Channel " + i + "] overloaded");
                    c.checkInterrupt();
                    c.CV = 0;
                } else if (c.CV == c.RC - 1) {
                    c.SR |= 1 << 4;
                    Util.println("[TC Channel " + i + "] RC Compare occurred");
                    c.checkInterrupt();
                    c.CV = 0;
                } else {
                    c.CV += 1;
                }
            }
        }
    }

    public void manualTick() {
        for (int i = 0; i < ch.length; i++) {
            Channel c = ch[i];
            if ((c.SR >> 16 & 1) == 1) {
                c.SR |= 1 << 4;
                Util.println("[TC Channel " + i + "] manual tick occurred");
                c.checkInterrupt();
            }
        }
    }

    @Override
    protected void link() {
        intc = (INTC) Device.findDevice("INTC");
    }

    @Override
    protected boolean onWrite(int ofs, int val) {

        // ---------- Channel registers ----------
        int channel = (ofs >> 6) & 0x3;   // 0x00~0x3F → 0, 0x40~0x7F → 1, 0x80~0xBF → 2
        int off = ofs & 0x3F;             // low 6 bits = register offset inside channel

        if (channel < 3) {
            Channel c = ch[channel];
            switch (off) {
                case 0x00:
                    c.CCR = val;
                    int clken = val & 1;
                    int clkdis = (val & 2) >> 1;
                    if (clkdis == 1) {
                        c.clk = false;
                        c.SR &= ~(1 << 16);
                        c.checkInterrupt();
                    } else if (clken == 1) {
                        c.clk = true;
                        System.err.println("[TC Channel " + channel + "] enabled");
                        c.SR |= 1 << 16;
                        c.checkInterrupt();
                    }
                    return true;
                case 0x04: c.CMR = val; return true;
                case 0x14: c.RA  = val; return true;
                case 0x18: c.RB  = val; return true;
                case 0x1C: c.RC  = val; return true;
                case 0x24: c.IER = val; return true;
                case 0x28: c.IDR = val; return true;

                // Read-only
                case 0x10: // CV
                case 0x20: // SR
                case 0x2C: // IMR
                    return false;
            }
        }

        // ---------- Block-level registers ----------
        switch (ofs) {
            case 0xC0: BCR = val; return true;
            case 0xC4: BMR = val; return true;

            case 0xF8: // read-only
            case 0xFC: // read-only
                return false;
        }

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        // ---------- Channel registers ----------
        int channel = (ofs >> 6) & 0x3;
        int off = ofs & 0x3F;

        if (channel < 3) {
            Channel c = ch[channel];
            switch (off) {
                case 0x00: return null;        // CCR write-only
                case 0x04: return c.CMR;
                case 0x10: return ++c.CV;
                case 0x14: return c.RA;
                case 0x18: return c.RB;
                case 0x1C: return c.RC;
                case 0x20:
                    int sr = c.SR;
                    c.SR &= ~0xff;
                    c.checkInterrupt();
                    return sr;
                case 0x24: return null;        // IER write-only
                case 0x28: return null;        // IDR write-only
                case 0x2C: return c.IMR;
            }
        }

        // ---------- Block-level ----------
        switch (ofs) {
            case 0xC0: return null; // BCR write-only
            case 0xC4: return BMR;
            case 0xF8: return FEATURES;
            case 0xFC: return VERSION;
        }

        return null;
    }
}

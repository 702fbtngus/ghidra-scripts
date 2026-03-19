package hw;

import hw.MmioDevice.Register.AccessType;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import helper.DeviceManager;
import helper.Logger;

public class TC extends MmioDevice {

    private static class Channel {
        Register CCR, CMR, CV, RA, RB, RC, SR, IER, IDR, IMR;
        boolean clk;
        TC tc;
        int num;

        Channel(TC tc, int num) {
            this.tc = tc;
            this.num = num;
            int base = num * 0x40;
            CCR = tc.newRegister(base + 0x00, 0, AccessType.WRITE_ONLY);
            CMR = tc.newRegister(base + 0x04, 0, AccessType.READ_WRITE);
            CV = tc.newRegister(base + 0x10, 0, AccessType.READ_ONLY);
            RA = tc.newRegister(base + 0x14, 0, AccessType.READ_WRITE);
            RB = tc.newRegister(base + 0x18, 0, AccessType.READ_WRITE);
            RC = tc.newRegister(base + 0x1C, 0, AccessType.READ_WRITE);
            SR = tc.newRegister(base + 0x20, 0, AccessType.READ_ONLY);
            IER = tc.newRegister(base + 0x24, 0, AccessType.WRITE_ONLY);
            IDR = tc.newRegister(base + 0x28, 0, AccessType.WRITE_ONLY);
            IMR = tc.newRegister(base + 0x2C, 0, AccessType.READ_ONLY);
        }

        public void checkInterrupt() {
            if ((SR.value & 0xff) == 0) {
                tc.intc.clearInterrupt(tc.group, num);
            } else {
                tc.intc.raiseInterrupt(tc.group, num);
            }
        }
    }

    Channel[] ch = new Channel[3];

    // Block registers
    Register BCR, BMR, FEATURES, VERSION;

    private INTC intc;
    private ScheduledExecutorService scheduler;
    public boolean manual_tick;

    public TC(DeviceManager deviceManager, long baseAddr, String name, int group) {
        super(deviceManager, baseAddr, name, group);

        for (int i = 0; i < 3; i++) {
            ch[i] = new Channel(this, i);
        }

        BCR = newRegister(0xC0, 0, AccessType.WRITE_ONLY);
        BMR = newRegister(0xC4, 0, AccessType.READ_WRITE);
        FEATURES = newRegister(0xF8, 0, AccessType.READ_ONLY);
        VERSION = newRegister(0xFC, 0, AccessType.READ_ONLY);
    }

    public void startClockThread() {
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "osc-32khz");
            t.setDaemon(true); // 핵심: main이 죽으면 JVM이 종료될 수 있게
            return t;
        });
        Runnable task = () -> tick();
        // scheduler.scheduleAtFixedRate(task, 0, 31, TimeUnit.MICROSECONDS); // 32KHz oscillator
        scheduler.scheduleAtFixedRate(task, 0, 310, TimeUnit.MICROSECONDS); // 3.2KHz oscillator
        // scheduler.scheduleAtFixedRate(task, 0, 31, TimeUnit.MILLISECONDS); // 32Hz oscillator
    }

    public void exitClockThread() {
        scheduler.shutdown();
    }

    private void tick() {
        for (int i = 0; i < ch.length; i++) {
            Channel c = ch[i];
            if ((c.SR.value >> 16 & 1) == 1) {
                if (c.CV.value == 0xffff) {
                    c.SR.value |= 1;
                    Logger.printlnGlobal(String.format("[TC Channel %d] overloaded", i));
                    c.checkInterrupt();
                    c.CV.value = 0;
                } else if (c.CV.value == c.RC.value - 1) {
                    c.SR.value |= 1 << 4;
                    Logger.printlnGlobal(String.format("[TC Channel %d] RC Compare occurred", i));
                    c.checkInterrupt();
                    c.CV.value = 0;
                } else {
                    c.CV.value += 1;
                }
            }
        }
    }

    public void manualTick() {
        for (int i = 0; i < ch.length; i++) {
            Channel c = ch[i];
            if ((c.SR.value >> 16 & 1) == 1) {
                c.SR.value |= 1 << 4;
                Logger.printlnGlobal(String.format("[TC Channel %d] manual tick occurred", i));
                c.checkInterrupt();
            }
        }
    }

    @Override
    public void link() {
        intc = (INTC) deviceManager.findDevice("INTC");
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
                    c.CCR.value = val;
                    int clken = val & 1;
                    int clkdis = (val & 2) >> 1;
                    if (clkdis == 1) {
                        c.clk = false;
                        c.SR.value &= ~(1 << 16);
                        c.checkInterrupt();
                    } else if (clken == 1) {
                        c.clk = true;
                        System.err.println("[TC Channel " + channel + "] enabled");
                        c.SR.value |= 1 << 16;
                        c.checkInterrupt();
                    }
                    return true;
                case 0x04: c.CMR.value = val; return true;
                case 0x14: c.RA.value  = val; return true;
                case 0x18: c.RB.value  = val; return true;
                case 0x1C: c.RC.value  = val; return true;
                case 0x24: c.IER.value = val; return true;
                case 0x28: c.IDR.value = val; return true;

                // Read-only
                case 0x10: // CV
                case 0x20: // SR
                case 0x2C: // IMR
                    return false;
            }
        }

        // ---------- Block-level registers ----------
        switch (ofs) {
            case 0xC0: BCR.value = val; return true;
            case 0xC4: BMR.value = val; return true;

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
                case 0x04: return c.CMR.value;
                case 0x10: return ++c.CV.value;
                case 0x14: return c.RA.value;
                case 0x18: return c.RB.value;
                case 0x1C: return c.RC.value;
                case 0x20:
                    int sr = c.SR.value;
                    c.SR.value &= ~0xff;
                    c.checkInterrupt();
                    return sr;
                case 0x24: return null;        // IER write-only
                case 0x28: return null;        // IDR write-only
                case 0x2C: return c.IMR.value;
            }
        }

        // ---------- Block-level ----------
        switch (ofs) {
            case 0xC0: return null; // BCR write-only
            case 0xC4: return BMR.value;
            case 0xF8: return FEATURES.value;
            case 0xFC: return VERSION.value;
        }

        return null;
    }
}

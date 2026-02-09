package hw;

import etc.Util;

public class PDCA extends MmioDevice {

    public static final int NUM_CHANNELS = 16;

    PDCAChannel[] channels = new PDCAChannel[NUM_CHANNELS];
    PDCAPerfMonitor mon = new PDCAPerfMonitor();
    int VERSION;

    public PDCA(long baseAddr, String name) {

        super(baseAddr, name, 0x1000);

        for (int i = 0; i < NUM_CHANNELS; i++) {
            channels[i] = new PDCAChannel(i, this);
        }

        VERSION = 0;
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean onWrite(int ofs, int val) {

        // Channel area
        if (ofs < 0x800) {
            int ch = ofs / 0x40;
            int ro = ofs % 0x40;

            if (ch < NUM_CHANNELS) {
                return channels[ch].onWrite(ro, val);
            }
            return false;
        }

        // Perf monitor area
        if (ofs >= 0x800 && ofs <= 0x830) {
            return mon.onWrite(ofs - 0x800, val);
        }

        // Version is read-only
        if (ofs == 0x834) return false;

        return false;
    }

    @Override
    protected Integer onRead(int ofs) {

        if (ofs < 0x800) {
            int ch = ofs / 0x40;
            int ro = ofs % 0x40;

            if (ch < NUM_CHANNELS) {
                return channels[ch].onRead(ro);
            }
            return null;
        }

        if (ofs >= 0x800 && ofs <= 0x830) {
            return mon.onRead(ofs - 0x800);
        }

        if (ofs == 0x834) return VERSION;

        return null;
    }

    public void transferData(int mar, int psr, int size) {
        
        Util.println("[PDCA transferData] MAR = " + Util.intToHex(mar) + ", PSR = " + Util.intToHex(psr), 2);
        boolean is_rx;
        if ((psr >= 0 && psr <= 12)
         || (psr >= 31 && psr <= 33)
         || (psr >= 37 && psr <= 44)
        ) {
            is_rx = true;
        } else {
            is_rx = false;
        }

        long addr = switch (psr) {
            case 0 -> 0xFFFD2460L; // RX ADCIFA LCV0
            case 1 -> 0xFFFD2464L; // RX ADCIFA LCV1
            case 2 -> 0xFFFF2818L; // RX USART0 RHR
            case 3 -> 0xFFFD1418L; // RX USART1 RHR
            case 4 -> 0xFFFF2C18L; // RX USART2 RHR
            case 5 -> 0xFFFF3018L; // RX USART3 RHR
            case 6 -> 0xFFFF3814L; // RX TWIM0 RHR
            case 7 -> 0xFFFF3C14L; // RX TWIM1 RHR
            case 8 -> 0xFFFF400CL; // RX TWIS0 RHR
            case 9 -> 0xFFFF440CL; // RX TWIS1 RHR
            case 10 -> 0xFFFD1808L; // RX SPI0 RDR
            case 11 -> 0xFFFF3408L; // RX SPI1 RDR
            case 12 -> 0xFFFF7018L; // RX AW RHR
            case 13 -> 0xFFFF281CL; // TX USART0 THR
            case 14 -> 0xFFFD141CL; // TX USART1 THR
            case 15 -> 0xFFFF2C1CL; // TX USART2 THR
            case 16 -> 0xFFFF301CL; // TX USART3 THR
            case 17 -> 0xFFFF3818L; // TX TWIM0 THR
            case 18 -> 0xFFFF3C18L; // TX TWIM1 THR
            case 19 -> 0xFFFF4010L; // TX TWIS0 THR
            case 20 -> 0xFFFF4410L; // TX TWIS1 THR
            case 21 -> 0xFFFD180CL; // TX SPI0 TDR
            case 22 -> 0xFFFF340CL; // TX SPI1 TDR
            case 23 -> 0xFFFF682CL; // TX DACIFB0 DR0
            case 24 -> 0xFFFF6830L; // TX DACIFB0 DR1
            case 25 -> 0xFFFF6C2CL; // TX DACIFB1 DR0
            case 26 -> 0xFFFF6C30L; // TX DACIFB1 DR1
            case 27 -> -1L; // TX PWM PWM PDCA register
            case 28 -> 0xFFFF701CL; // TX AW THR
            case 31 -> 0xFFFD2818L; // RX USART4 RHR
            case 32 -> 0xFFFD2C14L; // RX TWIM2 RHR
            case 33 -> 0xFFFD300CL; // RX TWIS2 RHR
            case 34 -> 0xFFFD281CL; // TX USART4 THR
            case 35 -> 0xFFFD2C18L; // TX TWIM2 THR
            case 36 -> 0xFFFD3010L; // TX TWIS2 THR
            default -> (psr >= 37 && psr <= 44) ? 0xFFFF4820L // RX IISC RHR
                     : (psr >= 45 && psr <= 52) ? 0xFFFF4824L // TX IISC THR
                     : -1L;
        };

        if (is_rx) {
            MmioDevice.loadFromMmioDeviceAddr(addr, mar, size);
        } else {
            MmioDevice.storeToMmioDeviceAddr(addr, mar, size);
        }

    }
}

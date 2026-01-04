package peripheral;

public class PDCAPerfMonitor {

    int PCONTROL;

    int[] PRDATA  = new int[2];
    int[] PRSTALL = new int[2];
    int[] PRLAT   = new int[2];
    int[] PWDATA  = new int[2];
    int[] PWSTALL = new int[2];
    int[] PWLAT   = new int[2];

    public PDCAPerfMonitor() {
        PCONTROL = 0;
    }

    public boolean onWrite(int ofs, int val) {
        // only offset 0x00 is RW
        if (ofs == 0x00) {
            PCONTROL = val;
            return true;
        }
        return false;
    }

    public Integer onRead(int ofs) {

        if (ofs == 0x00) return PCONTROL;

        // offsets for channel counters
        // 0x04 + ch*0x0C + sub
        if (ofs >= 0x04 && ofs <= 0x30) {
            int ch = (ofs - 0x04) / 0x0C;
            int sub = (ofs - 0x04) % 0x0C;

            switch (sub) {
                case 0x00: return PRDATA[ch];
                case 0x04: return PRSTALL[ch];
                case 0x08: return PRLAT[ch];
            }
        }

        return null;
    }
}

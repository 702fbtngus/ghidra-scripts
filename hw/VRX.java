package hw;

import java.util.ArrayDeque;
import java.util.Queue;

import etc.Util;

public class VRX extends I2CDevice {

    public Queue<Integer> q = new ArrayDeque<>();

    public VRX(String name, int addr) {
        super(name, addr);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean tx(byte value) {
        switch (value) {
            case 0x21:
                response = Util.intToByteArray(q.size(), 2);
                respIndex = 0;
                return true;

            default:
                break;
        }
        return false;
    }
}

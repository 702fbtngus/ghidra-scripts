package hw;

public class VRX extends I2CDevice {

    public VRX(String name, int addr) {
        super(name, addr);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean tx(int value) {
        return true;
    }
}

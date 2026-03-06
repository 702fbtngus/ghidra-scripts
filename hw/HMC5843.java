package hw;

public class HMC5843 extends I2CDevice {

    public HMC5843(String name, int addr) {
        super(name, addr);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean tx(byte b) {
        return true;
    }
}

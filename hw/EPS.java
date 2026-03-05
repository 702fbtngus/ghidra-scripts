package hw;

public class EPS extends I2CDevice {

    public EPS(String name, int addr) {
        super(name, addr);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean tx(int value) {
        return true;
    }
}

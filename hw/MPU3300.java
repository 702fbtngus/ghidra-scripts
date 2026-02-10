package hw;

public class MPU3300 extends I2CDevice {

    public MPU3300(String name, int addr) {
        super(name, addr);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean tx(int value) {
        return true;
    }

    @Override
    protected Integer rx() {
        return 0;
    }
}

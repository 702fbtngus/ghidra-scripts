package hw;

public class UTX extends I2CDevice {

    public UTX(String name, int addr) {
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
        return null;
    }
}

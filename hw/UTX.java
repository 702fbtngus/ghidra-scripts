package hw;

public class UTX extends I2CDevice {

    public UTX(String name, int addr) {
        super(name, addr);
    }
    
    @Override
    protected void link() {}

    @Override
    protected boolean tx(byte b) {
        return true;
    }
}

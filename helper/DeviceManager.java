package helper;

import ghidra.program.model.pcode.Varnode;
import helper.ByteUtil.DataSize;
import hw.ADCIFA;
import hw.CANIF;
import hw.Device;
import hw.EPS;
import hw.FLASHC;
import hw.GPIO;
import hw.HMATRIX;
import hw.HMC5843;
import hw.I2CDevice;
import hw.INTC;
import hw.MPU3300;
import hw.MmioDevice;
import hw.PDCA;
import hw.PM;
import hw.SCIF;
import hw.SDRAMC;
import hw.SPI;
import hw.TC;
import hw.TWIM;
import hw.TWIS;
import hw.USART;
import hw.UTX;
import hw.VRX;
import hw.WDT;

import java.util.ArrayList;
import java.util.List;

public final class DeviceManager {
    public final List<Device> registry = new ArrayList<>();
    public final CPUState cpuState;
    private String currentDeviceName;


    public DeviceManager(CPUState cpuState) {
        this.cpuState = cpuState;
    }

    public void initializeDevices() {
        // MMIO devices
        new PDCA    ( this, 0xFFFD0000L, "PDCA"    , -1);
        new USART   ( this, 0xFFFD1400L, "USART1"  , -1);
        new CANIF   ( this, 0xFFFD1C00L, "CANIF"   , -1);
        new SPI     ( this, 0xFFFD1800L, "SPI0"    , -1);
        new TC      ( this, 0xFFFD2000L, "TC0"     , 33);
        new ADCIFA  ( this, 0xFFFD2400L, "ADCIFA"  , -1);
        new USART   ( this, 0xFFFD2800L, "USART4"  , -1);
        new TWIM    ( this, 0xFFFD2C00L, "TWIM2"   , 45);
        new TWIS    ( this, 0xFFFD3000L, "TWIS2"   , -1);
        new FLASHC  ( this, 0xFFFE0000L, "FLASHC"  , -1);
        new HMATRIX ( this, 0xFFFE2000L, "HMATRIX" , -1);
        new SDRAMC  ( this, 0xFFFE2C00L, "SDRAMC"  , -1);
        new INTC    ( this, 0xFFFF0000L, "INTC"    , -1);
        new PM      ( this, 0xFFFF0400L, "PM"      , -1);
        new SCIF    ( this, 0xFFFF0800L, "SCIF"    , -1);
        new WDT     ( this, 0xFFFF1000L, "WDT"     , -1);
        new GPIO    ( this, 0xFFFF2000L, "GPIO"    , -1);
        new USART   ( this, 0xFFFF2800L, "USART0"  , -1);
        new USART   ( this, 0xFFFF2C00L, "USART2"  , -1);
        new USART   ( this, 0xFFFF3000L, "USART3"  , -1);
        new SPI     ( this, 0xFFFF3400L, "SPI1"    , -1);
        new TWIM    ( this, 0xFFFF3800L, "TWIM0"   , 25);
        new TWIM    ( this, 0xFFFF3C00L, "TWIM1"   , 26);
        new TWIS    ( this, 0xFFFF4000L, "TWIS0"   , -1);
        new TWIS    ( this, 0xFFFF4400L, "TWIS1"   , -1);
        new TC      ( this, 0xFFFF5800L, "TC1"     , 34);

        // I2C devicesthis
        new MPU3300 ( this, "MPU3300", 0x68 );
        new HMC5843 ( this, "HMC5843", 0x1E );
        new EPS     ( this, "EPS", 0x2B );
        new UTX     ( this, "UTX", 0x61 );
        new VRX     ( this, "VRX", 0x60 );
    }

    public void register(Device device) {
        registry.add(device);
    }

    public String getCurrentDeviceName() {
        return currentDeviceName;
    }

    public void linkAllDevices() {
        for (Device device : registry) {
            device.link();
        }
    }

    public Device findDevice(String name) {
        for (Device device : registry) {
            if (device.name.equals(name)) {
                return device;
            }
        }
        return null;
    }

    public MmioDevice findMmioDevice(long addr) {
        for (Device device : registry) {
            if (device instanceof MmioDevice mmioDevice && mmioDevice.contains(addr)) {
                Logger.printlnGlobal(String.format("findMmioDevice 0x%08X: %s", addr, mmioDevice.name));
                return mmioDevice;
            }
        }
        Logger.printlnGlobal(String.format("findMmioDevice 0x%08X: null", addr));
        return null;
    }

    public Integer storeToMmioDeviceAddr(long addr, Varnode node) {
        MmioDevice mmioDevice = findMmioDevice(addr);
        if (mmioDevice == null) {
            return null;
        }
        int offset = (int) (addr - mmioDevice.base);
        currentDeviceName = mmioDevice.name;
        try {
            Logger.printlnGlobal(String.format("Store to %s @ 0x%08X", mmioDevice.name, addr), 2);
            return mmioDevice.store(offset, node);
        } finally {
            currentDeviceName = null;
        }
    }

    public Integer loadFromMmioDeviceAddr(long addr, Varnode node) {
        MmioDevice mmioDevice = findMmioDevice(addr);
        if (mmioDevice == null) {
            return null;
        }
        int offset = (int) (addr - mmioDevice.base);
        currentDeviceName = mmioDevice.name;
        try {
            Logger.printlnGlobal(String.format("Load from %s @ 0x%08X", mmioDevice.name, addr), 2);
            return mmioDevice.load(offset, node);
        } finally {
            currentDeviceName = null;
        }
    }

    public Integer loadFromMmioDeviceAddr(long addr, long dest) {
        MmioDevice mmioDevice = findMmioDevice(addr);
        if (mmioDevice == null) {
            return null;
        }
        int offset = (int) (addr - mmioDevice.base);
        currentDeviceName = mmioDevice.name;
        try {
            Logger.printlnGlobal(String.format("Load from %s @ 0x%08X", mmioDevice.name, addr), 2);
            return mmioDevice.load(offset, dest);
        } finally {
            currentDeviceName = null;
        }
    }

    public Integer loadFromMmioDeviceAddr(long addr, long dest, DataSize size) {
        MmioDevice mmioDevice = findMmioDevice(addr);
        if (mmioDevice == null) {
            return null;
        }
        int offset = (int) (addr - mmioDevice.base);
        currentDeviceName = mmioDevice.name;
        try {
            Logger.printlnGlobal(String.format("Load from %s @ 0x%08X", mmioDevice.name, addr), 2);
            return mmioDevice.load(offset, dest, size);
        } finally {
            currentDeviceName = null;
        }
    }

    public Integer storeToMmioDeviceAddr(long addr, long src, DataSize size) {
        MmioDevice mmioDevice = findMmioDevice(addr);
        if (mmioDevice == null) {
            return null;
        }
        int offset = (int) (addr - mmioDevice.base);
        currentDeviceName = mmioDevice.name;
        try {
            Logger.printlnGlobal(String.format("Store to %s @ 0x%08X (size: %s)", mmioDevice.name, addr, size), 2);
            return mmioDevice.store(offset, src, size);
        } finally {
            currentDeviceName = null;
        }
    }

    public I2CDevice findI2CDevice(int addr) {
        for (Device device : registry) {
            if (device instanceof I2CDevice i2cDevice && i2cDevice.addr == addr) {
                Logger.printlnGlobal(String.format("findI2CDevice 0x%08X: %s", addr, i2cDevice.name));
                return i2cDevice;
            }
        }
        Logger.printlnGlobal(String.format("findI2CDevice 0x%08X: null", addr));
        return null;
    }

    public Integer sendToI2CDevice(int addr, byte value) {
        I2CDevice device = findI2CDevice(addr);
        if (device == null) {
            return 0;
        }
        currentDeviceName = device.name;
        try {
            Logger.printlnGlobal(String.format("Send to I2CDevice %s @ 0x%08X: 0x%02X", device.name, addr, Byte.toUnsignedInt(value)), 2);
            if (("VRX".equals(device.name) || "UTX".equals(device.name)) && !device.tx(value)) {
                Logger.printlnGlobal(device.getClass().getSimpleName() + ": invalid tx value =0x" + Integer.toHexString(value));
                return null;
            }
            Logger.printlnGlobal("Sent successfully", 2);
            return 0;
        } finally {
            currentDeviceName = null;
        }
    }

    public Byte recvFromI2CDevice(int addr) {
        I2CDevice device = findI2CDevice(addr);
        if (device == null) {
            return 0;
        }
        currentDeviceName = device.name;
        try {
            Logger.printlnGlobal(String.format("Recv from I2CDevice %s @ 0x%08X", device.name, addr), 2);
            Byte value = device.rx();
            if (("VRX".equals(device.name) || "UTX".equals(device.name)) && value == null) {
                Logger.printlnGlobal(device.getClass().getSimpleName() + ": invalid rx");
                return null;
            }
            Logger.printlnGlobal(String.format("Received successfully: 0x%02X", Byte.toUnsignedInt(value)), 2);
            return value;
        } finally {
            currentDeviceName = null;
        }
    }
}

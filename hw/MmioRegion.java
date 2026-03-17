package hw;

import hw.MmioDevice.Register;
import hw.MmioDevice.Register.AccessType;

import java.util.ArrayList;
import java.util.List;

public abstract class MmioRegion {

    protected final MmioDevice owner;
    public final int baseOffset;
    public final int size;
    protected final List<MmioRegion> regions = new ArrayList<>();

    protected MmioRegion(MmioDevice owner, int baseOffset, int size) {
        this.owner = owner;
        this.baseOffset = baseOffset;
        this.size = size;
    }

    public final boolean contains(int offset) {
        return offset >= baseOffset && offset < baseOffset + size;
    }

    protected final Register newRegister(int offset, int value, AccessType at) {
        return owner.newRegister(baseOffset + offset, value, at);
    }

    protected final void addRegion(MmioRegion region) {
        int parentStart = baseOffset;
        int parentEnd = baseOffset + size;
        int regionStart = region.baseOffset;
        int regionEnd = region.baseOffset + region.size;

        if (regionStart < parentStart || regionEnd > parentEnd || regionStart >= regionEnd) {
            throw new IllegalArgumentException(String.format(
                "%s: region out of bounds offset=0x%X size=0x%X",
                getClass().getSimpleName(),
                region.baseOffset,
                region.size
            ));
        }

        for (MmioRegion existing : regions) {
            int existingStart = existing.baseOffset;
            int existingEnd = existing.baseOffset + existing.size;
            if (regionStart < existingEnd && existingStart < regionEnd) {
                throw new IllegalArgumentException(String.format(
                    "%s: overlapping regions at 0x%X and 0x%X",
                    getClass().getSimpleName(),
                    region.baseOffset,
                    existing.baseOffset
                ));
            }
        }

        regions.add(region);
    }

    protected void afterWrite(int offset, int value) {}

    protected void beforeRead(int offset) {}

    final MmioRegion findRegion(int offset) {
        if (!contains(offset)) {
            return null;
        }

        for (MmioRegion child : regions) {
            MmioRegion region = child.findRegion(offset);
            if (region != null) {
                return region;
            }
        }

        return this;
    }
}

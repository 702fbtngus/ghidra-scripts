package helper;

public final class PhaseManager {
    private static final long[] PHASE_BOUNDARIES = {
        0x8001db06L,
        0x8001db0aL,
        0x8001db0eL,
        0x8001db12L,
        0x8001db16L,
        0x8001db1aL,
        0x8001db1eL,
        0x8001db22L,
        0x8001db26L,
        0x8001db2aL,
        0x8001db2eL,
        0x8001db32L,
        0x8001db36L,
        0x8001db3aL,
        0x8001db3eL,
        0x8001db42L,
        0x8001db46L,
        0x8001db4aL,
        0x8001db4eL,
        0x8001db52L,
        0x8001db56L,
        0x8001db5aL,
        0x8001db5eL,
        0x8001db62L,
        0x8001db66L,
        0x8001dc64L,
        0x8001dc68L,
        0x8001dc6cL,
    };

    private Phase currentPhase;
    private int totalInstructionCount;

    public void startPhase(String functionName) {
        currentPhase = new Phase(0, 0, functionName);
        totalInstructionCount = 0;
    }

    public void nextPhase(String functionName) {
        ensureInitialized(functionName);
        currentPhase.setPhaseNumber(currentPhase.getPhaseNumber() + 1);
        currentPhase.setPhaseInstructionCount(0);
        currentPhase.setFunctionName(functionName);
    }

    public void updatePhase(long counterOffset, String functionName) {
        if (isPhaseBoundary(counterOffset)) {
            nextPhase(functionName);
            return;
        }
        setFunctionName(functionName);
    }

    public void incrementPhaseInstructionCount() {
        ensureInitialized("null");
        currentPhase.setPhaseInstructionCount(currentPhase.getPhaseInstructionCount() + 1);
        totalInstructionCount++;
    }

    public void decrementPhaseInstructionCount() {
        ensureInitialized("null");
        currentPhase.setPhaseInstructionCount(currentPhase.getPhaseInstructionCount() - 1);
        totalInstructionCount--;
    }

    public void setFunctionName(String functionName) {
        ensureInitialized(functionName);
        currentPhase.setFunctionName(functionName);
    }

    public Phase getCurrentPhase() {
        ensureInitialized("null");
        return currentPhase;
    }

    public int getTotalInstructionCount() {
        ensureInitialized("null");
        return totalInstructionCount;
    }

    private void ensureInitialized(String functionName) {
        if (currentPhase == null) {
            startPhase(functionName);
        }
    }

    private boolean isPhaseBoundary(long counterOffset) {
        for (long boundary : PHASE_BOUNDARIES) {
            if (boundary == counterOffset) {
                return true;
            }
        }
        return false;
    }

    public static final class Phase {
        private int phaseNumber;
        private int phaseInstructionCount;
        private String functionName;

        private Phase(int phaseNumber, int phaseInstructionCount, String functionName) {
            this.phaseNumber = phaseNumber;
            this.phaseInstructionCount = phaseInstructionCount;
            this.functionName = functionName;
        }

        public int getPhaseNumber() {
            return phaseNumber;
        }

        public int getPhaseInstructionCount() {
            return phaseInstructionCount;
        }

        public String getFunctionName() {
            return functionName;
        }

        public void setPhaseNumber(int phaseNumber) {
            this.phaseNumber = phaseNumber;
        }

        public void setPhaseInstructionCount(int phaseInstructionCount) {
            this.phaseInstructionCount = phaseInstructionCount;
        }

        public void setFunctionName(String functionName) {
            this.functionName = functionName;
        }

        public String toShortString() {
            return String.format("P%d #%d", phaseNumber, phaseInstructionCount);
        }

        @Override
        public String toString() {
            return toShortString() + ", " + functionName;
        }
    }
}

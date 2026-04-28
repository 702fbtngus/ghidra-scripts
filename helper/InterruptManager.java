package helper;

import hw.INTC;

public final class InterruptManager {

    private final Context context;
    private final CPUState cpuState;
    private final TaskManager taskManager;
    private final PhaseManager phaseManager;
    public INTC intc;

    public InterruptManager(Context context, CPUState cpuState, TaskManager taskManager, PhaseManager phaseManager) {
        this.context = context;
        this.cpuState = cpuState;
        this.taskManager = taskManager;
        this.phaseManager = phaseManager;
    }


    public void callInterruptWrapper(int i, int addr) {
        // *(--SPSYS) = R8;
        // *(--SPSYS) = R9;
        // *(--SPSYS) = R10;
        // *(--SPSYS) = R11;
        // *(--SPSYS) = R12;
        // *(--SPSYS) = LR;
        // *(--SPSYS) = PC of first noncompleted instruction;
        // *(--SPSYS) = SR;
        // SR[R] = 0;
        // SR[J] = 0;
        // SR[M2:M0] = B’010;
        // SR[I0M] = 1;
        // PC = EVBA + INTERRUPT_VECTOR_OFFSET;
        
        context.interrupted = true;
        phaseManager.beginInterrupt(context.currentThread.getCounter().getOffset(), context.getCurrentFunctionName());
        Logger.printlnGlobal("interrupted", -1);
        int sp = cpuState.getRegisterValue("SP");

        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("R8"));
        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("R9"));
        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("R10"));
        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("R11"));
        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("R12"));
        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("LR"));
        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("PC"));
        sp -= 4;
        cpuState.storeToAddr(sp, cpuState.getRegisterValue("SR"));

        if (context.userMode) {
            taskManager.setUserAddr(context.currentTaskName, sp);
        }

        cpuState.setRegisterValue("SP", sp);

        int sr = cpuState.getRegisterValue("SR");
        sr &= ~(1 << 15);
        sr &= ~(1 << 28);

        sr &= ~(0b111 << 22);
        int mode = switch (i) {
            case 0 -> 0b010;
            case 1 -> 0b011;
            case 2 -> 0b100;
            case 3 -> 0b101;
            default -> -1;
        };
        sr |= mode << 22;
        
        int mask = switch (i) {
            case 0 -> 0b0001;
            case 1 -> 0b0011;
            case 2 -> 0b0111;
            case 3 -> 0b1111;
            default -> -1;
        };
        sr |= mask << 17;

        cpuState.setRegisterValue("SR", sr);

        // cpuState.setRegisterValue("PC", 0x8005ab20);
        int evba = cpuState.getRegisterValue("EVBA");
        cpuState.setRegisterValue("PC", evba + addr);
        cpuState.finishFrame();
    }

    public void handleInterrupt() {
        int prio = intc.highestPrio;
        int addr = intc.highestPrioAddr;
        // helper.println("highestprio: " + prio);
        int sr = cpuState.getRegisterValue("SR");
        // helper.println("sr: " + helper.intToHex(sr));
        if (prio != -1) {
            if (
                ((sr >> (17 + prio)) & 1) == 0
                && ((sr >> 16) & 1) == 0
            ) {
                callInterruptWrapper(prio, addr);
            }
        }
    }
}

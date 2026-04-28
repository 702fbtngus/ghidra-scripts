package helper;

import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeExecutorState;


public class UseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {

    private final Context context;
    private final CPUState cpuState;
    private final TaskManager taskManager;
    private final PhaseManager phaseManager;

    public UseropLibrary(Context context, CPUState cpuState, TaskManager taskManager, PhaseManager phaseManager) {
        this.context = context;
        this.cpuState = cpuState;
        this.taskManager = taskManager;
        this.phaseManager = phaseManager;
    }

    @PcodeUserop
    public void log(@OpState PcodeExecutorState<byte[]> state, int i) {
        String s = String.format("log: %d", i);
        Logger.printlnGlobal(s);
    }

    @PcodeUserop
    public void CheckAndRestoreInterupt(@OpState PcodeExecutorState<byte[]> state) {
        Logger.printlnGlobal("CheckAndRestoreInterupt", 4);

        // SR ← *(SPSYS++)
        // PC ← *(SPSYS++)
        // If ( SR[M2:M0] == {B’010, B’011, B’100, B’101} ) {
        //     LR ← *(SPSYS++)
        //     R12 ← *(SPSYS++)
        //     R11 ← *(SPSYS++)
        //     R10 ← *(SPSYS++)
        //     R9 ← *(SPSYS++)
        //     R8 ← *(SPSYS++)
        // }
        // SREG[L] ← 0;

        int sp = cpuState.getRegisterValue("SP");
        int userAddr = taskManager.getUserAddr(context.currentTaskName);
        Logger.printlnGlobal(String.format("useraddr of %s: %s, sp: %s", context.currentTaskName, taskManager.getUserAddr(context.currentTaskName), sp), 6);
        context.userMode = userAddr == sp || userAddr + 0x0c == sp || userAddr + 0x18 == sp;
        int sr = cpuState.getRegisterValue("SR");
        cpuState.setRegisterValue("SR", cpuState.loadFromAddr(sp));
        sp += 4;
        cpuState.setRegisterValue("PC", cpuState.loadFromAddr(sp));
        sp += 4;

        switch ((sr >> 22) & 0x7) {
            case 0b010:
            case 0b011:
            case 0b100:
            case 0b101:
                cpuState.setRegisterValue("LR", cpuState.loadFromAddr(sp));
                sp += 4;
                cpuState.setRegisterValue("R12", cpuState.loadFromAddr(sp));
                sp += 4;
                cpuState.setRegisterValue("R11", cpuState.loadFromAddr(sp));
                sp += 4;
                cpuState.setRegisterValue("R10", cpuState.loadFromAddr(sp));
                sp += 4;
                cpuState.setRegisterValue("R9", cpuState.loadFromAddr(sp));
                sp += 4;
                cpuState.setRegisterValue("R8", cpuState.loadFromAddr(sp));
                sp += 4;
                break;
            default:
                break;
        }

        sr = cpuState.getRegisterValue("SR");
        sr &= ~(1 << 5);

        cpuState.setRegisterValue("SP", sp);
        cpuState.setRegisterValue("SR", sr);
        cpuState.finishFrame();
        context.interrupted = false;
        phaseManager.endInterrupt();
    }

    @PcodeUserop
    public void CheckAndRestoreSupervisor(@OpState PcodeExecutorState<byte[]> state) {
        Logger.printlnGlobal("CheckAndRestoreSupervisor", 4);
        int sr = cpuState.getRegisterValue("SR");
        int mode = (sr >> 22) & 0x7;
        int sp = cpuState.getRegisterValue("SP");
        switch (mode) {
            case 0b000:
                // Privilege Exception Violation

                // *(--SPSYS) = PC;
                // *(--SPSYS) = SR;
                // SR[R] = 0;
                // SR[J] = 0;
                // SR[M2:M0] = B’110;
                // SR[EM] = 1;
                // SR[GM] = 1;
                // PC = EVBA + 0x28;

                sp -= 4;
                cpuState.storeToAddr(sp, cpuState.getRegisterValue("PC"));
                sp -= 4;
                cpuState.storeToAddr(sp, cpuState.getRegisterValue("SR"));
                cpuState.setRegisterValue("SP", sp);

                sr = cpuState.getRegisterValue("SR");
                sr &= ~(1 << 15);
                sr &= ~(1 << 28);
                sr &= ~(0b111 << 22);
                sr |= 0b110 << 22;
                sr |= 1 << 21;
                sr |= 1 << 16;
                cpuState.setRegisterValue("SR", sr);

                Logger.printlnGlobal("privilege exception violation!!!!");
                int evba = cpuState.getRegisterValue("EVBA");
                cpuState.setRegisterValue("PC", evba + 0x28);
                // cpuState.setRegisterValue("PC", 0x8005ab20);

            break;
            case 0b001:
                int userAddr = taskManager.getUserAddr(context.currentTaskName);
                Logger.printlnGlobal(String.format("useraddr of %s: %s, sp: %s", context.currentTaskName, taskManager.getUserAddr(context.currentTaskName), sp), 6);
                context.userMode = userAddr == sp || userAddr + 0x0c == sp || userAddr + 0x18 == sp;
                cpuState.setRegisterValue("SR", cpuState.loadFromAddr(sp));
                sp += 4;
                cpuState.setRegisterValue("PC", cpuState.loadFromAddr(sp));
                sp += 4;
                cpuState.setRegisterValue("SP", sp);
                break;
            default:
                cpuState.setRegisterValue("PC", cpuState.getRegisterValue("LR"));
        }
        cpuState.finishFrame();
    }

    @PcodeUserop
    public void SupervisorCallSetup(@OpState PcodeExecutorState<byte[]> state) {
        Logger.printlnGlobal("SupervisorCallSetup", 4);
        
        int sr = cpuState.getRegisterValue("SR");
        int mode = (sr >> 22) & 0x7;
        Logger.printlnGlobal("mode: " + mode, 4);
        int evba = cpuState.getRegisterValue("EVBA");
        switch (mode) {
            case 0b000:
            case 0b001:
                // *(--SPSYS) ← PC + 2;
                // *(--SPSYS) ← SR;
                // PC ← EVBA + 0x100;
                // SR[M2:M0] ← B’001;

                int sp = cpuState.getRegisterValue("SP");
                sp -= 4;
                cpuState.storeToAddr(sp, cpuState.nextInstructionAddr(cpuState.getRegisterValue("PC")));
                sp -= 4;
                cpuState.storeToAddr(sp, sr);
                cpuState.setRegisterValue("SP", sp);
                
                if (context.userMode) {
                    taskManager.setUserAddr(context.currentTaskName, sp);
                    context.userMode = false;
                }

                sr &= ~(0b111 << 22);
                sr |= 0b001 << 22;
                cpuState.setRegisterValue("SR", sr);
                cpuState.setRegisterValue("PC", evba + 0x100);
                // cpuState.setRegisterValue("PC", 0x8005ab00);
                
                break;
                
            default:
                // LRCurrent Context ← PC + 2;
                // PC ← EVBA + 0x100;

                cpuState.setRegisterValue("LR", cpuState.nextInstructionAddr(cpuState.getRegisterValue("PC")));
                cpuState.setRegisterValue("PC", evba + 0x100);
                // cpuState.setRegisterValue("PC", 0x8005ab00);

                break;
        }
        cpuState.finishFrame();
    }

    @PcodeUserop
    public void doSleep(@OpState PcodeExecutorState<byte[]> state, int i) {
        // ETC.println("doSleep", 4);
    }

    @PcodeUserop
    public void CoprocessorOp(@OpState PcodeExecutorState<byte[]> state, int i1, int i2, int i3, int i4, int i5) {
        Logger.printlnGlobal("CoprocessorOp", 4);
    }
}

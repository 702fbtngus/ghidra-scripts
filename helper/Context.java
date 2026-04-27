package helper;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class Context {
    public SystemRegister systemRegister = new SystemRegister();
    public String currentFunctionName = "";
    public int instructionLimit = -1;
    public int interruptInstructionLimit = 100000;
    public boolean toMain = false;
    public PcodeThread<byte[]> currentThread;
    public Program currentProgram;
    public TaskMonitor monitor;
    public PcodeFrame currentFrame;
    public RFModuleSimulator rfModuleSimulator;

    public String currentTaskName = "";
    public int currentNumDelayedTasks = 0;
    public int currentNumSuspendedTasks = 0;
    public int currentSchedulerSuspended = 0;
    public final int[] currentNumReadyTasks = new int[5];
    public final int[] currentPxIndex = new int[5];
    public int currentTopReadyPriority = 0;

    public boolean interrupted = false;
    public boolean userMode = false;
    public int temp = 0;

    public String getCurrentFunctionName() {
        if (currentThread == null) return "null";
        
        Address counter = currentThread.getCounter();
        if (counter == null) return "null";

        Function func = currentProgram.getFunctionManager().getFunctionContaining(counter);
        if (func == null) return "null";

        return func.getName();
    }
}

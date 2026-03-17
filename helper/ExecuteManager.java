package helper;

import java.util.Arrays;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;

public final class ExecuteManager {

    private final DeviceManager deviceManager;
    private final Context context;
    private final CPUState cpuState;
    private final LogHelper logHelper;
    private final TaskManager taskManager;
    private final Logger logger;
    private final PhaseManager phaseManager;
    private final ProgramUtil programUtil;


    public ExecuteManager(DeviceManager deviceManager, Context context, CPUState cpuState, LogHelper logHelper, TaskManager taskManager, Logger logger, PhaseManager phaseManager, ProgramUtil programUtil) {
        this.deviceManager = deviceManager;
        this.context = context;
        this.cpuState = cpuState;
        this.logHelper = logHelper;
        this.taskManager = taskManager;
        this.logger = logger;
        this.phaseManager = phaseManager;
        this.programUtil = programUtil;
    }

    public void println(String s, int i) {
        logger.println(s, i);
    }

    public void println(String s) {
        println(s, 0);
    }

    public int hookMemoryAccess(long addr, PcodeOp op) {
        // long addr = addr.getOffset();
        boolean isStore = PcodeOp.getMnemonic(op.getOpcode()).equals("STORE");
        boolean isLoad = PcodeOp.getMnemonic(op.getOpcode()).equals("LOAD");
    
        if (addr >= 0xFFFD0000L && addr < 0xFFFF7400L) {
            if (isStore) {
                Integer res = deviceManager.storeToMmioDeviceAddr(addr, op.getInputs()[2]);
                if (res == null) {
                    logger.println("Store to unsupported mmiodevice @ " + addr, 2);
                    return -1;
                }
                return res;
            } else if (isLoad) {
                Integer res = deviceManager.loadFromMmioDeviceAddr(addr, op.getOutput());
                if (res == null) {
                    logger.println("Load from unsupported mmiodevice @ " + addr, 2);
                    return -1;
                }
                return res;
            }
            return -1;
        }
        if (isStore) {
            if (addr == 0x1398) {
                int currentTCB = cpuState.getRAMValue(0x1398);
                if (currentTCB != 0) {
                    String newTaskName = cpuState.readString(currentTCB + 0x34);
                    if (context.currentTaskName.compareTo(newTaskName) != 0) {
                        int currentTick = cpuState.getRAMValue(0x13a0);
                        logger.println(String.format("task switched: %s (current tickCount: %d)", newTaskName, currentTick), 6);
                        taskManager.switchTask(context.currentTaskName, newTaskName);
                        context.currentTaskName = newTaskName;
                    }
                }
                return 0;
            }
            for (int tcb: taskManager.getAllTCBs()) {
                if (addr == tcb + 0x2c) {
                    String taskName = cpuState.readString(tcb + 0x34);
                    int prio = cpuState.getRAMValue(tcb + 0x2c);
                    logger.println(String.format("addr: 0x%08X", addr), 6);
                    logger.println(String.format("Priority of %s changed to %d", taskName, prio), 6);
                    taskManager.changePrio(taskName, prio);
                    return 0;
                }
                if (addr == tcb + 0x4) {
                    // String taskName = readString(tcb + 0x34);
                    // int time = getRAMValue(tcb + 0x4);
                    // println("" + taskName + " delayed until " + time, 6);
                }
                if (addr == tcb + 0x14) {
                    String taskName = cpuState.readString(tcb + 0x34);
                    int container = cpuState.getRAMValue(tcb + 0x14);
                    // int delayedTaskList = getRAMValue(0x1344);
                    switch (container) {
                        case 0x0:
                            break;
                        case 0x13e8:
                        case 0x13fc:
                        case 0x1410:
                        case 0x1424:
                        case 0x1438:
                            int priority = (container - 0x13e8) / 0x14;
                            logger.println(String.format("State of %s: ready (priority: %d)", taskName, priority), 6);
                            taskManager.readyTask(taskName, priority);
                            break;
                        case 0x1470:
                            int time = cpuState.getRAMValue(tcb + 0x4);
                            logger.println(String.format("State of %s: delayed until 0x%08X", taskName, time), 6);
                            taskManager.delayTask(taskName, time);
                            break;
                        case 0x13bc:
                            logger.println("State of " + taskName + ": suspended", 6);
                            taskManager.suspendTask(taskName);
                            break;
                        case 0x13d0:
                            logger.println("State of " + taskName + ": waiting termination", 6);
                            taskManager.terminateTask(taskName);
                            break;
                        default:
                            logger.println(String.format("Container of %s changed to 0x%08X", taskName, container), 6);
                            break;
                    }
                }
                // if (a == tcb + 0x18) {
                //     String taskName = readString(tcb + 0x34);
                //     logger.println("" + taskName + " suspended", 6);
                // }
            }
        }
        return 0;
    }

    public int hookSystemRegisterAccess(Varnode node, PcodeOp op) {

        long a = node.getOffset();
        String mn = PcodeOp.getMnemonic(op.getOpcode());
        boolean isCopy = mn.equals("COPY");

        if (isCopy && a <= 1020 && node.isRegister()) {
            Integer value = null;
            if (a == 0) {
                value = cpuState.getRegisterValue("SR");
            } else {
                value = context.systemRegister.onRead((int) a);
            }
            
            if (value != null) {
                logHelper.printAllRegisters();
                Varnode output = op.getOutput();
                Integer valueBefore = cpuState.getVar(output);
                cpuState.setVar(output, value);
                logger.println(String.format(
                    "Overwrote system register @ 0x%02X: 0x%02X -> 0x%02X",
                    a,
                    valueBefore,
                    value
                ), 3);
                logHelper.printAllRegisters();
            } else {
                logger.println(String.format("Copy from unsupported system register @ 0x%02X", a));
                return -1;
            }
        }
        return 0;
    }


    public boolean isFirstAddrInBlock(Address addr) {
        BasicBlockModel bbModel = new BasicBlockModel(context.currentProgram);
        CodeBlock startBlock;
        try {
            startBlock = bbModel.getFirstCodeBlockContaining(addr, context.monitor);
        } catch (CancelledException e) {
            return false;
        }
        long of1 = startBlock.getFirstStartAddress().getOffset();
        long of2 = addr.getOffset();
        return of1 == of2;
    }

        public void adjustPhaseInstructionCount(Instruction instr, Address addr) {
        if (
            (
                instr.getMnemonicString().endsWith("SRF")
                && !isFirstAddrInBlock(addr)
                && !instr.getPrevious().getMnemonicString().equals("MFSR")
                && !instr.getPrevious().getMnemonicString().equals("MTSR")
                && !instr.getPrevious().getMnemonicString().equals("STDSP")
            ) || context.interrupted
        ) {
            // println("adjusted", 1);
            phaseManager.decrementPhaseInstructionCount();
        }
    }

    public void beforeInstr() throws AddressFormatException {
        PcodeThread<byte[]> thread = context.currentThread;
        Address addr = thread.getCounter();
        
        if (addr.getOffset() == 0x8003bb88l) {
            // Entered _vfprintf_r
            println("_vfprintf_r called");
            cpuState.setCounter(cpuState.getRegisterValue("LR"));
            context.currentFrame.finishAsBranch();
        }

        if (addr.getOffset() == 0x80029ab0l) {
            // Entered gs_i2c_master_transaction
            println("gs_i2c_master_transaction called", 2);
            int tx = cpuState.getRegisterValue("R10");
            int txlen = cpuState.getRegisterValue("R9");
            println(String.format("tx: 0x%X", tx), 2);
            println(String.format("*tx: 0x%X", cpuState.getRAMValue(tx)), 2);
            println(String.format("txlen: %d", txlen), 2);
        }
    }

    public int executeInstr() throws AddressFormatException {
        PcodeThread<byte[]> thread = context.currentThread;
        Address addr = thread.getCounter();
        Instruction instr = programUtil.getInstructionAt(addr);
        boolean detail = logHelper.isDetail(addr);

        if (detail) {
            logHelper.printAllRegisters();
        }

        int old_sp = cpuState.getRegisterValue("SP");

        taskManager.monitorTasks(addr);
        
        println("PC = " + thread.getCounter(), 1);

        adjustPhaseInstructionCount(instr, addr);

        beforeInstr();

        if (logHelper.isInterestingInstr(instr, addr)) {
            thread.stepPcodeOp();
            PcodeFrame frame = thread.getFrame();
            if (frame != null) {
                context.currentFrame = frame;
                var ops = frame.getCode();
                println("Executing frame of size " + ops.size());

                // Fixed in local Ghidra
                // if (mn.startsWith("ST.B")) {
                //     // ops
                //     PcodeExecutorState<byte[]> state = thread.getState();
                //     Varnode rd = ops.get(1).getInput(0);
                //     Varnode res = ops.get(1).getOutput();
                //     byte[] rdb = thread.getState().getVar(rd, Reason.INSPECT);
                //     Integer rdv = helper.byteArrayToInt(rdb);
                //     byte[] resb = state.getVar(res, Reason.INSPECT);
                //     Integer resv = helper.byteArrayToInt(resb);
                //     if (rdv >= 0 && resv < 0) {
                //         setRegisterValue(state, "C", 1);
                //     }
                // }

                while (!frame.isFinished()) {
                    int id = frame.index();
                    PcodeOp op = ops.get(id);
                    boolean interesting = logHelper.isInterestingPcodeOp(op, addr);
                    if (interesting) {
                        logHelper.printCurrentPcodeOp(thread);
                    }
                    Varnode[] inputs = op.getInputs();
                    Varnode output = op.getOutput();
                    thread.stepPcodeOp();
                    
                    // Fixed in local Ghidra
                    // if (mn.equals("CPC") && id == 6 && instr.getNumOperands() == 1) {
                    //     PcodeExecutorState<byte[]> state = thread.getState();
                    //     Varnode rd = ops.get(1).getInput(0);
                    //     Varnode res = ops.get(1).getOutput();
                    //     byte[] rdb = thread.getState().getVar(rd, Reason.INSPECT);
                    //     Integer rdv = helper.byteArrayToInt(rdb);
                    //     byte[] resb = state.getVar(res, Reason.INSPECT);
                    //     Integer resv = helper.byteArrayToInt(resb);
                    //     if (rdv >= 0 && resv < 0) {
                    //         setRegisterValue(state, "C", 1);
                    //     }
                    // }

                    if (interesting) {
                        int[] result = null;
                        if (inputs.length > 0) {
                            result = Arrays.stream(inputs)
                            .mapToInt(cpuState::getVar)
                            .toArray();
                            
                            for (int j = 0; (j < result.length); j++) {
                                int b = result[j];
                                println(String.format("Input %d: 0x%08X", j, b));
                            }
                        }

                        if (result != null && result.length > 1) {
                            if (hookMemoryAccess(programUtil.toAddr(result[1]).getOffset(), op) == -1) {
                                return -1;
                            }
                        }

                        for (Varnode input : inputs) {
                            if (hookSystemRegisterAccess(input, op) == -1) {
                                return -1;
                            }
                        }
                        
                        if (output != null) {
                            var outputv = cpuState.getVar(output);
                            println(String.format("Output: 0x%08X", outputv));
                            if (output.isRegister() && output.getOffset() == 0x103c) {
                                cpuState.setRegisterValue("PC", outputv);
                            }
                        }
                    }
                }
                thread.stepPcodeOp();
            }
        } else {
            thread.stepInstruction();
        }
        int sp = cpuState.getRegisterValue("SP");
        if (sp != old_sp) {
            logHelper.printStack();
        }
        logHelper.printOutputRegisters(thread, addr);
        return 0;
    }
}

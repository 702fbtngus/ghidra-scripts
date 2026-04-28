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
    private final DynamicFlowTracker dynamicFlowTracker;


    public ExecuteManager(DeviceManager deviceManager, Context context, CPUState cpuState, LogHelper logHelper, TaskManager taskManager, Logger logger, PhaseManager phaseManager, ProgramUtil programUtil) {
        this.deviceManager = deviceManager;
        this.context = context;
        this.cpuState = cpuState;
        this.logHelper = logHelper;
        this.taskManager = taskManager;
        this.logger = logger;
        this.phaseManager = phaseManager;
        this.programUtil = programUtil;
        this.dynamicFlowTracker = new DynamicFlowTracker(context, logger);
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
                    String taskName = taskManager.getTaskNameByTCB(tcb);
                    int oldPrio = taskName != null ? taskManager.getPriority(taskName) : -1;
                    int newPrio = cpuState.getRAMValue(tcb + 0x2c);
                    if (taskName == null) {
                        taskName = cpuState.readString(tcb + 0x34);
                    }
                    logger.println(String.format("addr: 0x%08X", addr), 6);
                    logger.println(String.format("Priority of %s changed: %d -> %d", taskName, oldPrio, newPrio), 6);
                    taskManager.changePrio(taskName, newPrio);
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
            instr.getMnemonicString().endsWith("SRF")
            && !isFirstAddrInBlock(addr)
            && !instr.getPrevious().getMnemonicString().equals("MFSR")
            && !instr.getPrevious().getMnemonicString().equals("MTSR")
            && !instr.getPrevious().getMnemonicString().equals("STDSP")
        ) {
            phaseManager.decrementInstructionCount(context.currentTaskName);
        }
    }

    public boolean beforeInstr() throws AddressFormatException {
        boolean branchHandledManually = false;

        // Firmware dependent hooks
        PcodeThread<byte[]> thread = context.currentThread;
        Address addr = thread.getCounter();
        
        switch ((int) addr.getOffset()) {
            case 0x8003bb88:
                // Entered _vfprintf_r
                println("_vfprintf_r called");
                cpuState.setCounter(cpuState.getRegisterValue("LR"));
                context.currentFrame.finishAsBranch();
                break;

            case 0x800125b8: {
                // clyde_eps_get_status calling clyde_eps_cmd
                println("clyde_eps_get_status called");
                // set delay to 0
                cpuState.setRegisterValue("R12", 0);
                break;
            }

            case 0x80029ab0:
                // Entered gs_i2c_master_transaction
                println("gs_i2c_master_transaction called", 2);
                int tx = cpuState.getRegisterValue("R10");
                int txlen = cpuState.getRegisterValue("R9");
                println(String.format("tx: 0x%X", tx), 2);
                println(String.format("*tx: 0x%X", cpuState.getRAMValue(tx)), 2);
                println(String.format("txlen: %d", txlen), 2);
                break;
            case 0x80029ae0: {
                // Exiting gs_i2c_master_transaction
                println("gs_i2c_master_transaction exiting", 2);
                int res = cpuState.getRegisterValue("R12");
                println(String.format("res: 0x%X", res), 2);
                // println(String.format("res: %s", cpuState.getRAMValues(res, 10)), 2);
                break;
            }
                
            case 0x8002dd1e: {
                // Exiting twim_pdc_transfer
                println("twim_pdc_transfer exiting", 2);
                int res = cpuState.getRegisterValue("R12");
                println(String.format("res: 0x%X", res), 2);
                break;
            }
                
            case 0x8002f92c: {
                // Entered xTaskIncrementTick
                println("xTaskIncrementTick called", 2);
                int xTickCount = cpuState.getRegisterValue("R4");
                // Manually increment tick count to speed up emulation
                cpuState.setRegisterValue("R4", xTickCount + 0xf0);
                break;
            }
        
            case 0x80016cbc: {
                int r4 = cpuState.getRegisterValue("R4");
                println("r4 = 0x" + Integer.toHexString(r4), -1);
                int r5 = cpuState.getRegisterValue("R5");
                println("r5 = 0x" + Integer.toHexString(r5), -1);
                int r6 = cpuState.getRegisterValue("R6");
                println("r6 = 0x" + Integer.toHexString(r6), -1);
                break;
            }
        
            case 0x8001d0e0: {
                // memcpy before
                int r11 = cpuState.getRegisterValue("R11");
                println("r11 = 0x" + Integer.toHexString(r11), -1);
                println(String.format("res: %s", cpuState.getRAMValues(r11, 10)), 2);
                break;
            }

            case 0x8001d0e4: {
                // vrx_get_frame done
                int r7 = cpuState.getRegisterValue("R7");
                println("r7 = 0x" + Integer.toHexString(r7), -1);
                println(String.format("rx_length: 0x%X", cpuState.getRAMValue(r7, 2)), -1);
                println(String.format("doppler_freq: 0x%X", cpuState.getRAMValue(r7 + 2, 2)), -1);
                println(String.format("sig_strength: 0x%X", cpuState.getRAMValue(r7 + 4, 2)), -1);
                println(String.format("rx_content: %s", cpuState.getRAMValues(r7 + 6, 10)), 2);
                break;
            }

            case 0x8003769a: {
                // memset begin
                println("memset begin", -1);
                int r10 = cpuState.getRegisterValue("R10");
                println("n = 0x" + Integer.toHexString(r10), -1);
                break;
            }
        
            case 0x80005b28: {
                // memcpy begin
                println("memcpy begin", -1);
                int r10 = cpuState.getRegisterValue("R10");
                println("n = 0x" + Integer.toHexString(r10), -1);
                break;
            }
        
            // case 0x8002f44e: {
            //     // timeout occurred
            //     int numOfOverflows = cpuState.getRegisterValue("R12");
            //     int overflowCount = cpuState.getRegisterValue("R11");
            //     println("numOfOverflows = 0x" + Integer.toHexString(numOfOverflows), 1);
            //     println("overflowCount = 0x" + Integer.toHexString(overflowCount), 1);
            //     break;
            // }
            // case 0x8002f456: {
            //     // timeout occurred
            //     int xTickCount = cpuState.getRegisterValue("R10");
            //     int xTimeonEntering = cpuState.getRegisterValue("R9");
            //     int r8 = cpuState.getRegisterValue("R8");
            //     println("xTickCount = 0x" + Integer.toHexString(xTickCount), 1);
            //     println("xTimeonEntering = 0x" + Integer.toHexString(xTimeonEntering), 1);
            //     println("r8 = 0x" + Integer.toHexString(r8), 1);
            //     break;
            // }
            // case 0x8002f474: {
            //     // timeout occurred
            //     int r9 = cpuState.getRegisterValue("R9");
            //     println("xTickCount - pxTimeOut->xTimeOnEntering = 0x" + Integer.toHexString(r9), 1);
            //     break;
            // }
            case 0x8001d2d4: {
                // memset after vrx_get_uptime
                int r12 = cpuState.getRegisterValue("R12");
                int r11 = cpuState.getRegisterValue("R11");
                int r10 = cpuState.getRegisterValue("R10");
                println("cmd_result[2] = 0x" + Integer.toHexString(r12), -1);
                println("uptime_data = 0x" + Integer.toHexString(r11), -1);
                println("sizeof(uptime_data) = 0x" + Integer.toHexString(r10), -1);
                break;
            }
            case 0x8001d2d8: {
                // memset finished
                println("*cmd_result = 0x" + Integer.toHexString(cpuState.getRAMValue(0x9eb0)), -1);
                println("*cmd_result + 4 = 0x" + Integer.toHexString(cpuState.getRAMValue(0x9eb4)), -1);
                break;
            }
            case 0x800171d6: {
                // utx_send_frame
                int r12 = cpuState.getRegisterValue("R12");
                int r11 = cpuState.getRegisterValue("R11");
                // cmd_result, sizeof(cmd_result)
                println("cmd_result = 0x" + Integer.toHexString(r12), -1);
                println("sizeof(cmd_result) = 0x" + Integer.toHexString(r11), -1);
                println("*cmd_result = 0x" + Integer.toHexString(cpuState.getRAMValue(r12)), -1);
                println("*cmd_result + 4 = 0x" + Integer.toHexString(cpuState.getRAMValue(r12 + 4)), -1);
                break;
            }
            case 0x800171a8: {
                // after memset
                int sp = cpuState.getRegisterValue("SP");
                println("*SP[0x1f2] = 0x" + Integer.toHexString(cpuState.getRAMValue(sp + 0x1f2)), -1);
                println("*SP[0x1f3] = 0x" + Integer.toHexString(cpuState.getRAMValue(sp + 0x1f3)), -1);
                println("*SP[0x1f4] = 0x" + Integer.toHexString(cpuState.getRAMValue(sp + 0x1f4)), -1);
                println("*SP[0x1f5] = 0x" + Integer.toHexString(cpuState.getRAMValue(sp + 0x1f5)), -1);
                break;
            }
                
                default:
                break;
        }

        return branchHandledManually;
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
        
        println("" + phaseManager.getTotalInstructionCount(), 1);

        adjustPhaseInstructionCount(instr, addr);

        beforeInstr();
        PcodeFrame frame = thread.getFrame();
        // if (frame != null && frame.isFinished()) {
        //         thread.stepPcodeOp();
        //         return 0;
        //     }
            
        if (logHelper.isInterestingInstr(instr, addr)) {
            thread.stepPcodeOp();
            frame = thread.getFrame();
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
        dynamicFlowTracker.recordComputedFlow(instr, thread.getCounter());
        int sp = cpuState.getRegisterValue("SP");
        if (sp != old_sp) {
            logHelper.printStack();
        }
        logHelper.printOutputRegisters(thread, addr);
        return 0;
    }

    public void close() {
        dynamicFlowTracker.close();
    }
}

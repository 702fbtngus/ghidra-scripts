//TODO write a description for this script
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import ghidra.app.emulator.AdaptedEmulator;
import ghidra.app.emulator.EmulatorConfiguration;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.program.model.listing.Program;
import ghidra.pcode.emu.AbstractPcodeMachine;
import hw.*;
import helper.*;
import helper.PhaseManager.Phase;

public class CubeSatEmulator extends GhidraScript {

    // public static long INTERESTING_ADDR = 0x8005ab42L;
    // public static long INTERESTING_ADDR = 0x8002c5a4l;
    public static long INTERESTING_ADDR = 0x8002c634l;
    public static int DETAIL_UNTIL = 600000;
    // public static int DETAIL_FROM = 66400;
    public static int DETAIL_FROM = DETAIL_UNTIL + 1;
    public static String[] PW_FILENAMES = {
        "main.log",
        "instr.log",
        "device.log",
        "sysreg.log",
        "userop.log",
        "storeload.log",
        "thread.log",
        "tasks.log",
        "temp.log",
    };

    // Helpers and managers
    public final ProgramUtil programUtil = new ProgramUtil(this);
    public final Context context = new Context();
    public final CPUState cpuState = new CPUState(programUtil, context, (s, i) -> println(s, i));
    public final PhaseManager phaseManager = new PhaseManager();
    public final TaskManager taskManager = new TaskManager(context, cpuState);
    public final InterruptManager interruptManager = new InterruptManager(context, cpuState, taskManager);
    public ExecuteManager executeManager;
    public Logger logger;
    public LogHelper logHelper;
    public boolean exitCondition() {
        Phase phase = phaseManager.getCurrentPhase();
        return (
            // (currentPhase == 28)
            false
            || (context.instructionLimit >= 0 && phaseManager.getTotalInstructionCount() >= context.instructionLimit)
            || (phase.getPhaseNumber() == 28 && phase.getPhaseInstructionCount() > 2000000)
            // || (currentPhase == 1)
        );
    }
    public final DeviceManager deviceManager = new DeviceManager(cpuState);

    // Devices
    public TC tc0;
    public TC tc1;

    public void parseScriptArgs() {
        for (String arg : getScriptArgs()) {
            if (arg.equals("--to-main")) {
                context.toMain = true;
                continue;
            }

            if (arg.startsWith("--num-instr=")) {
                String value = arg.substring("--num-instr=".length());
                try {
                    context.instructionLimit = Integer.parseInt(value);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid --num-instr value: " + value, e);
                }

                if (context.instructionLimit < 0) {
                    throw new IllegalArgumentException("--num-instr must be non-negative");
                }

                continue;
            }
        }
    }

    public void initializeHelpers() throws Exception {

        // Initialize LogHelper and Logger
        logHelper = new LogHelper(
            cpuState,
            phaseManager,
            programUtil,
            () -> INTERESTING_ADDR,
            () -> DETAIL_FROM,
            () -> DETAIL_UNTIL
        );

        logger = new Logger(
            getSourceFile().getParentFile().getAbsolutePath(),
            PW_FILENAMES,
            logHelper::printerMask,
            () -> phaseManager.getCurrentPhase().toString(),
            () -> context.currentTaskName,
            deviceManager::getCurrentDeviceName,
            () -> context.interrupted,
            () -> context.userMode,
            () -> context.toMain,
            1000000
        );
        logger.initialize();
        Logger.setActiveLogger(logger);
        logHelper.setLogger(logger);

        // Initialize taskManager
        java.util.function.Supplier<Integer> getCurrentTick = () -> {
            return cpuState.getRAMValue(0x13a0);
        };
        taskManager.getCurrentTick = getCurrentTick;
        java.util.function.Supplier<String> getCurrentInstr = () -> {
            return phaseManager.getCurrentPhase().toShortString();
        };
        taskManager.getCurrentInstr = getCurrentInstr;
        taskManager.logger = logger;

        // Initialize DeviceManager
        deviceManager.initializeDevices();
        deviceManager.linkAllDevices();
        
        // Initialize InterruptManager
        interruptManager.intc = (INTC) deviceManager.findDevice("INTC");;

        // Initialize Context
        context.currentProgram = currentProgram;
        context.monitor = monitor;
        context.rfModuleSimulator = new RFModuleSimulator(deviceManager);

        // Initialize ExecuteManager
        executeManager = new ExecuteManager(deviceManager, context, cpuState,
            logHelper, taskManager, logger, phaseManager, programUtil);
    }

    public void println(String s, int i) {
        logger.println(s, i);
    }

    @Override
    public void println(String s) {
        println(s, 0);
    }

    public PcodeEmulator getInternalPcodeEmulator(Program program) throws Exception {
        // 1️⃣ 준비: EmulatorConfiguration 구현체 (EmulatorHelper 사용)
        EmulatorHelper emu = new EmulatorHelper(program);

        // 2️⃣ AdaptedEmulator 인스턴스 생성
        AdaptedEmulator adapted = new AdaptedEmulator(emu);
        
        // 3️⃣ protected 메서드 newPcodeEmulator(EmulatorConfiguration) 반사 호출
        Method m = AdaptedEmulator.class.getDeclaredMethod("newPcodeEmulator", EmulatorConfiguration.class);
        m.setAccessible(true);
        
        // 4️⃣ 호출 — 결과는 AdaptedPcodeEmulator (내부 클래스, PcodeEmulator 상속)
        Object inner = m.invoke(adapted, emu);
        
        if (!(inner instanceof PcodeEmulator)) {
            throw new IllegalStateException("Result is not a PcodeEmulator: " + inner.getClass());
        }
        PcodeEmulator pcemu = (PcodeEmulator) inner;

        Field library = AbstractPcodeMachine.class.getDeclaredField("library");
        library.setAccessible(true);
        library.set(inner, new UseropLibrary(context, cpuState, taskManager));

        return pcemu;
    }

    @Override
    protected void run() throws Exception {
        parseScriptArgs();
        initializeHelpers();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.dumpAndFlush();
        }));

        PcodeEmulator emu = getInternalPcodeEmulator(currentProgram);
        println("Got internal PcodeEmulator: " + emu.getClass().getName());

        tc0 = (TC) deviceManager.findDevice("TC0");
        tc1 = (TC) deviceManager.findDevice("TC1");
        
        tc0.startClockThread();
        tc1.startClockThread();

        var thread = emu.newThread("main");
        context.currentThread = thread;
        thread.overrideCounter(toAddr(0x80000000));
        phaseManager.startPhase(context.getCurrentFunctionName());
        cpuState.setVar("register", 0x0L, 0x610000);

        while (true) {
            phaseManager.updatePhase(thread.getCounter().getOffset(), context.getCurrentFunctionName());
            Phase phase = phaseManager.getCurrentPhase();
            if (phase.getPhaseInstructionCount() % 10000 == 0) {
                System.err.println(String.format("%s: PC = %s (%s %s)", phase, thread.getCounter(), context.interrupted, context.currentTaskName));
            }
            // int sp = getRegisterValue("SP");
            // helper.println("sp: " + helper.intToHex(sp), 1);
            // int n = getRAMValue(0x9d88);
            // if (temp != n) {
            //     helper.println(String.format("*0x9D88: %x", n), 1);
            //     temp = n;
            // }
            if (executeManager.executeInstr() == -1) {
                return;
            }
            phaseManager.incrementPhaseInstructionCount();
            interruptManager.handleInterrupt();
            if (exitCondition()) {
                tc0.exitClockThread();
                tc1.exitClockThread();
                logger.flush();
                return;
            }
        }
    }
}

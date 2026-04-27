package helper;

import java.util.function.IntSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import helper.PhaseManager.Phase;

public final class LogHelper {
    private final CPUState cpuStateManager;
    private final PhaseManager phaseManager;
    private final ProgramUtil programUtil;
    private Logger logger;
    private final LongSupplier interestingAddrSupplier;
    private final IntSupplier detailFromSupplier;
    private final IntSupplier detailUntilSupplier;
    private final Supplier<String> currentTaskNameSupplier;

    public LogHelper(
        CPUState cpuState,
        PhaseManager phaseManager,
        ProgramUtil programUtil,
        LongSupplier interestingAddrSupplier,
        IntSupplier detailFromSupplier,
        IntSupplier detailUntilSupplier,
        Supplier<String> currentTaskNameSupplier
    ) {
        this.cpuStateManager = cpuState;
        this.phaseManager = phaseManager;
        this.programUtil = programUtil;
        this.interestingAddrSupplier = interestingAddrSupplier;
        this.detailFromSupplier = detailFromSupplier;
        this.detailUntilSupplier = detailUntilSupplier;
        this.currentTaskNameSupplier = currentTaskNameSupplier;
    }

    public void setLogger(Logger logger) {
        this.logger = logger;
    }

    public boolean isDetail(Address addr) {
        Phase phase = phaseManager.getTaskPhase(currentTaskNameSupplier.get());
        return phase.getPhaseInstructionCount() > detailFromSupplier.getAsInt()
            && phase.getPhaseInstructionCount() < detailUntilSupplier.getAsInt();
    }

    public boolean printerMask(int i) {
        Phase phase = phaseManager.getTaskPhase(currentTaskNameSupplier.get());
        // return !"-25".equals(phase.getPhaseCode()) || i == 6 || i == 7;
        return true;
    }

    public void printPcodeOps(PcodeOp[] ops) {
        for (int i = 0; i < ops.length; i++) {
            logger.println(String.format("PcodeOp[%d] = %s", i, ops[i]), -1);
        }
    }

    public void printCurrentPcodeOp(PcodeThread<byte[]> thread) {
        var frame = thread.getFrame();
        if (frame == null) {
            return;
        }

        var ops = frame.getCode();
        int opIndex = frame.index();
        if (0 <= opIndex && opIndex < ops.size()) {
            logger.println(String.format("PcodeOp[%d] = %s", opIndex, ops.get(opIndex)));
            return;
        }
        logger.println(String.format("Index %d out of range (len=%d)", opIndex, ops.size()));
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public boolean isInterestingInstr(Instruction instr, Address addr) {
        String mn = instr.getMnemonicString();
        return interestingAddrSupplier.getAsLong() == addr.getOffset()
            || mn.startsWith("ST")
            || mn.startsWith("LD")
            || mn.startsWith("MFSR")
            || mn.startsWith("RETS")
            || mn.startsWith("RETE")
            || mn.startsWith("CPC")
            || mn.startsWith("BR")
            || mn.startsWith("CSRF")
            || mn.startsWith("SLEEP")
            || mn.startsWith("MOV");
    }

    public boolean isInterestingPcodeOp(PcodeOp op, Address addr) {
        String mn = PcodeOp.getMnemonic(op.getOpcode());
        return interestingAddrSupplier.getAsLong() == addr.getOffset()
            || mn.equals("STORE")
            || mn.equals("LOAD")
            || mn.equals("COPY");
    }

    public boolean isIgnoredFunction(Function func) {
        String fn = func.getName();
        return fn.startsWith("wdt")
            || fn.startsWith("sysclk")
            || fn.startsWith("gpio")
            || fn.startsWith("sdramc");
    }

    public void printOutputRegisters(PcodeThread<byte[]> thread, Address addr) {
        Instruction instr = programUtil.getInstructionAt(addr);
        Object[] outputs = instr.getResultObjects();

        logger.println(">>> Output Registers:");
        for (Object output : outputs) {
            if (output instanceof Register reg) {
                byte[] value = thread.getState().getVar(reg, Reason.INSPECT);
                logger.println(String.format("  %s (%s) = %s", reg.getName(), reg.getAddress(), bytesToHex(value)));
            }
        }
    }

    public void printInputRegisters(PcodeThread<byte[]> thread, Address addr) {
        Instruction instr = programUtil.getInstructionAt(addr);
        Object[] inputs = instr.getInputObjects();

        logger.println(">>> Input Registers:");
        for (Object input : inputs) {
            if (input instanceof Register reg) {
                byte[] value = thread.getState().getVar(reg, Reason.INSPECT);
                logger.println("  " + reg.getName() + " = " + bytesToHex(value));
            }
        }
    }

    public void printAllRegisters() {
        logger.println(">>> All Registers:");
        for (CPUState.RegisterName rn : CPUState.RegisterName.values()) {
            int value = cpuStateManager.getRegisterValue(rn.name());
            logger.println(String.format("  %s (0x%08X) = 0x%08X", rn.name(), rn.memoryAddress(), value));
        }
    }

    public void printStack() {
        logger.println(">>> Stack:");
        int sp = cpuStateManager.getRegisterValue("SP");
        for (int i = 0; i < 8; i++) {
            int addr = sp + 4 * i;
            logger.println(String.format(
                "  *0x%08X = 0x%08X",
                addr,
                cpuStateManager.getRAMValue(addr)
            ));
        }
    }
}

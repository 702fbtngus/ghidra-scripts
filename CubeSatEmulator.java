//TODO write a description for this script
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.function.BiFunction;

import ghidra.app.emulator.AdaptedEmulator;
import ghidra.app.emulator.EmulatorConfiguration;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import etc.LogBuffer;
import etc.Util;
import ghidra.pcode.emu.AbstractPcodeMachine;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import hw.*;

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
        "temp.log",
    };

    public SystemRegister system_register;
    public String currentFunctionName = "";
    public int currentInstructionCount = 0;
    public int currentPhase = 0;    
    public PrintWriter[] pw;
    public PcodeThread<byte[]> currentThread = null;
    public PcodeFrame currentFrame = null;
    public INTC intc;
    public TC tc0;
    public TC tc1;

    public String currentTaskName = "";

    public boolean interrupted = false;
    
    public LogBuffer log_buffer;
    
    public static java.util.function.Function<String, Void> println;

    public boolean isDetail(Address addr) {
        return (
            (currentInstructionCount > DETAIL_FROM
            && currentInstructionCount < DETAIL_UNTIL)
        );
    }

    public boolean printerMask(int i) {
        return (
            // true
            (currentPhase != 25)
            // && (
            //     (currentPhase == 27)
            //     || (currentThread != null && currentThread.getCounter() != null && (currentThread.getCounter().getOffset() == 0x8002f97al || currentThread.getCounter().getOffset() == 0x8002c634l))
            //     // || i == 2 || i == 1 || i == 0
            // )
            // || (currentPhase == 0 && i == 2)
            // || (currentPhase == 1 && (currentInstructionCount > 500000 || currentInstructionCount < 10000))
            // || (currentInstructionCount > 900000)
        );
    }

    public boolean exitCondition() {
        return (
            (currentPhase == 28)
            // || (currentPhase == 0 && currentInstructionCount > 200000)
            // || (currentPhase == 1)
        );
    }
        
    public String getCurrentFunctionName() {
        if (currentThread == null) return "null";
        
        Address counter = currentThread.getCounter();
        if (counter == null) return "null";

        Function func = currentProgram.getFunctionManager().getFunctionContaining(counter);
        if (func == null) return "null";

        return func.getName();
    }

    public void print_inner(String s, int i) {
        if (printerMask(i)) {
            if (i > 0 && pw.length > i) {
                pw[i].println(s);
            } else if (i == -1) {
                pw[pw.length - 1].println(s);
            } else if (i == 0) {
                log_buffer.println(s);
            }
        }
    }

    public void println(String s, int i) {
        String funcname = getCurrentFunctionName();
        String s1 = s + " (P" + currentPhase + " #" + currentInstructionCount + ", " + funcname + ")";
        if (i != 0) {
            print_inner(s1, i);
        }
        print_inner(s, 0);
    }

    @Override
    public void println(String s) {
        println(s, 0);
    }


    public enum RegisterName {
        SR   (0x0000l, 4),
        EVBA (0x0004l, 4),
        R0   (0x1000l, 4),
        C    (0x1100l, 1),
        Z    (0x1101l, 1),
        N    (0x1102l, 1),
        V    (0x1103l, 1),
        R1   (0x1004l, 4),
        R2   (0x1008l, 4),
        R3   (0x100cl, 4),
        R4   (0x1010l, 4),
        R5   (0x1014l, 4),
        R6   (0x1018l, 4),
        R7   (0x101cl, 4),
        R8   (0x1020l, 4),
        R9   (0x1024l, 4),
        R10  (0x1028l, 4),
        R11  (0x102cl, 4),
        R12  (0x1030l, 4),
        SP   (0x1034l, 4),
        LR   (0x1038l, 4),
        PC   (0x103cl, 4);
    
        private final long memoryAddress;
        private final int numBytes;
    
        RegisterName (long memoryAddress, int numBytes) {
            this.memoryAddress = memoryAddress;
            this.numBytes = numBytes;
        }
    
        public long memoryAddress() {
            return memoryAddress;
        }
    
        public int numBytes() {
            return numBytes;
        }
    
        public static RegisterName fromMnemonic(String mnemonic) {
            return RegisterName.valueOf(mnemonic);
        }
    }

    public int loadFromAddr(PcodeExecutorState<byte[]> state, int addr) {
        int result = Util.getVar(addr);
        println(String.format("[loadFromAddr] *0x%08X = %d (0x%08X)", addr, result, result), 5);
        return result;
    }


    public void storeToAddr(PcodeExecutorState<byte[]> state, int addr, int value) {
        println(String.format("[storeToAddr] *0x%08X <- %d (0x%08X)", addr, value, value), 5);
        Util.setVar(addr, value);
    }

    public int getRegisterValue(PcodeExecutorState<byte[]> state, String name) {
        RegisterName regname = RegisterName.fromMnemonic(name);
        long regaddr = regname.memoryAddress();
        int numbytes = regname.numBytes();
        return Util.getVar("register", regaddr, numbytes);
    }

    public int getRAMValue(PcodeExecutorState<byte[]> state, int offset) {
        return Util.getVar("RAM", offset);
    }

    public String readString(PcodeExecutorState<byte[]> state, int offset) {
        String s = "";
        while (true) {
            int c = Util.getVar("RAM", offset, 1);
            if (c == 0) break;
            offset += 1;
            s += (char) c;
        }
        return s;
    }

    public void finishFrame(PcodeExecutorState<byte[]> state) {
        currentThread.setCounter(toAddr(getRegisterValue(state, "PC")));
        currentFrame.finishAsBranch();
    }

    public void setRegisterValue(PcodeExecutorState<byte[]> state, String name, int value) {
        RegisterName regname = RegisterName.fromMnemonic(name);
        long regaddr = regname.memoryAddress();
        int numbytes = regname.numBytes();
        Util.setVar("register", regaddr, numbytes, value);
        if (name == "SR") {
            setRegisterValue(state, "C", value >> 0 & 1);
            setRegisterValue(state, "Z", value >> 1 & 1);
            setRegisterValue(state, "N", value >> 2 & 1);
            setRegisterValue(state, "V", value >> 3 & 1);
        }
    }

    public int nextInstructionAddr(int addr) {
        return ((int) getInstructionAfter(toAddr(addr)).getAddress().getOffset());
    }

    public void callInterruptWrapper(PcodeExecutorState<byte[]> state, int i) {
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
        
        println("callInterruptWrapper " + i);
        interrupted = true;
        int sp = getRegisterValue(state, "SP");

        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "R8"));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "R9"));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "R10"));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "R11"));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "R12"));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "LR"));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "PC"));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "SR"));

        setRegisterValue(state, "SP", sp);

        int sr = getRegisterValue(state, "SR");
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

        setRegisterValue(state, "SR", sr);

        setRegisterValue(state, "PC", 0x8005ab20);
        finishFrame(state);
    }

    public class MyUseropLibrary extends AnnotatedPcodeUseropLibrary<byte[]> {

        @PcodeUserop
        public void CheckAndRestoreInterupt(@OpState PcodeExecutorState<byte[]> state) {
            println("CheckAndRestoreInterupt", 4);

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

            int sp = getRegisterValue(state, "SP");
            int sr = getRegisterValue(state, "SR");
            setRegisterValue(state, "SR", loadFromAddr(state, sp));
            sp += 4;
            setRegisterValue(state, "PC", loadFromAddr(state, sp));
            sp += 4;

            switch ((sr >> 22) & 0x7) {
                case 0b010:
                case 0b011:
                case 0b100:
                case 0b101:
                    setRegisterValue(state, "LR", loadFromAddr(state, sp));
                    sp += 4;
                    setRegisterValue(state, "R12", loadFromAddr(state, sp));
                    sp += 4;
                    setRegisterValue(state, "R11", loadFromAddr(state, sp));
                    sp += 4;
                    setRegisterValue(state, "R10", loadFromAddr(state, sp));
                    sp += 4;
                    setRegisterValue(state, "R9", loadFromAddr(state, sp));
                    sp += 4;
                    setRegisterValue(state, "R8", loadFromAddr(state, sp));
                    sp += 4;
                    break;
                default:
                    break;
            }

            sr = getRegisterValue(state, "SR");
            sr &= ~(1 << 5);

            setRegisterValue(state, "SP", sp);
            setRegisterValue(state, "SR", sr);
            finishFrame(state);
            interrupted = false;
        }

        @PcodeUserop
        public void CheckAndRestoreSupervisor(@OpState PcodeExecutorState<byte[]> state) {
            println("CheckAndRestoreSupervisor", 4);
            int sr = getRegisterValue(state, "SR");
            int mode = (sr >> 22) & 0x7;
            int sp = getRegisterValue(state, "SP");
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
                    storeToAddr(state, sp, getRegisterValue(state, "PC"));
                    sp -= 4;
                    storeToAddr(state, sp, getRegisterValue(state, "SR"));
                    setRegisterValue(state, "SP", sp);

                    sr = getRegisterValue(state, "SR");
                    sr &= ~(1 << 15);
                    sr &= ~(1 << 28);
                    sr &= ~(0b111 << 22);
                    sr |= 0b110 << 22;
                    sr |= 1 << 21;
                    sr |= 1 << 16;
                    setRegisterValue(state, "SR", sr);

                    println("privilege exception violation!!!!");
                    setRegisterValue(state, "PC", 0x8005ab20);

                break;
                case 0b001:
                    setRegisterValue(state, "SR", loadFromAddr(state, sp));
                    sp += 4;
                    setRegisterValue(state, "PC", loadFromAddr(state, sp));
                    sp += 4;
                    setRegisterValue(state, "SP", sp);
                    break;
                default:
                    setRegisterValue(state, "PC", getRegisterValue(state, "LR"));
            }
            finishFrame(state);
        }

        @PcodeUserop
        public void SupervisorCallSetup(@OpState PcodeExecutorState<byte[]> state) {
            println("SupervisorCallSetup", 4);
            
            int sr = getRegisterValue(state, "SR");
            int mode = (sr >> 22) & 0x7;
            println("mode: " + mode, 4);
            switch (mode) {
                case 0b000:
                case 0b001:
                    // *(--SPSYS) ← PC + 2;
                    // *(--SPSYS) ← SR;
                    // PC ← EVBA + 0x100;
                    // SR[M2:M0] ← B’001;

                    int sp = getRegisterValue(state, "SP");
                    sp -= 4;
                    storeToAddr(state, sp, nextInstructionAddr(getRegisterValue(state, "PC")));
                    sp -= 4;
                    storeToAddr(state, sp, sr);
                    setRegisterValue(state, "SP", sp);

                    sr &= ~(0b111 << 22);
                    sr |= 0b001 << 22;
                    setRegisterValue(state, "SR", sr);
                    setRegisterValue(state, "PC", 0x8005ab00);
                    
                    break;
                    
                default:
                    // LRCurrent Context ← PC + 2;
                    // PC ← EVBA + 0x100;

                    setRegisterValue(state, "LR", nextInstructionAddr(getRegisterValue(state, "PC")));
                    setRegisterValue(state, "PC", 0x8005ab00);

                    break;
            }
            finishFrame(state);
        }

        @PcodeUserop
        public void doSleep(@OpState PcodeExecutorState<byte[]> state, int i) {
            println("doSleep", 4);
        }
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
        library.set(inner, new MyUseropLibrary());

        return pcemu;
    }

    public void printPcodeOps(PcodeOp[] ops) {
        for (int i = 0; (i < ops.length); i++) {
            println("PcodeOp[" + i + "] = " + ops[i], -1);
        }
    }

    public void printCurrentPcodeOp(PcodeThread<byte[]> thread) {
        PcodeFrame frame = thread.getFrame();
        if (frame != null) {    
            var ops = frame.getCode();
            var OP_INDEX = frame.index();
            
            // 4️⃣ index 번째 op 출력
            if (0 <= OP_INDEX && OP_INDEX < ops.size()) {
                println("PcodeOp[" + OP_INDEX + "] = " + ops.get(OP_INDEX));
            } else {
                println("Index " + OP_INDEX + " out of range (len=" + ops.size() + ")");
            }
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public boolean isFirstAddrInBlock(Address addr) {
        BasicBlockModel bbModel = new BasicBlockModel(currentProgram);
        CodeBlock startBlock;
        try {
            startBlock = bbModel.getFirstCodeBlockContaining(addr, monitor);
        } catch (CancelledException e) {
            return false;
        }
        long of1 = startBlock.getFirstStartAddress().getOffset();
        long of2 = addr.getOffset();
        return of1 == of2;
    }

    public void adjustInstructionCount(Instruction instr, Address addr) {
        if (
            (
                instr.getMnemonicString().endsWith("SRF")
                && !isFirstAddrInBlock(addr)
                && !instr.getPrevious().getMnemonicString().equals("MFSR")
                && !instr.getPrevious().getMnemonicString().equals("MTSR")
                && !instr.getPrevious().getMnemonicString().equals("STDSP")
            ) || interrupted
        ) {
            // println("adjusted", 1);
            currentInstructionCount--;
        }
    }

    public boolean isInterestingInstr(Instruction instr, Address addr) {
        String mn = instr.getMnemonicString();
        return INTERESTING_ADDR == addr.getOffset()
            || mn.startsWith("ST")
            || mn.startsWith("LD")
            || mn.startsWith("MFSR")
            || mn.startsWith("RETS")
            || mn.startsWith("RETE")
            || mn.startsWith("CPC")
            || mn.startsWith("BR")
            || mn.startsWith("CSRF")
            || mn.startsWith("SLEEP")
            || mn.startsWith("MOV")
        ;
    }

    public boolean isInterestingPcodeOp(PcodeOp op, Address addr) {
        String mn = PcodeOp.getMnemonic(op.getOpcode());
        return INTERESTING_ADDR == addr.getOffset()
            || mn.equals("STORE")
            || mn.equals("LOAD")
            || mn.equals("COPY")
            ;
    }
    
    public boolean isIgnoredFunction(Function func) {
        String fn = func.getName();
        return fn.startsWith("wdt")
            || fn.startsWith("sysclk")
            || fn.startsWith("gpio")
            || fn.startsWith("sdramc")
        ;
    }
    
    public void printOutputRegisters(PcodeThread<byte[]> thread, Address addr) {
        Instruction instr = getInstructionAt(addr);
        // 1) Instruction 단위 input/output objects 가져오기
        Object[] outputs = instr.getResultObjects();   // 결과 (= output)
        
        // 3) output registers 추출
        println(">>> Output Registers:");
        for (Object o : outputs) {
            if (o instanceof Register) {
                Register reg = (Register) o;
                byte[] v = thread.getState().getVar(reg, Reason.INSPECT);
                println("  " + reg.getName() + " (" + reg.getAddress()  + ") = " + bytesToHex(v));
            }
        }
    }
    
    public void printInputRegisters(PcodeThread<byte[]> thread, Address addr) {
        Instruction instr = getInstructionAt(addr);
        // 1) Instruction 단위 input/output objects 가져오기
        Object[] inputs = instr.getInputObjects();
        
        // 2) input registers 추출
        println(">>> Input Registers:");
        for (Object o : inputs) {
            if (o instanceof Register) {
                Register reg = (Register) o;
                byte[] v = thread.getState().getVar(reg, Reason.INSPECT);
                println("  " + reg.getName() + " = " + bytesToHex(v));
            }
        }
    }

    public void printAllRegisters(PcodeThread<byte[]> thread) {
        println(">>> All Registers:");
        for (RegisterName rn : RegisterName.values()) {
            int v = getRegisterValue(thread.getState(), rn.name());
            println("  " + rn.name() + " (" + Util.intToHex((int) rn.memoryAddress())  + ") = " + Util.intToHex(v));
        }
    }

    public void printStack(PcodeThread<byte[]> thread) {
        println(">>> Stack:");
        int sp = getRegisterValue(thread.getState(), "SP");
        // for (int i = 20; i >= 0; i--) {
        for (int i = 0; i < 8; i++) {
            int addr = sp + 4 * i;
            println("  *0x" + Util.intToHex(addr) + " = " + Util.intToHex(getRAMValue(thread.getState(), addr)));
        }
    }

        
    public int hookMemoryAccess(Address addr, PcodeOp op, PcodeThread<byte[]> thread) {
        long a = addr.getOffset();
        boolean isStore = PcodeOp.getMnemonic(op.getOpcode()).equals("STORE");
        boolean isLoad = PcodeOp.getMnemonic(op.getOpcode()).equals("LOAD");
    
        if (a >= 0xFFFD0000L && a < 0xFFFF7400L) {
            if (isStore) {
                Integer res = MmioDevice.storeToMmioDeviceAddr(a, op.getInputs()[2]);
                if (res == null) {
                    println("Store to unsupported mmiodevice @ " + addr, 2);
                    return -1;
                }
                return res;
            } else if (isLoad) {
                Integer res = MmioDevice.loadFromMmioDeviceAddr(a, op.getOutput());
                if (res == null) {
                    println("Load from unsupported mmiodevice @ " + addr, 2);
                    return -1;
                }
                return res;
            }
            return -1;
        }
        return 0;
    }

    public int hookSystemRegisterAccess(Varnode node, PcodeOp op, PcodeThread<byte[]> thread) {

        long a = node.getOffset();
        String mn = PcodeOp.getMnemonic(op.getOpcode());
        boolean isCopy = mn.equals("COPY");

        if (isCopy && a <= 1020 && node.isRegister()) {
            Integer value = null;
            if (a == 0) {
                value = getRegisterValue(thread.getState(), "SR");
            } else {
                value = system_register.onRead((int) a);
            }
            
            if (value != null) {
                printAllRegisters(thread);
                Varnode output = op.getOutput();
                Integer valueBefore = Util.getVar(output);
                Util.setVar(output, value);
                println("Overwrote system register @ " + String.format("0x%02X", a) + ": " + String.format("0x%02X", valueBefore) + " -> " + String.format("0x%02X", value), 3);
                printAllRegisters(thread);
            } else {
                println("Copy from unsupported system register @ " + String.format("0x%02X", a));
                return -1;
            }
        }
        return 0;
    }

    public int executeInstr(PcodeThread<byte[]> thread) throws AddressFormatException {
        Address addr = thread.getCounter();
        Instruction instr = getInstructionAt(addr);
        boolean detail = isDetail(addr);

        if (detail) {
            printAllRegisters(thread);
        }
        
        // switch (currentInstructionCount) {
        //     case 40206:
        //     case 40239:
        //     case 40452:
        //     case 40676:
        //     case 40785:
        //         tc0.manualTick();
        //         tc1.manualTick();
        //         break;
        // }

        adjustInstructionCount(instr, addr);

        PcodeExecutorState<byte[]> state = thread.getState();
        int old_sp = getRegisterValue(state, "SP");

        if (addr.getOffset() == 0x8002c31cl) {
            // gs_thread_create
            int np = getRegisterValue(state, "R12");
            // int func = getRegisterValue(state, "R11");
            println("[gs_thread_create] " + readString(state, np), 6);
            // for (int i = 0; i < 10; i++) {
            //     println("*" + Util.intToHex(np) + " = " + Util.intToHex(getRAMValue(state, np)), 6);
            //     np += 4;
            // }
        }

        if (addr.getOffset() == 0x8002f8f2l) {
            // update pxCurrentTCB
            int currentTCB = getRAMValue(state, getRegisterValue(state, "R8"));
            String newTaskName = readString(state, currentTCB + 0x34);
            if (currentTaskName.compareTo(newTaskName) != 0) {
                println("[vTaskSwitchContext] current task: " + newTaskName, 6);
                currentTaskName = newTaskName;
            }
        }

        if (isInterestingInstr(instr, addr)) {
            thread.stepPcodeOp();
            PcodeFrame frame = thread.getFrame();
            if (frame != null) {
                currentFrame = frame;
                var ops = frame.getCode();
                println("Executing frame of size " + ops.size());

                // Fixed in local Ghidra
                // if (mn.startsWith("ST.B")) {
                //     // ops
                //     PcodeExecutorState<byte[]> state = thread.getState();
                //     Varnode rd = ops.get(1).getInput(0);
                //     Varnode res = ops.get(1).getOutput();
                //     byte[] rdb = thread.getState().getVar(rd, Reason.INSPECT);
                //     Integer rdv = Util.byteArrayToInt(rdb);
                //     byte[] resb = state.getVar(res, Reason.INSPECT);
                //     Integer resv = Util.byteArrayToInt(resb);
                //     if (rdv >= 0 && resv < 0) {
                //         setRegisterValue(state, "C", 1);
                //     }
                // }

                while (!frame.isFinished()) {
                    int id = frame.index();
                    PcodeOp op = ops.get(id);
                    boolean interesting = isInterestingPcodeOp(op, addr);
                    if (interesting) {
                        printCurrentPcodeOp(thread);
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
                    //     Integer rdv = Util.byteArrayToInt(rdb);
                    //     byte[] resb = state.getVar(res, Reason.INSPECT);
                    //     Integer resv = Util.byteArrayToInt(resb);
                    //     if (rdv >= 0 && resv < 0) {
                    //         setRegisterValue(state, "C", 1);
                    //     }
                    // }

                    if (interesting) {
                        int[] result = null;
                        if (inputs.length > 0) {
                            result = Arrays.stream(inputs)
                            .mapToInt(x -> Util.getVar(x))
                            .toArray();
                            
                            for (int j = 0; (j < result.length); j++) {
                                int b = result[j];
                                println("Input " + j + ": " + Util.intToHex(b));
                            }
                        }

                        if (result != null && result.length > 1) {
                            Address memaddr = toAddr(result[1]);
                            if (hookMemoryAccess(memaddr, op, thread) == -1) {
                                return -1;
                            }
                        }

                        for (Varnode input : inputs) {
                            if (hookSystemRegisterAccess(input, op, thread) == -1) {
                                return -1;
                            }
                        }
                        
                        if (output != null) {
                            var outputv = Util.getVar(output);
                            println("Output: " + Util.intToHex(outputv));
                            if (output.isRegister() && output.getOffset() == 0x103c) {
                                setRegisterValue(thread.getState(), "PC", outputv);
                            }
                        }
                    }
                }
                thread.stepPcodeOp();
            }
        } else {
            thread.stepInstruction();
        }
        int sp = getRegisterValue(thread.getState(), "SP");
        if (sp != old_sp) {
            printStack(thread);
        }
        printOutputRegisters(thread, addr);
        return 0;
    }

    void handleInterrupt() {
        int prio = intc.highestPrio;
        // Util.println("highestprio: " + prio);
        PcodeExecutorState<byte[]> state = currentThread.getState();
        int sr = getRegisterValue(state, "SR");
        // Util.println("sr: " + Util.intToHex(sr));
        if (prio != -1) {
            if (
                ((sr >> (17 + prio)) & 1) == 0
                && ((sr >> 16) & 1) == 0
            ) {
                callInterruptWrapper(state, prio);
            }
        }
    }

    @Override
    protected void run() throws Exception {

        pw = new PrintWriter[PW_FILENAMES.length];
        for (int i = 1; i < PW_FILENAMES.length; i++) {
            String fn = PW_FILENAMES[i];
            File outFile = new File(getSourceFile().getParentFile().getAbsolutePath() + "/log/" + fn);
            pw[i] = new PrintWriter(new FileWriter(outFile));
        }
        
        java.util.function.Function<String, Void> pln = (String s) -> {
            println(s);
            return null;
        };
        BiFunction<String, Integer, Void> pln_alt = (String s, Integer i) -> {
            println(s, i);
            return null;
        };
        Util.setFunctions(pln, pln_alt);
        Util.currentScript = this;
        log_buffer = new LogBuffer(1000000);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log_buffer.dump();
        }));

        PcodeEmulator emu = getInternalPcodeEmulator(currentProgram);
        println("Got internal PcodeEmulator: " + emu.getClass().getName());

        new PDCA    ( 0xFFFD0000L, "PDCA"    , -1);
        new USART   ( 0xFFFD1400L, "USART1"  , -1);
        new CANIF   ( 0xFFFD1C00L, "CANIF"   , -1);
        new SPI     ( 0xFFFD1800L, "SPI0"    , -1);
        new TC      ( 0xFFFD2000L, "TC0"     , 33);
        new ADCIFA  ( 0xFFFD2400L, "ADCIFA"  , -1);
        new USART   ( 0xFFFD2800L, "USART4"  , -1);
        new TWIM    ( 0xFFFD2C00L, "TWIM2"   , 45);
        new TWIS    ( 0xFFFD3000L, "TWIS2"   , -1);
        new FLASHC  ( 0xFFFE0000L, "FLASHC"  , -1);
        new HMATRIX ( 0xFFFE2000L, "HMATRIX" , -1);
        new SDRAMC  ( 0xFFFE2C00L, "SDRAMC"  , -1);
        new INTC    ( 0xFFFF0000L, "INTC"    , -1);
        new PM      ( 0xFFFF0400L, "PM"      , -1);
        new SCIF    ( 0xFFFF0800L, "SCIF"    , -1);
        new WDT     ( 0xFFFF1000L, "WDT"     , -1);
        new GPIO    ( 0xFFFF2000L, "GPIO"    , -1);
        new USART   ( 0xFFFF2800L, "USART0"  , -1);
        new USART   ( 0xFFFF2C00L, "USART2"  , -1);
        new USART   ( 0xFFFF3000L, "USART3"  , -1);
        new SPI     ( 0xFFFF3400L, "SPI1"    , -1);
        new TWIM    ( 0xFFFF3800L, "TWIM0"   , 25);
        new TWIM    ( 0xFFFF3C00L, "TWIM1"   , 26);
        new TWIS    ( 0xFFFF4000L, "TWIS0"   , -1);
        new TWIS    ( 0xFFFF4400L, "TWIS1"   , -1);
        new TC      ( 0xFFFF5800L, "TC1"     , 34);

        new MPU3300 ( "MPU3300", 0x68 );
        new HMC5843 ( "HMC5843", 0x1E );

        Device.linkAllDevices();
        intc = (INTC) Device.findDevice("INTC");

        tc0 = (TC) Device.findDevice("TC0");
        tc1 = (TC) Device.findDevice("TC1");
        
        tc0.startClockThread();
        tc1.startClockThread();

        system_register = new SystemRegister();

        var thread = emu.newThread("main");
        currentThread = thread;
        Util.currentThread = thread;
        Address entry = toAddr(0x80000000);
        thread.overrideCounter(entry);

        Util.setVar("register", 0x0l, 0x610000);

        while (true) {
            if (thread.getCounter().getOffset() == 0x8001db06l
             || thread.getCounter().getOffset() == 0x8001db0al
             || thread.getCounter().getOffset() == 0x8001db0el
             || thread.getCounter().getOffset() == 0x8001db12l
             || thread.getCounter().getOffset() == 0x8001db16l
             || thread.getCounter().getOffset() == 0x8001db1al
             || thread.getCounter().getOffset() == 0x8001db1el
             || thread.getCounter().getOffset() == 0x8001db22l
             || thread.getCounter().getOffset() == 0x8001db26l
             || thread.getCounter().getOffset() == 0x8001db2al
             || thread.getCounter().getOffset() == 0x8001db2el
             || thread.getCounter().getOffset() == 0x8001db32l
             || thread.getCounter().getOffset() == 0x8001db36l
             || thread.getCounter().getOffset() == 0x8001db3al
             || thread.getCounter().getOffset() == 0x8001db3el
             || thread.getCounter().getOffset() == 0x8001db42l
             || thread.getCounter().getOffset() == 0x8001db46l
             || thread.getCounter().getOffset() == 0x8001db4al
             || thread.getCounter().getOffset() == 0x8001db4el
             || thread.getCounter().getOffset() == 0x8001db52l
             || thread.getCounter().getOffset() == 0x8001db56l
             || thread.getCounter().getOffset() == 0x8001db5al
             || thread.getCounter().getOffset() == 0x8001db5el
             || thread.getCounter().getOffset() == 0x8001db62l
             || thread.getCounter().getOffset() == 0x8001db66l
             || thread.getCounter().getOffset() == 0x8001dc64l
             || thread.getCounter().getOffset() == 0x8001dc68l
             || thread.getCounter().getOffset() == 0x8001dc6cl
            ) {
                currentPhase++;
                currentInstructionCount = 0;
            }
            String funcname = getCurrentFunctionName();
            println("P" + currentPhase + " #" + currentInstructionCount + ": PC = " + thread.getCounter() + " (" + funcname + ")", 1);
            if (currentInstructionCount % 10000 == 0) {
                System.err.println("P" + currentPhase + " #" + currentInstructionCount + ": PC = " + thread.getCounter());
            }
            int sp = getRegisterValue(currentThread.getState(), "SP");
            Util.println("sp: " + Util.intToHex(sp));
            if (executeInstr(thread) == -1) {
                return;
            }
            currentInstructionCount++;
            handleInterrupt();
            if (exitCondition()) {
                tc0.exitClockThread();
                tc1.exitClockThread();
                return;
            }
        }
    }
}

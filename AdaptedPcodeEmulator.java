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
import java.util.List;
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

import etc.Util;
import ghidra.pcode.emu.AbstractPcodeMachine;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import peripheral.*;

public class AdaptedPcodeEmulator extends GhidraScript {

    // public static long INTERESTING_ADDR = 0x8005ab42L;
    public static long INTERESTING_ADDR = 0x8002c4fcL;
    public static Integer INTERESTING_PHASE = null;
    public static int DETAIL_UNTIL = 150000;
    // public static int DETAIL_FROM = 66400;
    public static int DETAIL_FROM = DETAIL_UNTIL + 1;
    public static String[] PW_FILENAMES = {
        "main.log",
        "instr.log",
        "peripheral.log",
        "sysreg.log",
        "userop.log",
        "storeload.log",
        "temp.log",
    };

    public List<Peripheral> peripherals;
    public SystemRegister system_register;
    public String currentFunctionName = "";
    public int currentInstructionCount = 0;
    public int currentPhase = 0;    
    public PrintWriter[] pw;
    public PcodeThread<byte[]> currentThread = null;
    public PcodeFrame currentFrame = null;
    
    public static java.util.function.Function<String, Void> println;

    public boolean isDetail(Address addr) {
        return (
            (currentInstructionCount > DETAIL_FROM
            && currentInstructionCount < DETAIL_UNTIL)
            // || currentPhase == 5
            || addr.getOffset() == 0x8002fda8l
            || addr.getOffset() == 0x8002fb22l
        );
    }
        
    public void println(String s, int i) {
        if (INTERESTING_PHASE == null || currentPhase == INTERESTING_PHASE) {
            if (pw.length > 0) {
                pw[0].println(s);
            }
            if (i > 0 && pw.length > i) {
                String s1 = s + " (P" + currentPhase + " #" + currentInstructionCount + ")";
                pw[i].println(s1);
            } else if (i == -1) {
                String s1 = s + " (P" + currentPhase + " #" + currentInstructionCount + ")";
                pw[pw.length - 1].println(s1);
            }
            super.println(s);
        }
    }

    @Override
    public void println(String s) {
        println(s, 0);
    }


    public Register findRegisterByName(PcodeExecutorState<byte[]> state, String name) {
        for (Register reg : state.getRegisterValues().keySet()) {
            // println("regname: " + reg.getName());
            // println("regaddr: " + reg.getAddress());
            if (reg.getName().equals(name)) {
                return reg;
            }
        }
        return null;
    }

    public int getRegisterValue(PcodeExecutorState<byte[]> state, String name) {
        if (name == "PC") {
            return ((int) currentThread.getCounter().getOffset());
        }
        return Util.byteArrayToInt(state.getVar(findRegisterByName(state, name), Reason.INSPECT));
    }

    public int loadFromAddr(PcodeExecutorState<byte[]> state, int addr) {
        int result = Util.byteArrayToInt(state.getVar(toAddr(addr), 4, true, Reason.INSPECT));
        println(String.format("[loadFromAddr] *0x%08X = %d (0x%08X)", addr, result, result), 5);
        return Util.byteArrayToInt(state.getVar(toAddr(addr), 4, true, Reason.INSPECT));
    }

    public void setRegisterValue(PcodeExecutorState<byte[]> state, String name, int value) {
        if (name == "PC") {
            currentThread.setCounter(toAddr(value));
            // currentFrame.finishAsBranch();
        }
        else {
            Register reg = findRegisterByName(state, name);
            state.setVar(reg, Util.intToByteArray(value, reg.getNumBytes()));
        }
    }


    public void storeToAddr(PcodeExecutorState<byte[]> state, int addr, int value) {
        println(String.format("[storeToAddr] *0x%08X <- %d (0x%08X)", addr, value, value), 5);
        state.setVar(toAddr(addr), 4, true, Util.intToByteArray(value));
    }

    public int nextInstructionAddr(int addr) {
        return ((int) getInstructionAfter(toAddr(addr)).getAddress().getOffset());
    }

    public void int0(PcodeExecutorState<byte[]> state) {
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
        storeToAddr(state, sp, nextInstructionAddr(getRegisterValue(state, "PC")));
        sp -= 4;
        storeToAddr(state, sp, getRegisterValue(state, "SR"));

        setRegisterValue(state, "SP", sp);

        int sr = getRegisterValue(state, "SR");
        sr &= ~(1 << 15);
        sr &= ~(1 << 28);
        sr &= ~(0b111 << 22);
        sr |= 0b010 << 22;
        sr |= 1 << 17;
        setRegisterValue(state, "SR", sr);

        setRegisterValue(state, "PC", 0x8005ab20);
        currentFrame.finishAsBranch();
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
            currentFrame.finishAsBranch();
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
                    setRegisterValue(state, "SP", sp);
                    break;
                default:
                    setRegisterValue(state, "PC", getRegisterValue(state, "LR"));
            }
            currentFrame.finishAsBranch();
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
            currentFrame.finishAsBranch();

            // if (currentThread != null) {
            //     currentThread.setCounter(toAddr(0x8005ab00));
            // }
            // if (currentFrame != null) {
            //     currentFrame.finishAsBranch();
            // }
        }

        @PcodeUserop
        public void doSleep(@OpState PcodeExecutorState<byte[]> state, int i) {
            // TODO: Your logic, which I suppose could be NOP
            println("doSleep", 4);
            int0(state);
        }

        // @PcodeUserop
        // public void MoveToDebugReg(@OpState PcodeExecutorState<byte[]> state, Varnode input1, Varnode input2) {
        //     // TODO: Your logic, which I suppose could be NOP
        //     println("debu1g");
        //     if (currentThread != null) {
        //         currentThread.setCounter(toAddr(0x8005ab00));
        //     }
        //     if (currentFrame != null) {
        //         currentFrame.finishAsBranch();
        //     }
        //     println("debu2g");
        // }
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

    public void printCurrentPcodeOp(PcodeThread thread) {
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

    public static String intToHex(int i) {
        return String.format("%08X", i);
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
            instr.getMnemonicString().endsWith("SRF")
            && !isFirstAddrInBlock(addr)
            // && addr.getOffset() != 0x8002e71cL
            // && addr.getOffset() != 0x8002e628L
            && !instr.getPrevious().getMnemonicString().equals("MFSR")
            && !instr.getPrevious().getMnemonicString().equals("MTSR")
            && !instr.getPrevious().getMnemonicString().equals("STDSP")
        ) {
            println("adjusted", 1);
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
        // Function func = getFunctionContaining(addr);
        // if (func != null) {
        //     if (isIgnoredFunction(func)) {
        //         Instruction instr = getInstructionAt(addr);
        //         if (instr.getMnemonicString().startsWith("BR")) {
        //             thread.skipInstruction();
        //         }
        //     }
        // }
        // if (0x80037292L == addr.getOffset()) {
        if (true) {
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
    }
    
    public void printInputRegisters(PcodeThread<byte[]> thread, Address addr) {
        // Function func = getFunctionContaining(addr);
        // if (func != null) {
        //     if (isIgnoredFunction(func)) {
        //         Instruction instr = getInstructionAt(addr);
        //         if (instr.getMnemonicString().startsWith("BR")) {
        //             thread.skipInstruction();
        //         }
        //     }
        // }
        // if (0x800371faL <= addr.getOffset() && addr.getOffset() <= 0x800372c6L) {
        if (true) {
            Instruction instr = getInstructionAt(addr);
            // 1) Instruction 단위 input/output objects 가져오기
            Object[] inputs = instr.getInputObjects();
            Object[] outputs = instr.getResultObjects();   // 결과 (= output)
            
            // 2) input registers 추출
            println(">>> Input Registers:");
            for (Object o : inputs) {
                if (o instanceof Register) {
                    Register reg = (Register) o;
                    byte[] v = thread.getState().getVar(reg, Reason.INSPECT);
                    println("  " + reg.getName() + " = " + bytesToHex(v));
                }
            }

            // println(">>> All Registers:");
            // var rv = thread.getState().getRegisterValues();
            // for (Register reg : rv.keySet()) {
            //     byte[] v = thread.getState().getVar(reg, Reason.INSPECT);
            //     println("  " + reg.getName() + " = " + bytesToHex(v));
            // }
        }
    }

    public void printAllRegisters(PcodeThread<byte[]> thread) {
        // if (0x800371faL <= addr.getOffset() && addr.getOffset() <= 0x800372c6L) {

        String[] interesting_regs = {"PC", "SP", "LR", "C", "Z", "N", "V", "SR"};
        if (true) {
            println(">>> All Registers:");
            var rv = thread.getState().getRegisterValues();
            for (Register reg : rv.keySet()) {
                if ((reg.getName().startsWith("R")
                    && !reg.getName().equals("R"))
                || Arrays.asList(interesting_regs).contains(reg.getName())) {
                    byte[] v = thread.getState().getVar(reg, Reason.INSPECT);
                    println("  " + reg.getName() + " (" + reg.getAddress()  + ") = " + bytesToHex(v));
                }
            }
        }
        // byte[] v = thread.getState().getVar(toAddr(0x368), 4, true, Reason.INSPECT);
        // println(" *0x368 = " + bytesToHex(v));
        // v = thread.getState().getVar(toAddr(0x8005AF40), 4, true, Reason.INSPECT);
        // println(" *0x8005AF40 = " + bytesToHex(v));
    }

        
    public int hookMemoryAccess(Address addr, PcodeOp op, PcodeThread<byte[]> thread) {
        long a = addr.getOffset();
        boolean isStore = PcodeOp.getMnemonic(op.getOpcode()).equals("STORE");
        boolean isLoad = PcodeOp.getMnemonic(op.getOpcode()).equals("LOAD");
    
        if (a >= 0xFFFD0000L && a < 0xFFFF7400L) {
            for (Peripheral p : Peripheral.registry) {
                
                if (!p.contains(a)) continue;
                
                int off = (int)(a - p.base);
                
                if (isStore) {
                    println("Store to " + p.name + " @ " + addr, 2);
                    return p.store(off, op.getInputs()[2], thread);
                } else if (isLoad) {
                    println("Load from " + p.name + " @ " + addr, 2);
                    return p.load(off, op.getOutput(), thread);
                } 
            }
            if (isStore) {
                println("Store to unsupported peripheral @ " + addr, 2);
            } else if (isLoad) {
                println("Load from unsupported peripheral @ " + addr, 2);
            }
            return -1;
        }
        return 0;
    }
    
    public int hookSystemRegisterAccess_(Varnode node, PcodeThread<byte[]> thread) {

        long a = node.getOffset();

        if (node.isConstant() && a <= 1020) {
        // if (isCopy && a == 0x108) {
            Integer value = system_register.onRead((int) a);
            
            if (value != null) {
                printAllRegisters(thread);
                Integer valueBefore = Util.byteArrayToInt(thread.getState().getVar(node, Reason.INSPECT));
                if (a != 0)
                    thread.getState().setVar(node, Util.intToByteArray(value, node.getSize()));
                println("Overwrote system register @ " + String.format("0x%02X", a) + ": " + String.format("0x%02X", valueBefore) + " -> " + String.format("0x%02X", value), 3);
                printAllRegisters(thread);
            } else {
                println("Copy from unsupported system register @ " + String.format("0x%02X", a));
                return -1;
            }
        }
        return 0;
    }

    public int hookSystemRegisterAccess(Varnode node, PcodeOp op, PcodeThread<byte[]> thread) {

        long a = node.getOffset();
        String mn = PcodeOp.getMnemonic(op.getOpcode());
        boolean isCopy = mn.equals("COPY");

        if (isCopy && a <= 1020 && node.isRegister()) {
        // if (isCopy && a <= 1020) {
        // if (isCopy && a == 0x108) {
            Integer value = null;
            if (a == 0) {
                var rv = thread.getState().getRegisterValues();
                for (Register reg : rv.keySet()) {
                    if ((reg.getName().equals("SR"))) {
                        value = Util.byteArrayToInt(thread.getState().getVar(reg, Reason.INSPECT));
                    }
                }
            } else {
                value = system_register.onRead((int) a);
            }
            
            if (value != null) {
                printAllRegisters(thread);
                Varnode output = op.getOutput();
                Integer valueBefore = Util.byteArrayToInt(thread.getState().getVar(output, Reason.INSPECT));
                // if (a != 0)
                thread.getState().setVar(output, Util.intToByteArray(value, output.getSize()));
                println("Overwrote system register @ " + String.format("0x%02X", a) + ": " + String.format("0x%02X", valueBefore) + " -> " + String.format("0x%02X", value), 3);
                printAllRegisters(thread);
            } else {
                println("Copy from unsupported system register @ " + String.format("0x%02X", a));
                return -1;
            }
        }
        return 0;
    }
    

    public Address byteArrayToAddress(byte[] b) {

        // long addrVal = 0L;
        // for (int i = 0; i < b.length; i++) {
        //     addrVal |= (b[i] & 0xFFL) << (8 * (3-i));
        // }

        Address target = toAddr(Util.byteArrayToInt(b));

        return target;

    }
    

    public int executeInstr(PcodeThread<byte[]> thread) throws AddressFormatException {
        Address addr = thread.getCounter();
        Instruction instr = getInstructionAt(addr);
        String mn = instr.getMnemonicString();
        boolean detail = isDetail(addr);

        if (detail) {
            printAllRegisters(thread);
        }
        // currentFunctionName = func.toString();
        // if (addr.getOffset() == 0x8002E340L) {
        //     return -1;
        // }

        adjustInstructionCount(instr, addr);
        if (isInterestingInstr(instr, addr)) {
            thread.stepPcodeOp();
            PcodeFrame frame = thread.getFrame();
            if (frame != null) {
                currentFrame = frame;
                var ops = frame.getCode();
                println("Executing frame of size " + ops.size());
                // for (int i = 0; i < ops.size(); i++) {
                while (!frame.isFinished()) {
                    int id = frame.index();
                    PcodeOp op = ops.get(id);
                    boolean interesting = isInterestingPcodeOp(op, addr);
                    // if (interesting) {
                        printCurrentPcodeOp(thread);
                    // }
                    Varnode[] inputs = op.getInputs();
                    Varnode output = op.getOutput();
                    thread.stepPcodeOp();
                    
                    if (mn.equals("CPC") && id == 6 && instr.getNumOperands() == 1) {
                        PcodeExecutorState<byte[]> state = thread.getState();
                        Varnode rd = ops.get(1).getInput(0);
                        Varnode res = ops.get(1).getOutput();
                        byte[] rdb = thread.getState().getVar(rd, Reason.INSPECT);
                        Integer rdv = Util.byteArrayToInt(rdb);
                        byte[] resb = state.getVar(res, Reason.INSPECT);
                        Integer resv = Util.byteArrayToInt(resb);
                        if (rdv >= 0 && resv < 0) {
                            setRegisterValue(state, "C", 1);
                        }
                    }

                    if (interesting) {
                        byte[][] result = null;
                        if (inputs.length > 0) {
                            result = Arrays.stream(inputs)
                            .map(x -> thread.getState().getVar(x, Reason.INSPECT))
                            .toArray(byte[][]::new);
                            
                            for (int j = 0; (j < result.length); j++) {
                                byte[] b = result[j];
                                println("Input " + j + ": " + bytesToHex(b));
                            }
                        }

                        if (result != null && result.length > 1) {
                            Address memaddr = byteArrayToAddress(result[1]);
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
                            var outputv = thread.getState().getVar(output, Reason.INSPECT);
                            println("Output: " + bytesToHex(outputv));
                            if (output.isRegister() && output.getOffset() == 0x103c) {
                                setRegisterValue(thread.getState(), "PC", Util.byteArrayToInt(outputv));
                            }
                        }
                        // boolean ok = askYesNo("중단", "계속 실행할까요?");
                        // if (!ok) {
                        //     return -1;
                        // }
                    }
                }
                thread.stepPcodeOp();
            }
        } else {
            thread.stepInstruction();
        }
        printOutputRegisters(thread, addr);
        return 0;
    }

    // void handleInterrupt() {
        
    // }

    @Override
    protected void run() throws Exception {
        // 이 코드는 Ghidra Headless Analyzer나 Ghidra plugin 환경에서 실행해야 함.
        // Program currentProgram = ...; // Ghidra 환경에서 주입됨
        
        pw = new PrintWriter[PW_FILENAMES.length];
        for (int i = 0; i < PW_FILENAMES.length; i++) {
            String fn = PW_FILENAMES[i];
            File outFile = new File("/Users/suhyeonryu/CubeSatPcode/ghidra_scripts/log/" + fn);
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

        PcodeEmulator emu = getInternalPcodeEmulator(currentProgram);
        println("Got internal PcodeEmulator: " + emu.getClass().getName());

        new PDCA    ( 0xFFFD0000L, "PDCA"    );
        new USART   ( 0xFFFD1400L, "USART1"  );
        new CANIF   ( 0xFFFD1C00L, "CANIF"   );
        new SPI     ( 0xFFFD1800L, "SPI0"    );
        new TC      ( 0xFFFD2000L, "TC0"     );
        new ADCIFA  ( 0xFFFD2400L, "ADCIFA"  );
        new USART   ( 0xFFFD2800L, "USART4"  );
        new TWIM    ( 0xFFFD2C00L, "TWIM2"   );
        new TWIS    ( 0xFFFD3000L, "TWIS2"   );
        new FLASHC  ( 0xFFFE0000L, "FLASHC"  );
        new HMATRIX ( 0xFFFE2000L, "HMATRIX" );
        new SDRAMC  ( 0xFFFE2C00L, "SDRAMC"  );
        new INTC    ( 0xFFFF0000L, "INTC"    );
        new PM      ( 0xFFFF0400L, "PM"      );
        new SCIF    ( 0xFFFF0800L, "SCIF"    );
        new WDT     ( 0xFFFF1000L, "WDT"     );
        new GPIO    ( 0xFFFF2000L, "GPIO"    );
        new USART   ( 0xFFFF2800L, "USART0"  );
        new USART   ( 0xFFFF2C00L, "USART2"  );
        new USART   ( 0xFFFF3000L, "USART3"  );
        new SPI     ( 0xFFFF3400L, "SPI1"    );
        new TWIM    ( 0xFFFF3800L, "TWIM0"   );
        new TWIM    ( 0xFFFF3C00L, "TWIM1"   );
        new TWIS    ( 0xFFFF4000L, "TWIS0"   );
        new TWIS    ( 0xFFFF4400L, "TWIS1"   );
        new TC      ( 0xFFFF5800L, "TC1"     );

        peripherals = Peripheral.registry;
        system_register = new SystemRegister();



        // 예시: 스레드 생성 및 실행
        var thread = emu.newThread("main");
        currentThread = thread;
        Address entry = toAddr(0x80000000);
        // Address entry = toAddr(0x8001da84);
        // var thread = emu.newThread("randev_sys_uplink_manager");
        // Address entry = toAddr(0x80017158);
        thread.overrideCounter(entry);
        // println(currentProgram.getLanguage().getLanguageID().getIdAsString());
        // setRegisterValue(thread.getState(), "SR", 0x610000);
        var regAddrSpace = currentProgram.getAddressFactory().getAddressSpace("register");
        thread.getState().setVar(regAddrSpace, 0x0l, 4, true, Util.intToByteArray(0x610000));
        // state.setVar(toAddr(addr), , true, Util.intToByteArray(value));

        
        while (currentInstructionCount < DETAIL_UNTIL) {
        // while (true) {
            if (thread.getCounter().getOffset() == 0x8001da8cl
             || thread.getCounter().getOffset() == 0x8001db06l
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
            ) {
                currentPhase++;
                currentInstructionCount = 0;
            }
            println("P" + currentPhase + " #" + currentInstructionCount + ": PC = " + thread.getCounter(), 1);
            if (executeInstr(thread) == -1) {
                return;
            }
            currentInstructionCount++;
            // handleInterrupt();
        }
        
        
        // println("Next operation: " + thread.getFrame().nextOp());
    }
}

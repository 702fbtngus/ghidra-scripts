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
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import ghidra.app.emulator.AdaptedEmulator;
import ghidra.app.emulator.EmulatorConfiguration;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.pcode.PcodeOp;

import etc.Util;
import ghidra.program.model.pcode.Varnode;
import peripheral.*;

public class Test extends GhidraScript {

    public List<Peripheral> peripherals;
    public SystemRegister system_register;
    public String current_function_name = "";
    PrintWriter pw;
    
    public static java.util.function.Function<String, Void> println;

    @Override
    public void println(String s) {
        if (pw == null) {
            super.println(s);
        }
        else {
            pw.println(s);
        }
        
        super.println(s);
    }

    public PcodeEmulator getInternalPcodeEmulator(Program program) throws Exception {
        // 1️⃣ 준비: EmulatorConfiguration 구현체 (EmulatorHelper 사용)
        EmulatorConfiguration config = new EmulatorHelper(program);

        // 2️⃣ AdaptedEmulator 인스턴스 생성
        AdaptedEmulator adapted = new AdaptedEmulator(config);
        
        // 3️⃣ protected 메서드 newPcodeEmulator(EmulatorConfiguration) 반사 호출
        Method m = AdaptedEmulator.class.getDeclaredMethod("newPcodeEmulator", EmulatorConfiguration.class);
        m.setAccessible(true);
        
        // 4️⃣ 호출 — 결과는 AdaptedPcodeEmulator (내부 클래스, PcodeEmulator 상속)
        Object inner = m.invoke(adapted, config);
        
        if (!(inner instanceof PcodeEmulator)) {
            throw new IllegalStateException("Result is not a PcodeEmulator: " + inner.getClass());
        }

        return (PcodeEmulator) inner;
    }

    

    public void printPcodeOp(PcodeThread thread) {
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

    public boolean isInterestingInstr(Address addr) {
        Instruction instr = getInstructionAt(addr);
        if (instr.getMnemonicString().startsWith("ST")) {
            return true;
        }
        if (instr.getMnemonicString().startsWith("LD")) {
            return true;
        }
        if (instr.getMnemonicString().startsWith("MFSR")) {
            return true;
        }
        return false;
    }

    public boolean isInterestingPcodeOp(PcodeOp op, Address addr) {
        if (0x80037292L == addr.getOffset()) {
            return true;
        }
        String mn = PcodeOp.getMnemonic(op.getOpcode());
        if (mn.equals("STORE")) {
            return true;
        }
        if (mn.equals("LOAD")) {
            return true;
        }
        if (mn.equals("COPY")) {
            return true;
        }
        return false;
    }
    
    public boolean isIgnoredFunction(Function func) {
        if (func.getName().startsWith("wdt")) {
            return true;
        }
        if (func.getName().startsWith("sysclk")) {
            return true;
        }
        if (func.getName().startsWith("gpio")) {
            return true;
        }
        if (func.getName().startsWith("sdramc")) {
            return true;
        }
        return false;
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
        if (0x80037292L == addr.getOffset()) {
        // if (true) {
            Instruction instr = getInstructionAt(addr);
            // 1) Instruction 단위 input/output objects 가져오기
            Object[] outputs = instr.getResultObjects();   // 결과 (= output)
            
            // 3) output registers 추출
            println(">>> Output Registers:");
            for (Object o : outputs) {
                if (o instanceof Register) {
                    Register reg = (Register) o;
                    byte[] v = thread.getState().getVar(reg, Reason.INSPECT);
                    println("  " + reg.getName() + " = " + bytesToHex(v));
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

    public void printAllRegisters(PcodeThread<byte[]> thread, Address addr) {
        // if (0x800371faL <= addr.getOffset() && addr.getOffset() <= 0x800372c6L) {

        // String[] interesting_regs = {"PC", "SP", "LR"};
        // if (true) {
        //     println(">>> All Registers:");
        //     var rv = thread.getState().getRegisterValues();
        //     for (Register reg : rv.keySet()) {
        //         if ((reg.getName().startsWith("R")
        //             && !reg.getName().equals("R"))
        //             || Arrays.asList(interesting_regs).contains(reg.getName())) {
        //             byte[] v = thread.getState().getVar(reg, Reason.INSPECT);
        //             println("  " + reg.getName() + " = " + bytesToHex(v));
        //         }
        //     }
        // }
        byte[] v = thread.getState().getVar(toAddr(0x368), 4, true, Reason.INSPECT);
        println(" *0x368 = " + bytesToHex(v));
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
                    println("Store to " + p.getClass().getSimpleName() + " @ " + addr);
                    return p.store(off, op.getInputs()[2], thread);
                } else if (isLoad) {
                    println("Load from " + p.getClass().getSimpleName() + " @ " + addr);
                    return p.load(off, op.getOutput(), thread);
                } 
            }
            if (isStore) {
                println("Store to unsupported peripheral @ " + addr);
            } else if (isLoad) {
                println("Load from unsupported peripheral @ " + addr);
            }
            return -1;
        }
        return 0;
    }
    
    public int hookSystemRegisterAccess(Varnode node, PcodeOp op, PcodeThread<byte[]> thread) {

        long a = node.getOffset();
        boolean isCopy = PcodeOp.getMnemonic(op.getOpcode()).equals("COPY");

        if (isCopy && a <= 1020) {
            Integer value = system_register.onRead((int) a);
            
            if (value != null) {
                println("Copy from system register @ " + a);
                var output = op.getOutput();
                thread.getState().setVar(output, Util.intToByteArray(value));
            } else {
                println("Copy from unsupported system register @ " + a);
                return -1;
            }
        }
        return 0;
    }
    

    public Address byteArrayToAddress(byte[] b) {

        long addrVal = 
            ((b[3] & 0xFFL)) |
            ((b[2] & 0xFFL) << 8) |
            ((b[1] & 0xFFL) << 16) |
            ((b[0] & 0xFFL) << 24);

        Address target = toAddr(addrVal);

        return target;

    }
    

    public int executeInstr(PcodeThread<byte[]> thread) {
        Address addr = thread.getCounter();
        println("Instruction address: " + addr);
        Function func = getFunctionContaining(addr);
        println("Function: " + func.toString());
        // if (!current_function_name.equals(func.toString())) {
            printAllRegisters(thread, addr);
        // }
        current_function_name = func.toString();
        // if (addr.getOffset() == 0x8002E340L) {
        //     return -1;
        // }
        if (isInterestingInstr(addr)) {
            thread.stepPcodeOp();
            PcodeFrame frame = thread.getFrame();
            if (frame != null) {
                var ops = frame.getCode();
                // println("Executing frame of size " + ops.size());
                for (int i = 0; i < ops.size(); i++) {
                    println("index: " + frame.index());
                    PcodeOp op = ops.get(frame.index());
                    boolean interesting = isInterestingPcodeOp(op, addr);
                    if (interesting) {
                        printPcodeOp(thread);
                    }
                    Varnode[] inputs = op.getInputs();
                    Varnode output = op.getOutput();
                    thread.stepPcodeOp();
                    if (interesting) {
                        byte[][] result = null;
                        if (inputs.length > 0) {
                            result = Arrays.stream(inputs)
                            .map(x -> thread.getState().getVar(x, Reason.INSPECT))
                            .toArray(byte[][]::new);
                            
                            for (int j = 0; j < result.length; j++) {
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
                        if (inputs != null && inputs.length > 0) {
                            if (hookSystemRegisterAccess(inputs[0], op, thread) == -1) {
                                return -1;
                            }
                        }
                        if (output != null) {
                            println("Output: " + bytesToHex(thread.getState().getVar(output, Reason.INSPECT)));
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

    @Override
    protected void run() throws Exception {
        // 이 코드는 Ghidra Headless Analyzer나 Ghidra plugin 환경에서 실행해야 함.
        // Program currentProgram = ...; // Ghidra 환경에서 주입됨
        
        File outFile = new File("/Users/suhyeonryu/CubeSatPcode/ghidra_scripts/hooks.txt");
        pw = new PrintWriter(new FileWriter(outFile));
        // Util.println = (String s) -> {
        //     println(s);
        //     return null;
        // };

        PcodeEmulator emu = getInternalPcodeEmulator(currentProgram);
        var thread = emu.newThread("main");

        for (int i = 0x14; i <= 0x7e7; i = i + 4) {
            println(" *0x" + String.format("%02X", i) + " = " + bytesToHex(thread.getState().getVar(toAddr(i), 4, true, Reason.INSPECT)));
        }
        
        
        
        // println("Next operation: " + thread.getFrame().nextOp());
    }
}

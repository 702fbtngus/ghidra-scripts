//TODO write a description for this script
//@author 
//@category AAA
//@keybinding 
//@menupath 
//@toolbar 
//@runtime Java

import java.io.ByteArrayInputStream;
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
import ghidra.app.util.bin.ByteProvider;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.pcode.PcodeOp;

import etc.Util;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.Varnode;
import peripheral.*;

public class PopulateDataLMA extends GhidraScript {

    static int DATA_LMA = 0x8005ac00;

    @Override
    protected void run() throws Exception {
        // 이 코드는 Ghidra Headless Analyzer나 Ghidra plugin 환경에서 실행해야 함.
        // Program currentProgram = ...; // Ghidra 환경에서 주입됨
        
        Memory mem = currentProgram.getMemory();

        // 1) .data 블록 찾기 (VMA 쪽)
        String dataBlockName = ".data";
        MemoryBlock dataBlock = mem.getBlock(dataBlockName);
        if (dataBlock == null) {
            println("Memory block '" + dataBlockName + "' not found.");
            return;
        }
        
        Address vma = dataBlock.getStart();
        long size = dataBlock.getSize();
        println(String.format("Found %s: VMA=%s size=0x%x", dataBlockName, vma, size));
        
        
        Address lma = toAddr(DATA_LMA);
        String lmaSymbolName = "_data_lma";
        println(String.format("%s = %s", lmaSymbolName, lma));

        // 3) .data 내용을 VMA에서 읽어오기
        byte[] buf = new byte[(int) size];
        mem.getBytes(vma, buf);

        // 4) LMA 위치에 이미 블록이 있으면 그냥 실패로 두거나, 필요시 삭제/overlay 처리
        MemoryBlock exist = mem.getBlock(lma);
        if (exist != null) {
            println("There is already a block at LMA (" + exist.getName() + "); not overwriting.");
            println("Block size = " + exist.getSize());
            return;
        }
        
    
        // 5) ByteArrayInputStream으로 감싸서 initialized block 생성
        ByteArrayInputStream bais = new ByteArrayInputStream(buf);

        int txId = currentProgram.startTransaction("create .data_lma");
        try {
            mem.createInitializedBlock(
                ".data_lma",
                lma,
                bais,
                size,
                monitor,   // GhidraScript 안에 기본 제공 TaskMonitor
                false      // overlay 사용 안 함
            );
        } finally {
            currentProgram.endTransaction(txId, true);
        }

        println("Successfully created initialized .data_lma block at " + lma);
    }
}

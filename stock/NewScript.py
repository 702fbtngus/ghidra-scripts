# -*- coding: utf-8 -*-

#TODO write a description for this script
#@author 
#@category AAA
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import Varnode

monitor = ConsoleTaskMonitor()

emu = EmulatorHelper(currentProgram)
emu.writeRegister("pc", toAddr(0x80000000).getOffset())

watch_space = "ram"   # AVR32 typical memory space name (check Memory Map if unsure)
max_steps = 5000

print("Starting emulation and monitoring for writes to '{}'...".format(watch_space))

for i in range(max_steps):
    pc = emu.getExecutionAddress()
    instr = getInstructionAt(pc)
    if instr is None:
        print("No instruction at {}".format(pc))
        break

    ops = instr.getPcode()
    hit = False
    for op in ops:
        out = op.getOutput()

        # Also detect STORE8/16/32 mnemonics (AVR32-specific)
        opname = op.getMnemonic().upper()
        if opname.startswith("STORE"):
            print("[{}] {} detected at {}".format(i, opname, instr))
            hit = True
            break

    if hit:
        print(">>> Breakpoint hit at {}".format(pc))
        break

    ok = emu.step(monitor)
    if not ok:
        print("Emulation stopped (error or end of code).")
        break

emu.dispose()
print("Done.")

# -*- coding: utf-8 -*-

#TODO write a description for this script
#@author 
#@category AAA
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython
# Jython (Ghidra script) — get underlying PcodeEmulator if present
from ghidra.app.emulator import EmulatorHelper
from java.lang import Class
from java.lang.reflect import Modifier

def find_pcode_emulator_from_emulator(emulator):
    """
    Try to find ghidra.pcode.emu.PcodeEmulator instance hidden inside an Emulator (AdaptedEmulator/DefaultEmulator).
    Returns the PcodeEmulator instance or None if not found.
    """
    try:
        # load the runtime class objects
        PcodeEmuClass = Class.forName("ghidra.pcode.emu.PcodeEmulator")
    except Exception as e:
        print("PcodeEmulator class not found:", e)
        return None

    clazz = emulator.getClass()
    # walk class hierarchy (in case the field is declared in a superclass)
    while clazz is not None:
        try:
            fields = clazz.getDeclaredFields()
        except:
            fields = []
        for f in fields:
            try:
                f.setAccessible(True)
                val = f.get(emulator)
                if val is None:
                    continue
                # check type: isAssignableFrom handles subclasses
                if PcodeEmuClass.isInstance(val):
                    return val
                # sometimes inner wrapper holds another delegate object; try to inspect it recursively
                # avoid infinite recursion by only trying one extra level
                innerClazz = val.getClass()
                try:
                    innerFields = innerClazz.getDeclaredFields()
                except:
                    innerFields = []
                for ifld in innerFields:
                    try:
                        ifld.setAccessible(True)
                        ival = ifld.get(val)
                        if ival is not None and PcodeEmuClass.isInstance(ival):
                            return ival
                    except:
                        pass
            except:
                # ignore inaccessible fields
                pass
        # climb to superclass
        clazz = clazz.getSuperclass()

    return None

# usage
helper = EmulatorHelper(currentProgram)
em = helper.getEmulator()   # returns an Emulator (AdaptedEmulator/DefaultEmulator)
print(em)
pcode_emu = find_pcode_emulator_from_emulator(em)
if pcode_emu:
    print("Found PcodeEmulator:", pcode_emu)
else:
    print("No internal PcodeEmulator found (or reflection blocked).")

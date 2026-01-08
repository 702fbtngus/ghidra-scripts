# -*- coding: utf-8 -*-

#TODO write a description for this script
#@author 
#@category AAA
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

#@category Emulation
# Jython: obtain a PcodeEmulator from AdaptedEmulator via reflection
# WARNING: uses reflection to call a protected method; this is not officially supported
# and may break on future Ghidra versions. Use PcodeEmulator directly if possible.

from ghidra.app.emulator import AdaptedEmulator, EmulatorHelper, EmulatorConfiguration
from ghidra.pcode.emu import PcodeEmulator
from java.lang import Class
import traceback

def get_pcode_emulator_from_adapted(program):
    """
    Create an AdaptedEmulator backed by an EmulatorConfiguration (EmulatorHelper),
    and call the protected newPcodeEmulator(...) via reflection to get the internal
    AdaptedPcodeEmulator (a PcodeEmulator subclass).
    Returns: an object implementing PcodeEmulator (or raises).
    """
    # 1) create an EmulatorConfiguration instance. EmulatorHelper implements the interface.
    config = EmulatorHelper(program)

    # 2) construct an AdaptedEmulator with that config
    adapted = AdaptedEmulator(config)

    # 3) reflectively access protected method newPcodeEmulator(EmulatorConfiguration)
    try:
        # get java.lang.Class for the interface type
        ec_class = Class.forName("ghidra.app.emulator.EmulatorConfiguration")
        # get declared method
        decl_m = adapted.getClass().getDeclaredMethod("newPcodeEmulator", [ec_class])
        decl_m.setAccessible(True)  # force accessible
    except Exception as e:
        raise RuntimeError("Reflection: could not locate method newPcodeEmulator: %s\n%s" %
                           (e, traceback.format_exc()))

    # 4) invoke method; pass the EmulatorConfiguration instance (config)
    try:
        # result is an instance of AdaptedPcodeEmulator (inner class), which subclasses PcodeEmulator
        result = decl_m.invoke(adapted, config)
    except Exception as e:
        raise RuntimeError("Reflection: invocation failed: %s\n%s" % (e, traceback.format_exc()))

    # 5) sanity-check: ensure we can treat it like a PcodeEmulator
    if result is None:
        raise RuntimeError("Reflection returned None")
    # duck-typing: check it has expected methods
    # for mname in ("newThread", "getSharedState", "dispose"):
    #     if not hasattr(result, mname):
    #         raise RuntimeError("Result does not appear to be a PcodeEmulator (missing %s)" % mname)

    return adapted, result, config

# ---------- usage ----------
from ghidra.pcode.emu import PcodeEmulator
try:
    adapted_emulator, pcode_emu, config = get_pcode_emulator_from_adapted(currentProgram)

    pcode_emu = cast(PcodeEmulator, result)
    print("Got adapted emulator:", adapted_emulator)
    print("Got pcode emulator (wrapper):", pcode_emu)
    # Example: create thread and run one pcode op
    thr = pcode_emu.newThread("fromAdapted")
    entry = currentProgram.getEntryPoint()
    thr.overrideCounter(entry)
    print("PC set to", entry)
    ok = thr.stepPcodeOp()
    print("stepPcodeOp ->", ok, "PC now:", thr.getCounter())
finally:
    # cleanup if available
    try:
        adapted_emulator.dispose()
    except:
        pass
    try:
        pcode_emu.dispose()
    except:
        pass

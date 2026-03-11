#!/usr/bin/env python3

import sys
import subprocess
import argparse

parser = argparse.ArgumentParser()


subparsers = parser.add_subparsers(dest="mode", required=True)

# list mode
parser_list = subparsers.add_parser("list")

# delete mode
parser_del = subparsers.add_parser("del")
parser_del.add_argument("file")

# emulation mode
parser_emul = subparsers.add_parser("emul")
parser_emul.add_argument("--fast", action="store_true")
parser_emul.add_argument("--num-instr", type=int)

# import mode
parser_list = subparsers.add_parser("import")
parser_list.add_argument("file")

# manual run mode
parser_run = subparsers.add_parser("run")
parser_run.add_argument("script")
parser_run.add_argument("--fast", action="store_true")

args = parser.parse_args()

def execute_script(script=None, args=[], process=None, _import=None, to_main=False):
    runargs = [
        "/home/fbtngus/ghidra-randev/build/dist/ghidra_12.0_DEV/support/analyzeHeadless",
        "/home/fbtngus/ghidra-projects", "RandevGhidra",
        # "-scriptPath", "/home/fbtngus/ghidra-scripts",
        # "-postScript", script, *args,
        # "-noanalysis",
        # "-process", firmware,
    ]
    if script:
        runargs += [
            "-scriptPath", "/home/fbtngus/ghidra-scripts",
            "-postScript", script, *args,
        ]
    if process:
        runargs += ["-process", process, "-noanalysis"]
    if _import:
        runargs += ["-import", _import]

    if to_main:
        with open("./log/main.log", "w") as f:
            subprocess.run(runargs, stdout=f)
    else:
        subprocess.run(runargs)

if args.mode == "list":
    execute_script("ProjectManager.java", ["list"])
elif args.mode == "del":
    execute_script("ProjectManager.java", ["delete", args.file])
elif args.mode == "emul":
    file = "nanomind-bsp-fast.elf" if args.fast else "nanomind-bsp-new.elf"
    emul_args = []
    if args.num_instr is not None:
        emul_args.append(f"--num-instr={args.num_instr}")
    execute_script("CubeSatEmulator.java", emul_args, process=file, to_main=True)
elif args.mode == "import":
    file = "/home/fbtngus/ghidra-randev/build/dist/" + args.file
    execute_script(_import=file)
elif args.mode == "run":
    file = "nanomind-bsp-fast.elf" if args.fast else "nanomind-bsp-new.elf"
    execute_script(args.script, process=file)

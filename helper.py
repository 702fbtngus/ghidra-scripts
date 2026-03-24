#!/bin/python3

import subprocess
import argparse
from pathlib import Path

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
parser_emul.add_argument("--version", type=int)

# compare mode
parser_compare = subparsers.add_parser("compare")
parser_compare.add_argument("left")
parser_compare.add_argument("right")

# import mode
parser_list = subparsers.add_parser("import")
parser_list.add_argument("--fast", action="store_true")
# parser_list.add_argument("file")

# manual run mode
parser_run = subparsers.add_parser("run")
parser_run.add_argument("script")
parser_run.add_argument("--fast", action="store_true")

# vscode timeline restore mode
parser_timeline = subparsers.add_parser("timeline")
parser_timeline.add_argument("timeline_command", choices=["list", "restore"])
parser_timeline.add_argument("--workspace", default=".")
parser_timeline.add_argument("--history-root")
parser_timeline.add_argument("--version", type=int)
parser_timeline.add_argument("--dest")
parser_timeline.add_argument("--empty-base", action="store_true")
parser_timeline.add_argument("--strict", action="store_true")
parser_timeline.add_argument("--non-interactive", action="store_true")

args = parser.parse_args()

def execute_script(script=None, args=None, process=None, _import=None, to_main=False, script_path=None, workdir=None):
    if args is None:
        args = []

    runargs = [
        "/home/fbtngus/ghidra-randev/build/dist/ghidra_12.0_DEV/support/analyzeHeadless",
        "/home/fbtngus/ghidra-projects", "RandevGhidra",
        # "-scriptPath", "/home/fbtngus/ghidra-scripts",
        # "-postScript", script, *args,
        # "-noanalysis",
        # "-process", firmware,
    ]
    if script:
        if script_path is None:
            script_path = "/home/fbtngus/ghidra-scripts"
        runargs += [
            "-scriptPath", script_path,
            "-postScript", script, *args,
        ]
        if to_main:
            runargs.append("--to-main")
    if process:
        runargs += ["-process", process, "-noanalysis"]
    if _import:
        runargs += ["-import", _import]

    subprocess.run(runargs, cwd=workdir)


def build_restore_dir(version):
    # Keep restored snapshots outside the Ghidra script root so Java script bundle
    # compilation does not scan duplicate sources under tmp/version-*.
    return Path("/tmp/ghidra-scripts-timeline") / f"version-{version:02d}"


def restore_version(version, strict=False):
    dest = build_restore_dir(version)
    runargs = [
        "python3",
        "/home/fbtngus/ghidra-scripts/vscode_timeline_restore.py",
        "--workspace", "/home/fbtngus/ghidra-scripts",
        "restore",
        "--version", str(version),
        "--non-interactive",
        "--dest", str(dest),
    ]
    if strict:
        runargs.append("--strict")
    subprocess.run(runargs, check=True)
    return dest


def resolve_compare_target(value):
    if value == "current":
        return Path("/home/fbtngus/ghidra-scripts")

    try:
        version = int(value)
    except ValueError as exc:
        raise SystemExit(
            f"Invalid compare target {value!r}. Use a version number or 'current'."
        ) from exc

    return restore_version(version, strict=False)

if args.mode == "list":
    execute_script("helper/ProjectManager.java", ["list"])
elif args.mode == "del":
    execute_script("helper/ProjectManager.java", ["delete", args.file])
elif args.mode == "emul":
    file = "nanomind-bsp-fast.elf" if args.fast else "nanomind-bsp-new.elf"
    emul_args = []
    if args.num_instr is not None:
        emul_args.append(f"--num-instr={args.num_instr}")
    script_path = "/home/fbtngus/ghidra-scripts"
    workdir = None
    if args.version is not None:
        restored_dir = restore_version(args.version, strict=False)
        script_path = str(restored_dir)
        workdir = str(restored_dir)
    execute_script(
        "CubeSatEmulator.java",
        emul_args,
        process=file,
        to_main=True,
        script_path=script_path,
        workdir=workdir,
    )
    # execute_script("CubeSatEmulator.java", emul_args, process=file)
elif args.mode == "compare":
    left_dir = resolve_compare_target(args.left)
    right_dir = resolve_compare_target(args.right)
    runargs = [
        "diff",
        "--color=always",
        "-ruN",
        "--exclude=.git",
        "--exclude=.metals",
        "--exclude=.vscode",
        "--exclude=tmp",
        "--exclude=__pycache__",
        "--exclude=.vscode-timeline-restore-report.json",
        str(left_dir),
        str(right_dir),
    ]
    subprocess.run(runargs)
elif args.mode == "import":
    file = "nanomind-bsp-fast.elf" if args.fast else "nanomind-bsp-new.elf"
    filepath = "/home/fbtngus/ghidra-randev/build/dist/" + file
    execute_script("helper/ProjectManager.java", ["delete", file])
    execute_script(_import=filepath)
    execute_script("helper/PopulateDataLMA.java", process=file)
    execute_script("helper/ManualDisassemble.java", process=file)
elif args.mode == "run":
    file = "nanomind-bsp-fast.elf" if args.fast else "nanomind-bsp-new.elf"
    execute_script(args.script, process=file)
elif args.mode == "timeline":
    runargs = [
        "python3",
        "/home/fbtngus/ghidra-scripts/vscode_timeline_restore.py",
        "--workspace", args.workspace,
    ]
    if args.history_root:
        runargs += ["--history-root", args.history_root]

    runargs += [args.timeline_command]
    if args.version is not None:
        runargs += ["--version", str(args.version)]
    if args.dest:
        runargs += ["--dest", args.dest]
    if args.empty_base:
        runargs.append("--empty-base")
    if args.strict:
        runargs.append("--strict")
    if args.non_interactive:
        runargs.append("--non-interactive")

    subprocess.run(runargs)

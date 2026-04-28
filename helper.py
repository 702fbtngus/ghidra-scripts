#!/bin/python3

import argparse
import subprocess
from pathlib import Path

ANALYZE_HEADLESS = "/home/fbtngus/ghidra-randev/build/dist/ghidra_12.0_DEV/support/analyzeHeadless"
PROJECT_DIR = "/home/fbtngus/ghidra-projects"
PROJECT_NAME = "RandevGhidra"
SCRIPT_ROOT = "/home/fbtngus/ghidra-scripts"
FIRMWARE_ROOT = "/home/fbtngus/ghidra-randev/build/dist"
EMUL_SUFFIX = ".emul"

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(dest="mode", required=True)

parser_list = subparsers.add_parser("list")

parser_del = subparsers.add_parser("del")
parser_del.add_argument("file")

parser_emul = subparsers.add_parser("emul")
parser_emul.add_argument("--fast", action="store_true")
parser_emul.add_argument("--num-instr", type=int)
parser_emul.add_argument("--version", type=int)

parser_compare = subparsers.add_parser("compare")
parser_compare.add_argument("left")
parser_compare.add_argument("right")

parser_import = subparsers.add_parser("import")
parser_import.add_argument("--fast", action="store_true")

parser_callgraph = subparsers.add_parser("callgraph")
parser_callgraph.add_argument("--fast", action="store_true")

parser_run = subparsers.add_parser("run")
parser_run.add_argument("script")
parser_run.add_argument("--fast", action="store_true")

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


def execute_script(
    script=None,
    args=None,
    process=None,
    _import=None,
    to_main=False,
    script_path=None,
    workdir=None,
    check=True,
    capture_output=False,
):
    if args is None:
        args = []

    runargs = [
        ANALYZE_HEADLESS,
        PROJECT_DIR,
        PROJECT_NAME,
    ]
    if script:
        if script_path is None:
            script_path = SCRIPT_ROOT
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

    return subprocess.run(
        runargs,
        cwd=workdir,
        check=check,
        capture_output=capture_output,
        text=capture_output,
    )


def execute_project_manager(command_args, capture_output=False, check=True):
    return execute_script(
        script="helper/ProjectManager.java",
        args=command_args,
        capture_output=capture_output,
        check=check,
    )


def build_restore_dir(version):
    return Path("/tmp/ghidra-scripts-timeline") / f"version-{version:02d}"


def restore_version(version, strict=False):
    dest = build_restore_dir(version)
    runargs = [
        "python3",
        f"{SCRIPT_ROOT}/vscode_timeline_restore.py",
        "--workspace", SCRIPT_ROOT,
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
        return Path(SCRIPT_ROOT)

    try:
        version = int(value)
    except ValueError as exc:
        raise SystemExit(
            f"Invalid compare target {value!r}. Use a version number or 'current'."
        ) from exc

    return restore_version(version, strict=False)


def imported_program_name(use_fast):
    return "nanomind-bsp-fast.elf" if use_fast else "nanomind-bsp-new.elf"


def emulated_program_name(use_fast):
    return imported_program_name(use_fast) + EMUL_SUFFIX


def firmware_path(use_fast):
    return str(Path(FIRMWARE_ROOT) / imported_program_name(use_fast))


def project_file_exists(name):
    result = execute_project_manager(["exists", name], capture_output=True)
    for line in reversed(result.stdout.splitlines()):
        stripped = line.strip().lower()
        if stripped == "true" or "> true" in stripped:
            return True
        if stripped == "false" or "> false" in stripped:
            return False
    raise RuntimeError(f"Could not determine whether project file exists: {name}")


def delete_project_file(name):
    execute_project_manager(["delete", name])


def copy_project_file(src, dst):
    execute_project_manager(["copy", src, dst])


def require_project_file(name):
    if not project_file_exists(name):
        raise SystemExit(f"Project file not found: {name}")


def run_callgraph(process_name):
    execute_script(
        "CallGraphBuilder.java",
        ["--static-only", f"--output-subdir={process_name}"],
        process=process_name,
    )


if args.mode == "list":
    execute_project_manager(["list"])
elif args.mode == "del":
    delete_project_file(args.file)
elif args.mode == "emul":
    baseline_file = imported_program_name(args.fast)
    emul_file = emulated_program_name(args.fast)
    require_project_file(baseline_file)
    delete_project_file(emul_file)
    copy_project_file(baseline_file, emul_file)

    emul_args = []
    if args.num_instr is not None:
        emul_args.append(f"--num-instr={args.num_instr}")
    script_path = SCRIPT_ROOT
    workdir = None
    if args.version is not None:
        restored_dir = restore_version(args.version, strict=False)
        script_path = str(restored_dir)
        workdir = str(restored_dir)
    execute_script(
        "CubeSatEmulator.java",
        emul_args,
        process=emul_file,
        to_main=True,
        script_path=script_path,
        workdir=workdir,
    )
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
    subprocess.run(runargs, check=True)
elif args.mode == "import":
    baseline_file = imported_program_name(args.fast)
    emul_file = emulated_program_name(args.fast)
    delete_project_file(emul_file)
    delete_project_file(baseline_file)
    execute_script(_import=firmware_path(args.fast))
    execute_script("helper/PopulateDataLMA.java", process=baseline_file)
    execute_script("helper/ManualDisassemble.java", process=baseline_file)
elif args.mode == "callgraph":
    baseline_file = imported_program_name(args.fast)
    emul_file = emulated_program_name(args.fast)
    require_project_file(baseline_file)
    run_callgraph(baseline_file)
    if project_file_exists(emul_file):
        run_callgraph(emul_file)
    else:
        print(f"Skipping emulated program call graph; project file not found: {emul_file}")
elif args.mode == "run":
    execute_script(args.script, process=imported_program_name(args.fast))
elif args.mode == "timeline":
    runargs = [
        "python3",
        f"{SCRIPT_ROOT}/vscode_timeline_restore.py",
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

    subprocess.run(runargs, check=True)

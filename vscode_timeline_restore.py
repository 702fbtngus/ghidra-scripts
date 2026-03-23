#!/usr/bin/env python3

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote


KST = timezone(timedelta(hours=9), "KST")
DEFAULT_HISTORY_ROOTS = [
    Path.home() / ".vscode-server" / "data" / "User" / "History",
    Path.home() / ".config" / "Code" / "User" / "History",
    Path.home() / ".config" / "Code - OSS" / "User" / "History",
]


@dataclass(frozen=True)
class RestorePoint:
    version: int
    timestamp_text: str
    label: str

    @property
    def dt(self) -> datetime:
        return datetime.fromisoformat(self.timestamp_text.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )

    @property
    def dt_kst(self) -> datetime:
        return self.dt.astimezone(KST)


RESTORE_POINTS = [
    RestorePoint(1, "2026-03-19T01:29:49Z", "ExecuteManager first instrumentation"),
    RestorePoint(2, "2026-03-19T02:57:33Z", "TWIM and PDCA work starts"),
    RestorePoint(3, "2026-03-19T03:31:26Z", "MMIO device logging changes"),
    RestorePoint(4, "2026-03-19T04:45:05Z", "TWIM state-machine iteration"),
    RestorePoint(5, "2026-03-19T05:23:48Z", "PDCA draining loop rewrite"),
    RestorePoint(6, "2026-03-19T05:47:12Z", "TWIM follow-up adjustments"),
    RestorePoint(7, "2026-03-19T06:35:09Z", "ExecuteManager follow-up logging"),
    RestorePoint(8, "2026-03-19T07:58:22Z", "TC timing changes"),
    RestorePoint(9, "2026-03-19T08:28:56Z", "ExecuteManager deep debug pass"),
    RestorePoint(10, "2026-03-19T08:56:29Z", "TaskManager delay formatting"),
    RestorePoint(11, "2026-03-19T10:05:42Z", "TWIM late-morning pass"),
    RestorePoint(12, "2026-03-19T10:45:35Z", "TWIM CRDY and IMR pass"),
    RestorePoint(13, "2026-03-19T11:05:18Z", "TWIM final morning pass"),
    RestorePoint(14, "2026-03-19T13:46:17Z", "Last TWIM save"),
]


@dataclass(frozen=True)
class HistoryEntry:
    timestamp_ms: int
    file_path: Path
    snapshot_path: Path

    @property
    def dt(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc)

    @property
    def dt_kst(self) -> datetime:
        return self.dt.astimezone(KST)


@dataclass(frozen=True)
class GitEntry:
    commit: str
    timestamp: datetime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Restore this workspace from VS Code Timeline history."
    )
    parser.add_argument(
        "--workspace",
        default=".",
        help="Workspace root to restore. Defaults to the current directory.",
    )
    parser.add_argument(
        "--history-root",
        help="Explicit VS Code History directory. Defaults to common local paths.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="Show the built-in restore point versions.")

    restore_parser = subparsers.add_parser("restore", help="Restore one built-in version.")
    restore_parser.add_argument(
        "--version",
        type=int,
        help="Restore point number. If omitted, you will be prompted.",
    )
    restore_parser.add_argument(
        "--dest",
        help="Restore destination directory. Defaults to <workspace>/tmp/version-<N>.",
    )
    restore_parser.add_argument(
        "--empty-base",
        action="store_true",
        help="Do not seed the restore from the current workspace first.",
    )
    restore_parser.add_argument(
        "--strict",
        action="store_true",
        help="Alias for --empty-base. Restore only files backed by timeline history.",
    )
    restore_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Fail instead of prompting when --version is omitted.",
    )

    return parser.parse_args()


def resolve_workspace(path_str: str) -> Path:
    workspace = Path(path_str).expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"Workspace does not exist or is not a directory: {workspace}")
    return workspace


def resolve_history_root(explicit: str | None) -> Path:
    if explicit:
        root = Path(explicit).expanduser().resolve()
        if not root.is_dir():
            raise SystemExit(f"History root does not exist: {root}")
        return root

    for root in DEFAULT_HISTORY_ROOTS:
        if root.is_dir():
            return root.resolve()

    roots = ", ".join(str(p) for p in DEFAULT_HISTORY_ROOTS)
    raise SystemExit(f"Could not find a VS Code History directory. Tried: {roots}")


def decode_resource(resource: str) -> str:
    decoded = unquote(resource)
    marker = "://"
    if marker in decoded:
        prefix, rest = decoded.split(marker, 1)
        if prefix.startswith("vscode-remote"):
            first_slash = rest.find("/")
            if first_slash >= 0:
                decoded = rest[first_slash:]
    return decoded


def iter_entries(history_root: Path, workspace: Path) -> Iterable[HistoryEntry]:
    workspace_prefix = str(workspace) + os.sep

    for child in sorted(history_root.iterdir()):
        if not child.is_dir():
            continue
        entries_path = child / "entries.json"
        if not entries_path.is_file():
            continue

        try:
            data = json.loads(entries_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        resource = decode_resource(data.get("resource", ""))
        if not resource.startswith(workspace_prefix):
            continue

        file_path = Path(resource)
        for entry in data.get("entries", []):
            snapshot_id = entry.get("id")
            if not snapshot_id:
                continue
            snapshot_path = child / snapshot_id
            if not snapshot_path.is_file():
                continue
            yield HistoryEntry(
                timestamp_ms=int(entry["timestamp"]),
                file_path=file_path,
                snapshot_path=snapshot_path,
            )


def build_index(history_root: Path, workspace: Path) -> dict[Path, list[HistoryEntry]]:
    by_file: dict[Path, list[HistoryEntry]] = defaultdict(list)
    for entry in iter_entries(history_root, workspace):
        by_file[entry.file_path].append(entry)
    for entries in by_file.values():
        entries.sort(key=lambda item: item.timestamp_ms)
    if not by_file:
        raise SystemExit(f"No VS Code history entries found for workspace: {workspace}")
    return dict(by_file)


def list_workspace_files(workspace: Path) -> tuple[set[Path], set[Path]]:
    tracked_out = subprocess.run(
        ["git", "ls-files"],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    untracked_out = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()

    tracked = {
        (workspace / rel).resolve()
        for rel in tracked_out
        if rel.strip()
    }
    untracked = {
        (workspace / rel).resolve()
        for rel in untracked_out
        if rel.strip()
    }
    return tracked, untracked


def latest_history_before(entries: list[HistoryEntry], target_dt: datetime) -> HistoryEntry | None:
    chosen = None
    for entry in entries:
        if entry.dt <= target_dt:
            chosen = entry
        else:
            break
    return chosen


def latest_git_before(
    workspace: Path,
    relative_path: str,
    target_dt: datetime,
) -> GitEntry | None:
    proc = subprocess.run(
        ["git", "log", "--follow", "--format=%H%x09%cI", "--", relative_path],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=True,
    )
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        commit, iso_time = line.split("\t", 1)
        dt = datetime.fromisoformat(iso_time).astimezone(timezone.utc)
        if dt <= target_dt:
            return GitEntry(commit=commit, timestamp=dt)
    return None


def write_git_snapshot(dest: Path, workspace: Path, relative_path: str, commit: str) -> None:
    proc = subprocess.run(
        ["git", "show", f"{commit}:{relative_path}"],
        cwd=workspace,
        capture_output=True,
        check=True,
    )
    out_path = dest / relative_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(proc.stdout)


def get_restore_point(version: int) -> RestorePoint:
    for point in RESTORE_POINTS:
        if point.version == version:
            return point
    valid = ", ".join(str(point.version) for point in RESTORE_POINTS)
    raise SystemExit(f"Unknown version {version}. Valid versions: {valid}")


def prompt_for_version() -> RestorePoint:
    print("Available restore points:")
    for point in RESTORE_POINTS:
        print(
            f"{point.version:>2}. "
            f"{point.dt_kst.strftime('%Y-%m-%d %H:%M:%S KST')} | {point.label}"
        )

    while True:
        raw = input("Pick a version number: ").strip()
        try:
            version = int(raw)
        except ValueError:
            print("Please enter a number.")
            continue
        try:
            return get_restore_point(version)
        except SystemExit as exc:
            print(exc)


def ensure_dest(dest_arg: str | None, workspace: Path, point: RestorePoint) -> Path:
    if dest_arg:
        return Path(dest_arg).expanduser().resolve()
    return workspace / "tmp" / f"version-{point.version:02d}"


def reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def copy_workspace_base(workspace: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(
        workspace,
        dest,
        dirs_exist_ok=False,
        ignore=shutil.ignore_patterns("tmp"),
    )


def write_snapshot(dest: Path, workspace: Path, entry: HistoryEntry) -> None:
    rel_path = entry.file_path.relative_to(workspace)
    out_path = dest / rel_path
    out_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(entry.snapshot_path, out_path)


def restore_workspace(
    workspace: Path,
    dest: Path,
    index: dict[Path, list[HistoryEntry]],
    point: RestorePoint,
    empty_base: bool,
) -> dict[str, object]:
    if empty_base:
        reset_dir(dest)
    else:
        copy_workspace_base(workspace, dest)

    tracked_files, untracked_files = list_workspace_files(workspace)
    candidate_files = sorted(
        path for path in (tracked_files | untracked_files)
        if path.exists() and path.is_file()
    )

    restored_history_count = 0
    restored_git_count = 0
    future_only_files: list[str] = []

    for file_path in candidate_files:
        rel_path = os.path.relpath(file_path, workspace)
        history_entry = latest_history_before(index.get(file_path, []), point.dt)
        git_entry = None
        if file_path in tracked_files:
            git_entry = latest_git_before(workspace, rel_path, point.dt)

        if history_entry and (git_entry is None or history_entry.dt >= git_entry.timestamp):
            write_snapshot(dest, workspace, history_entry)
            restored_history_count += 1
            continue

        if git_entry is not None:
            write_git_snapshot(dest, workspace, rel_path, git_entry.commit)
            restored_git_count += 1
            continue

        if empty_base:
            future_only_files.append(rel_path)
        else:
            # Overlay mode keeps the current file when there is no historical evidence.
            if empty_base:
                future_only_files.append(rel_path)

    report = {
        "version": point.version,
        "selected_time_utc": point.dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "selected_time_kst": point.dt_kst.strftime("%Y-%m-%d %H:%M:%S KST"),
        "label": point.label,
        "destination": str(dest),
        "restored_snapshot_files": restored_history_count + restored_git_count,
        "restored_from_history": restored_history_count,
        "restored_from_git": restored_git_count,
        "future_only_files": future_only_files,
    }
    report_path = dest / ".vscode-timeline-restore-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def cmd_list() -> int:
    print("Available restore points:")
    for point in RESTORE_POINTS:
        print(
            f"{point.version:>2}. "
            f"{point.dt_kst.strftime('%Y-%m-%d %H:%M:%S KST')} | {point.label}"
        )
    return 0


def cmd_restore(args: argparse.Namespace, workspace: Path, history_root: Path) -> int:
    if args.version is None:
        if args.non_interactive:
            raise SystemExit("--version is required with --non-interactive.")
        point = prompt_for_version()
    else:
        point = get_restore_point(args.version)

    index = build_index(history_root, workspace)
    dest = ensure_dest(args.dest, workspace, point)
    use_empty_base = args.empty_base or args.strict
    report = restore_workspace(workspace, dest, index, point, use_empty_base)

    print(f"Version: {report['version']}")
    print(f"Selected restore point: {report['selected_time_kst']}")
    print(f"Label: {report['label']}")
    print(f"Restored into: {report['destination']}")
    print(f"Files restored from history: {report['restored_snapshot_files']}")
    print(f"  history: {report['restored_from_history']}")
    print(f"  git: {report['restored_from_git']}")
    if report["future_only_files"]:
        print(f"Files with no older snapshot: {len(report['future_only_files'])}")
    print(f"Report: {Path(report['destination']) / '.vscode-timeline-restore-report.json'}")
    if use_empty_base:
        print("Mode: strict restore (history-backed files only)")
    else:
        print("Mode: overlay restore (current workspace + historical overrides)")
    return 0


def main() -> int:
    args = parse_args()
    workspace = resolve_workspace(args.workspace)
    history_root = resolve_history_root(args.history_root)

    if args.command == "list":
        return cmd_list()
    return cmd_restore(args, workspace, history_root)


if __name__ == "__main__":
    sys.exit(main())

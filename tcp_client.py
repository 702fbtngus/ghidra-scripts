#!/bin/python3

import argparse
import binascii
from collections import Counter
import contextlib
from pathlib import Path
import socket
import sys
import threading
import time

HOST = "127.0.0.1"
PORT = 10001
LOG_SOURCES = ("ghidra", "qemu")

# Keep commands that are backed by both the Java device emulation and the
# firmware-side randev_sys_run_* handlers.
DEVICE_HEX = {
    "utx": [
        "00 00 00 00 28 41 00",       # utx_get_state()
        "00 00 00 00 28 25 00",       # utx_get_telemetries()
        "00 00 00 00 28 10 05 1C ED C0 FF EE",       # utx_send_frame()
        "00 00 00 00 28 24 01 08",    # utx_set_idle()
        "00 00 00 00 28 28 01 08",    # utx_set_bitrate()
        "00 00 00 00 28 40 00",       # utx_get_uptime()
    ],
    "vrx": [
        "00 00 00 00 29 21 00",       # vrx_get_frames()
        "00 00 00 00 29 22 00",       # vrx_get_frame()
        "00 00 00 00 29 24 00",       # vrx_remove_frame()
        "00 00 00 00 29 1A 00",       # vrx_get_telemetries()
        "00 00 00 00 29 40 00",       # vrx_get_uptime()
        "00 00 00 00 29 1A 00",       # vrx_get_telemetries()
    ],
    "eps": [
        "00 00 00 00 1E 01 00",       # eps_get_status()
        "00 00 00 00 1E 21 01 0A",    # eps_set_watchdog_period(10)
        "00 00 00 00 1E 01 00",       # eps_get_status()
        "00 00 00 00 1E 22 00",       # eps_set_watchdog_period_reset()
        "00 00 00 00 1E 80 00",       # eps_reset_manual()
        "00 00 00 00 1E 45 00",       # eps_set_all_pdm_init()
        "00 00 00 00 1E 40 00",       # eps_set_all_pdm_on()
        "00 00 00 00 1E 41 00",       # eps_set_all_pdm_off()
    ],
    "uvant": [
        "00 00 00 00 32 AA 00",       # uvant_reset()
        "00 00 00 00 32 C3 00",       # uvant_get_status_deploy() after reset
        "00 00 00 00 32 AD 00",       # uvant_arm()
        "00 00 00 00 32 C3 00",       # uvant_get_status_deploy() after arm
        "00 00 00 00 32 AC 00",       # uvant_disarm()
        "00 00 00 00 32 C3 00",       # uvant_get_status_deploy() after disarm
        "00 00 00 00 32 C0 00",       # uvant_get_temp()
    ],
    "adcs": [
        "00 00 00 00 3C 80 00",       # adcs_tm_get_ident()
        "00 00 00 00 3C 84 00",       # adcs_tm_get_current_state()
        "00 00 00 00 3C 8C 00",       # adcs_tm_get_current_time()
        "00 00 00 00 3C 92 00",       # adcs_tm_get_est_attitude()
        "00 00 00 00 3C 93 00",       # adcs_tm_get_est_rates()
        "00 00 00 00 3C DA 00",       # adcs_tm_get_est_quat()
        "00 00 00 00 3D 01 00",       # adcs_tc_reset()
        "00 00 00 00 3D 03 01 01",    # adcs_tc_enable_cache(1)
        "00 00 00 00 3D 06 00",       # adcs_tc_reset_boot_register()
    ],
    "hstx": [
        "00 00 00 00 46 11 00",       # hstx_get_firmware_version()
        "00 00 00 00 46 12 00",       # hstx_get_status_register()
        "00 00 00 00 46 13 00",       # hstx_get_ready_register()
        "00 00 00 00 46 05 00",       # hstx_reset_register()
        "00 00 00 00 46 00 00",       # hstx_get_control_register()
        "00 00 00 00 46 C0 00",       # hstx_set_pa_disable_configuration()
        "00 00 00 00 46 00 00",       # hstx_get_control_register()
        "00 00 00 00 46 C1 00",       # hstx_set_pa_disable_synchronisation()
        "00 00 00 00 46 00 00",       # hstx_get_control_register()
        "00 00 00 00 46 C2 00",       # hstx_set_pa_enable_synchronisation()
        "00 00 00 00 46 00 00",       # hstx_get_control_register()
        "00 00 00 00 46 C3 00",       # hstx_set_pa_enable_data()
        "00 00 00 00 46 00 00",       # hstx_get_control_register()
        "00 00 00 00 46 C4 00",       # hstx_set_pa_enable_test_data()
        "00 00 00 00 46 00 00",       # hstx_get_control_register()
    ],
}

DEFAULT_DEVICE_ORDER = ["utx", "vrx"]
# DEFAULT_DEVICE_ORDER = ["utx", "vrx", "eps", "uvant", "adcs", "hstx"]
DEFAULT_BATCH_SIZE = 30
DEFAULT_BATCH_TIMEOUT_SECONDS = 0.0
VRX_REMOVE_FRAME_KEY = (0x29, 0x24)


class TeeStream:
    def __init__(self, *streams):
        self.streams = streams
        self.lock = threading.Lock()
        self.encoding = getattr(streams[0], "encoding", "utf-8")

    def write(self, data: str) -> int:
        with self.lock:
            for stream in self.streams:
                stream.write(data)
                stream.flush()
        return len(data)

    def flush(self):
        with self.lock:
            for stream in self.streams:
                stream.flush()

    def isatty(self) -> bool:
        return any(getattr(stream, "isatty", lambda: False)() for stream in self.streams)


@contextlib.contextmanager
def tee_output(log_path: Path):
    log_file = log_path.open("w", encoding="utf-8")
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    stdout_tee = TeeStream(original_stdout, log_file)
    stderr_tee = TeeStream(original_stderr, log_file)
    try:
        sys.stdout = stdout_tee
        sys.stderr = stderr_tee
        yield
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr
        log_file.close()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        choices=LOG_SOURCES,
        default="ghidra",
        help="Label for the dump log file name (default: %(default)s)",
    )
    parser.add_argument(
        "--device",
        default="all",
        help="Target device to test: all, utx, vrx, eps, uvant, adcs, hstx",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Number of commands to send before waiting for replies (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--batch-timeout",
        type=float,
        default=DEFAULT_BATCH_TIMEOUT_SECONDS,
        help=(
            "Seconds to wait for all command replies in a batch before reconnecting; "
            f"0 waits forever (default: {DEFAULT_BATCH_TIMEOUT_SECONDS:g})"
        ),
    )
    return parser.parse_args()


def unhexlify(s: str) -> bytes:
    return binascii.unhexlify("".join(s.split()))


def to_hex(b: bytes) -> str:
    h = binascii.hexlify(b).decode().upper()
    return " ".join(h[i:i + 2] for i in range(0, len(h), 2))


def get_log_path(source_name: str) -> Path:
    return Path(__file__).with_name(f"response_{source_name.lower()}.log")


def get_hex_commands(device_name: str):
    normalized = device_name.lower()
    if normalized == "all":
        commands = []
        for device in DEFAULT_DEVICE_ORDER:
            commands.extend(DEVICE_HEX[device])
        return commands

    if normalized not in DEVICE_HEX:
        valid = ", ".join(["all"] + list(DEVICE_HEX.keys()))
        raise ValueError(f"Unknown device '{device_name}'. Valid values: {valid}")

    return DEVICE_HEX[normalized]


def get_command_key(payload: bytes):
    if len(payload) < 6:
        return None
    return (payload[4], payload[5])


def get_response_key(payload: bytes):
    if len(payload) < 2:
        return None
    return (payload[0], payload[1])


def format_command_key(command_key):
    if command_key is None:
        return "?? ??"
    return f"{command_key[0]:02X} {command_key[1]:02X}"


def get_effective_batch_payloads(payloads):
    effective_payloads = []
    index = 0
    while index < len(payloads):
        payload = payloads[index]
        effective_payloads.append(payload)
        if get_command_key(payload) == VRX_REMOVE_FRAME_KEY and index + 1 < len(payloads):
            index += 2
            continue
        index += 1
    return effective_payloads


class BatchReplyTracker:
    def __init__(self):
        self.condition = threading.Condition()
        self.expected = Counter()
        self.received = Counter()

    def start_batch(self, payloads):
        with self.condition:
            self.expected = Counter(
                command_key
                for payload in get_effective_batch_payloads(payloads)
                if (command_key := get_command_key(payload)) is not None
            )
            self.received = Counter()

    def record_response(self, payload: bytes):
        response_key = get_response_key(payload)
        if response_key is None:
            return None

        with self.condition:
            if self.expected[response_key] <= self.received[response_key]:
                return None

            self.received[response_key] += 1
            matched = self.received[response_key]
            total = self.expected[response_key]
            remaining = self.remaining_locked()
            self.condition.notify_all()
            return response_key, matched, total, remaining

    def wait_until_complete(self, disconnected: threading.Event, timeout_seconds: float):
        deadline = None if timeout_seconds <= 0 else time.monotonic() + timeout_seconds
        with self.condition:
            while self.remaining_locked() > 0 and not disconnected.is_set():
                timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
                if timeout == 0.0:
                    break
                self.condition.wait(timeout)

            return self.remaining_locked() == 0

    def snapshot_remaining(self):
        with self.condition:
            return self.remaining_counter_locked()

    def remaining_locked(self):
        return sum(self.remaining_counter_locked().values())

    def remaining_counter_locked(self):
        return +(self.expected - self.received)


def recv_loop(sock: socket.socket, disconnected: threading.Event, reply_tracker: BatchReplyTracker):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[!] 서버가 연결을 종료했습니다.")
                disconnected.set()
                with reply_tracker.condition:
                    reply_tracker.condition.notify_all()
                return
            print(f"\nRecv({len(data)}): {to_hex(data)}")
            match = reply_tracker.record_response(data)
            if match is not None:
                command_key, matched, total, remaining = match
                print(
                    f"[+] matched reply {format_command_key(command_key)} "
                    f"({matched}/{total}, batch remaining: {remaining})"
                )
    except OSError as e:
        print(f"\n[!] 수신 에러: {e}")
        disconnected.set()
        with reply_tracker.condition:
            reply_tracker.condition.notify_all()


def chunked(sequence, size):
    for index in range(0, len(sequence), size):
        yield sequence[index:index + size]


def format_remaining(counter: Counter):
    if not counter:
        return "none"
    return ", ".join(
        f"{format_command_key(command_key)} x{count}"
        for command_key, count in sorted(counter.items())
    )


def main(args):
    try:
        hex_commands = get_hex_commands(args.device)
    except ValueError as e:
        print(f"[!] {e}")
        return

    if args.batch_size <= 0:
        print("[!] --batch-size must be greater than 0")
        return

    print(f"[+] log source: {args.source} -> {get_log_path(args.source).name}")
    print(f"[+] device filter: {args.device} ({len(hex_commands)} commands)")

    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print("[+] 서버에 연결 중...")
            while True:
                try:
                    s.connect((HOST, PORT))
                    break
                except (ConnectionRefusedError, OSError):
                    time.sleep(1)

            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            disconnected = threading.Event()
            reply_tracker = BatchReplyTracker()
            t = threading.Thread(target=recv_loop, args=(s, disconnected, reply_tracker), daemon=True)
            t.start()

            should_retry = False
            encoded_commands = [unhexlify(hex_str) for hex_str in hex_commands]

            for batch_index, batch_payloads in enumerate(chunked(encoded_commands, args.batch_size), start=1):
                reply_tracker.start_batch(batch_payloads)
                print(f"[+] batch {batch_index}: sending {len(batch_payloads)} commands")

                for payload in batch_payloads:
                    s.sendall(payload)
                    print(f"Sent({len(payload)}): {to_hex(payload)}")
                    time.sleep(0.1)

                print(f"[+] batch {batch_index}: waiting for {len(batch_payloads)} command replies...")
                completed = reply_tracker.wait_until_complete(disconnected, args.batch_timeout)
                if disconnected.is_set():
                    should_retry = True
                    break
                if not completed:
                    remaining = reply_tracker.snapshot_remaining()
                    print(
                        f"[!] batch {batch_index}: timed out waiting for replies "
                        f"({format_remaining(remaining)})"
                    )
                    should_retry = True
                    break

                print(f"[+] batch {batch_index}: all command replies received")

            if should_retry:
                continue

            while not disconnected.is_set():
                time.sleep(0.1)


if __name__ == "__main__":
    args = parse_args()
    with tee_output(get_log_path(args.source)):
        main(args)

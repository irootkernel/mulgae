#!/usr/bin/env python3
"""Run the fixed live-provider recipe in the guest user's Aqua audit session."""
from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import pwd
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

import guest
from haepari_inputs import (
    Refusal, regular_bytes, remove_owned_tree, validate_guest_identity, verify_sealed_bundle,
)


def send(sock: socket.socket, value: dict) -> None:
    raw = json.dumps(value).encode()
    if len(raw) > 1024 * 1024:
        raise Refusal("GUI control message exceeds its metadata bound")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def receive(sock: socket.socket) -> dict:
    def exact(size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = sock.recv(size - len(chunks))
            if not chunk:
                raise Refusal("GUI caller lifeline closed")
            chunks.extend(chunk)
        return bytes(chunks)
    size = struct.unpack("!I", exact(4))[0]
    if size > 1024 * 1024:
        raise Refusal("GUI control message exceeds its metadata bound")
    value = json.loads(exact(size))
    if not isinstance(value, dict):
        raise Refusal("GUI control message is not an object")
    return value


def alive(pid: int, group: bool = False) -> bool:
    try:
        (os.killpg if group else os.kill)(pid, 0)
        return True
    except ProcessLookupError:
        return False


def drain(proc: subprocess.Popen) -> bool:
    # guest.py's interrupt handler waits its nested command before fixture cleanup.
    for sig, budget in ((signal.SIGINT, 25), (signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        if not alive(proc.pid, group=True):
            break
        os.killpg(proc.pid, sig)
        try:
            proc.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            continue
        deadline = time.monotonic() + 1
        while alive(proc.pid, group=True) and time.monotonic() < deadline:
            time.sleep(0.02)
    proc.wait(timeout=5)
    return not alive(proc.pid, group=True)


def run_command(argv: list[str], cwd: Path, env: dict, log, lifeline: socket.socket) -> dict:
    """Supervise one owned process group; EOF or any caller input cancels it."""
    stopped = False

    def on_signal(_signum, _frame):
        nonlocal stopped
        stopped = True

    previous = {sig: signal.signal(sig, on_signal) for sig in (signal.SIGINT, signal.SIGTERM)}
    proc = None
    cancelled = False
    drained = False
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        send(lifeline, {"guest_pid": proc.pid})
        while proc.poll() is None:
            if stopped or select.select([lifeline], [], [], 0.05)[0]:
                cancelled = True
                break
        drained = drain(proc)
        return {"exit_code": proc.returncode, "cancelled": cancelled,
                "guest_pid": proc.pid, "guest_group_drained": drained}
    finally:
        if proc is not None and not drained:
            drain(proc)
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def child(socket_path: Path) -> int:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(20)
        conn.connect(str(socket_path))
        send(conn, {"helper_pid": os.getpid()})
        handoff = receive(conn)
        args = handoff["args"]
        if len(args) != 7 or args[:2] != ["live-providers", "auto"]:
            raise Refusal("GUI helper only runs the live-provider recipe")
        env = handoff["environment"]
        env["HOME"] = pwd.getpwuid(os.getuid()).pw_dir
        cursor_source = "inherited"
        if not env.get("CURSOR_AUTH_TOKEN"):
            token = subprocess.run(
                ["/usr/bin/security", "find-generic-password", "-a", "cursor-user",
                 "-s", "cursor-access-token", "-w"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if token.returncode or not token.stdout.strip():
                raise Refusal("approved guest-native Cursor token is unavailable")
            env["CURSOR_AUTH_TOKEN"] = token.stdout.strip()
            cursor_source = "guest_native_keychain"
        results = Path(args[6])
        with (results / "gui-guest.log").open("xb") as log:
            os.chmod(log.name, 0o600)
            outcome = run_command(
                [sys.executable, "-B", str(Path(__file__).with_name("guest.py")), *args],
                Path(args[5]), env, log, conn,
            )
        outcome["cursor_token_source"] = cursor_source
        guest.write_json(results / "gui-worker-result.json", outcome)
        try:
            send(conn, outcome)
        except OSError:
            pass  # The owned worker result remains available after caller loss.
        return 0 if outcome["guest_group_drained"] else 3


def launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/launchctl", *args], capture_output=True, timeout=15, check=False)


def parent(args: list[str]) -> int:
    if len(args) != 7 or args[:2] != ["live-providers", "auto"]:
        raise Refusal("GUI runner only supports automatic live-provider execution")
    bundle, results = Path(args[5]).resolve(), Path(args[6]).resolve()
    verify_sealed_bundle(bundle)
    request = json.loads(regular_bytes(bundle / "profiles/execution-request.json"))
    os_name = subprocess.check_output(["/usr/bin/uname", "-s"], text=True).strip()
    hypervisor = subprocess.check_output(
        ["/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"], text=True).strip()
    hardware = subprocess.check_output(
        ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], text=True)
    uuid_line = next(line for line in hardware.splitlines() if '"IOPlatformUUID"' in line)
    actual_uuid = uuid_line.split('"')[-2].upper()
    native = validate_guest_identity(
        os.environ.get("HAEPARI_PARENT_CONTEXT", ""), os_name, hypervisor, actual_uuid,
        request["guest"]["expected_hardware_uuid"], request["haepari"]["installation_id"],
    )
    if (args[2], int(args[3]), args[4]) != (
            native["job_id"], native["lease_generation"], actual_uuid):
        raise Refusal("GUI arguments differ from the admitted native guest identity")
    identity = guest.binding(request, args[2], int(args[3]), args[4])
    args = [*args[:5], str(bundle), str(results)]
    results.mkdir(parents=True, exist_ok=True)
    state = Path(tempfile.mkdtemp(prefix="mulgae-gui-", dir="/private/tmp")).resolve()
    info = state.stat()
    label = "io.rootkernel.mulgae.vm-gui." + state.name
    domain = f"gui/{os.getuid()}"
    service = domain + "/" + label
    plist = state / "helper.plist"
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": [sys.executable, "-B", str(Path(__file__).resolve()),
                             "--child", str(state / "s")],
        "RunAtLoad": True, "KeepAlive": False, "LimitLoadToSessionType": "Aqua",
        "WorkingDirectory": str(bundle),
        "EnvironmentVariables": {"PYTHONDONTWRITEBYTECODE": "1"},
    }))
    plist.chmod(0o600)
    stopped = False

    def on_signal(_signum, _frame):
        nonlocal stopped
        stopped = True

    previous = {sig: signal.signal(sig, on_signal) for sig in (signal.SIGINT, signal.SIGTERM)}
    conn = None
    helper_pid = None
    outcome = {}
    gaps = []
    bootstrap_attempted = False
    service_absent = False
    helper_gone = False
    state_removed = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(state / "s"))
            os.chmod(state / "s", 0o600)
            listener.listen(1)
            listener.settimeout(20)
            bootstrap_attempted = True
            if launchctl("bootstrap", domain, str(plist)).returncode:
                raise Refusal("normal guest Aqua session is unavailable")
            conn, _ = listener.accept()
        conn.settimeout(20)
        helper_pid = int(receive(conn)["helper_pid"])
        send(conn, {"args": args, "environment": dict(os.environ)})
        started = receive(conn)
        outcome["guest_pid"] = int(started["guest_pid"])
        while not stopped:
            if select.select([conn], [], [], 0.1)[0]:
                outcome = receive(conn)
                break
        if stopped:
            conn.sendall(b"!")
            conn.settimeout(40)
            outcome = receive(conn)
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        gaps.append(str(exc))
    finally:
        if conn is not None:
            conn.close()  # EOF also tells the helper to drain, including failed handoff.
        # Joining precedes bootout, which otherwise can kill a still-draining helper.
        if helper_pid:
            deadline = time.monotonic() + 40
            while alive(helper_pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            helper_gone = not alive(helper_pid)
        if bootstrap_attempted:
            bootout = launchctl("bootout", service)
            probe = launchctl("print", service)
            # launchctl's documented missing-service error is distinct from permission failure.
            service_absent = probe.returncode == 113
            if not helper_pid:
                helper_gone = bootout.returncode == 113 and service_absent
        group_gone = bool(outcome.get("guest_group_drained"))
        if outcome.get("guest_pid"):
            group_gone = group_gone and not alive(int(outcome["guest_pid"]), group=True)
        physical_drain = helper_gone and service_absent and group_gone
        if physical_drain:
            current = state.lstat()
            handles = subprocess.run(
                ["/usr/sbin/lsof", "-n", "-P", "-t", "+D", str(state)],
                capture_output=True, timeout=10, check=False,
            )
            if ((current.st_dev, current.st_ino, current.st_uid, current.st_mode & 0o777)
                    == (info.st_dev, info.st_ino, os.getuid(), 0o700)
                    and handles.returncode == 1 and not handles.stdout and not handles.stderr):
                remove_owned_tree(state)
                state_removed = True
        guest.write_json(results / "gui-execution.json", dict(
            identity, schema="mulgae.vm-gui-execution/v1",
            guest_result=outcome, cancelled=stopped, gaps=gaps,
            helper_pid=helper_pid, helper_gone=helper_gone, service_absent=service_absent,
            drain_status="verified" if physical_drain else "unverified",
            cleanup_status="clean" if state_removed else "unverified",
            remaining_owned_roots=[] if state_removed else [str(state)],
            limits="Guest fixture cleanup and native Job cleanup are separate observations.",
        ))
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    if gaps or stopped or not state_removed or not outcome.get("guest_group_drained"):
        return 3
    code = int(outcome.get("exit_code", 3))
    return code if code >= 0 else 128 - code


def main() -> int:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "--child":
            return child(Path(sys.argv[2]))
        return parent(sys.argv[1:])
    except (Refusal, OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as exc:
        print("refused: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

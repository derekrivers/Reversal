#!/usr/bin/env python3
"""One-consent, local-only broker for bounded pinned-game reference capture.

The elevated server accepts only inventory, snapshot, watch, ping and stop.
Capture requests invoke the independently checked helper, which authenticates
the executable, process and thread and writes exclusively beneath results/.
No raw register or memory content crosses this socket.
"""
from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
CAPTURE = ROOT / "scripts" / "reference_capture_37.py"
CAPTURE_SHA = "26ba36928b8e5d35f3b3b9ff40043f661a0f8a64bd549cd8f0f98a80e1d15d80"
MAX_WIRE = 4096
MAX_REQUESTS = 120
LIFETIME_SECONDS = 7200
SYSTEM32 = Path("C:/Windows/System32")


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def session_path(value: str) -> Path:
    path = Path(value).resolve()
    need(path.is_relative_to(RESULTS.resolve()) and path.suffix == ".json",
         "session file must be a new .json beneath ignored results/")
    return path


def read_line(sock: socket.socket, timeout: int = 10) -> dict:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) <= MAX_WIRE:
        remaining = deadline - time.monotonic()
        need(remaining > 0, "request framing deadline exceeded")
        sock.settimeout(remaining)
        block = sock.recv(1)
        need(block, "connection closed before request")
        if block == b"\n":
            value = json.loads(data)
            need(isinstance(value, dict), "request must be an object")
            return value
        data.extend(block)
    raise ValueError("request exceeds bound")


def send(sock: socket.socket, result: dict) -> None:
    payload = json.dumps(result, separators=(",", ":")).encode() + b"\n"
    need(len(payload) <= MAX_WIRE, "response exceeds bound")
    sock.sendall(payload)


def bounded_request(value: dict, token: str) -> tuple[str, int | None, int | None]:
    need(set(value) <= {"token", "mode", "pid", "thread"}, "unexpected request field")
    supplied = value.get("token")
    need(isinstance(supplied, str) and len(supplied) == 64 and
         all("0" <= ch <= "9" or "a" <= ch <= "f" for ch in supplied) and
         hmac.compare_digest(value["token"], token), "authentication failed")
    mode = value.get("mode")
    need(mode in ("ping", "inventory", "snapshot", "watch", "stop"), "unsupported mode")
    pid = value.get("pid")
    thread = value.get("thread")
    if mode in ("ping", "stop"):
        need(pid is None and thread is None, "control request has capture fields")
    else:
        need(type(pid) is int and 0 < pid <= 0xFFFFFFFF, "invalid PID")
        need(mode == "inventory" or (type(thread) is int and 0 < thread <= 0xFFFFFFFF),
             "snapshot/watch needs one thread")
        need(mode != "inventory" or thread is None, "inventory has no selected thread")
    return mode, pid, thread


def pinned_capture() -> dict:
    source = CAPTURE.read_bytes()
    need(hashlib.sha256(source).hexdigest() == CAPTURE_SHA, "capture implementation changed")
    scope = {"__name__": "reference_capture_37_broker_loaded", "__file__": str(CAPTURE)}
    exec(compile(source, str(CAPTURE), "exec"), scope)
    return scope


def private_session(path: Path, value: dict) -> None:
    """Restrict the empty file before writing the bearer secret into it."""
    with path.open("x", encoding="utf-8"):
        pass
    try:
        identity = subprocess.run([str(SYSTEM32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                                  check=True, capture_output=True, text=True)
        sid = next(csv.reader(identity.stdout.splitlines()))[1]
        need(sid.startswith("S-1-5-21-"), "unexpected user SID")
        acl = subprocess.run([str(SYSTEM32 / "icacls.exe"), str(path), "/inheritance:r",
                              "/grant:r", f"*{sid}:(F)", "*S-1-5-32-544:(F)",
                              "*S-1-5-18:(F)"], capture_output=True, text=True)
        need(acl.returncode == 0, "could not restrict broker session ACL")
        with path.open("w", encoding="utf-8") as stream:
            json.dump(value, stream)
            stream.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def capture_once(mode: str, pid: int, thread: int | None, exe: Path,
                 sequence: int, implementation: dict) -> dict:
    output = RESULTS / f"reference37-auto-{int(time.time())}-{sequence:03d}.json"
    need(hashlib.sha256(CAPTURE.read_bytes()).hexdigest() == CAPTURE_SHA,
         "capture implementation changed")
    settings = argparse.Namespace(mode=mode, pid=pid, exe=exe, output=output,
                                  thread=thread, region=[], samples=1000,
                                  seconds=30.0, interval_ms=10, boundary=0x7023E3,
                                  synthetic_sha256=None)
    with output.open("x", encoding="utf-8") as stream:
        try:
            result = implementation["capture"](settings)
            result["tool_sha256"] = CAPTURE_SHA  # executed bytes, not a later disk read
            json.dump(result, stream, indent=2)
            stream.write("\n")
        except (implementation["CaptureError"], OSError, ValueError) as error:
            json.dump({"private": True, "capture_accepted": False,
                       "error": str(error)}, stream)
            stream.write("\n")
            return {"ok": False, "error": "bounded capture failed",
                    "private_output": str(output)}
    return {"ok": True,
            "summary": {"profile": result["profile"], "stop_reason": result["stop_reason"],
                        "boundary_observed": result["boundary_observed"],
                        "probe_count": result["probe_count"], "private_output_written": True},
            "private_output": str(output)}


def serve(args: argparse.Namespace) -> int:
    need(os.name == "nt", "Windows required")
    need(args.test_only or bool(ctypes.windll.shell32.IsUserAnAdmin()),
         "production broker requires administrator token")
    target = session_path(args.session)
    need(not target.exists(), "refusing to replace broker session")
    exe = Path(args.exe).resolve(strict=True)
    implementation = None if args.test_only else pinned_capture()
    RESULTS.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(1)
        private_session(target, {"schema": "reversal.reference-broker-37.v1",
                                 "port": listener.getsockname()[1], "token": token,
                                 "test_only": args.test_only})
        try:
            deadline = time.monotonic() + (30 if args.test_only else LIFETIME_SECONDS)
            sequence = 0
            while sequence < MAX_REQUESTS and time.monotonic() < deadline:
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    try:
                        mode, pid, thread = bounded_request(
                            read_line(connection, timeout=max(0, min(10, deadline-time.monotonic()))),
                            token)
                        if mode == "ping":
                            answer = {"ok": True, "status": "ready", "test_only": args.test_only}
                        elif mode == "stop":
                            send(connection, {"ok": True, "status": "stopping"})
                            break
                        else:
                            need(not args.test_only, "test broker cannot capture")
                            sequence += 1
                            answer = capture_once(mode, pid, thread, exe, sequence, implementation)
                        send(connection, answer)
                    except (ValueError, OSError) as error:
                        try:
                            send(connection, {"ok": False, "error": str(error)})
                        except OSError:
                            pass
        finally:
            target.unlink(missing_ok=True)
    return 0


def request(args: argparse.Namespace) -> int:
    status = json.loads(session_path(args.session).read_text(encoding="utf-8"))
    need(status.get("schema") == "reversal.reference-broker-37.v1", "wrong session schema")
    port, token = status.get("port"), status.get("token")
    need(type(port) is int and 0 < port <= 65535 and isinstance(token, str) and len(token) == 64,
         "invalid broker session")
    message = {"token": token, "mode": args.mode}
    if args.mode in ("inventory", "snapshot", "watch"):
        message["pid"] = args.pid
    if args.mode in ("snapshot", "watch"):
        message["thread"] = args.thread
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        send(connection, message)
        response = read_line(connection, timeout=50)
    print(json.dumps(response))
    return 0 if response.get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", required=True)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--test-only", action="store_true")
    parser.add_argument("--exe")
    parser.add_argument("--mode", choices=("ping", "inventory", "snapshot", "watch", "stop"), default="ping")
    parser.add_argument("--pid", type=int)
    parser.add_argument("--thread", type=int)
    args = parser.parse_args()
    try:
        if args.serve:
            need(args.exe is not None and args.pid is None and args.thread is None,
                 "server requires only --exe")
            return serve(args)
        need(not args.test_only and args.exe is None, "client has server-only arguments")
        return request(args)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

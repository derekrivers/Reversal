#!/usr/bin/env python3
"""One-consent, local-only broker for bounded pinned-game reference capture.

The elevated server accepts only inventory, snapshot, watch, ping and stop.
Capture requests invoke the independently checked helper, which authenticates
the executable, process and thread and writes exclusively beneath results/.
No raw register or memory content crosses this socket.
"""
from __future__ import annotations

import argparse
import contextlib
import csv
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import msvcrt
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
CAPTURE = ROOT / "scripts" / "reference_capture_37.py"
CAPTURE_SHA = "e83f8a6142692ba6560e64c346830f541fc780d60ac5010106f60c0b6d89e7bd"
MAX_WIRE = 4096
MAX_REQUESTS = 120
LIFETIME_SECONDS = 7200
SYSTEM32 = Path("C:/Windows/System32")


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def session_path(value: str) -> Path:
    path = Path(os.path.abspath(value))
    need(path.parent == RESULTS and path.suffix == ".json" and
         path.name.isascii() and all(ch.isalnum() or ch in "-_." for ch in path.name) and
         ".." not in path.name,
         "session file must be a new .json directly in ignored results/")
    return path


FILE_READ_ATTRIBUTES = 0x80
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
CREATE_NEW = 1
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
INVALID_HANDLE = ctypes.c_void_p(-1).value


class FileAttributeTagInfo(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


class SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class FileDispositionInfo(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOL)]


@contextlib.contextmanager
def session_security(user_sid: str):
    """Provide a protected DACL before the bearer-secret file becomes visible."""
    need(user_sid.startswith("S-1-5-21-") and
         user_sid[len("S-1-5-21-"):].replace("-", "").isdigit(),
         "unexpected user SID")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{user_sid})"
    need(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None), "cannot build private session DACL")
    try:
        yield SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    finally:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.LocalFree.argtypes = [ctypes.c_void_p]
        kernel.LocalFree.restype = ctypes.c_void_p
        kernel.LocalFree(descriptor)


def file_api():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    api.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                 ctypes.c_void_p, wintypes.DWORD]
    api.GetFileInformationByHandleEx.restype = wintypes.BOOL
    api.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                               wintypes.DWORD, wintypes.DWORD]
    api.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    api.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                               ctypes.c_void_p, wintypes.DWORD]
    api.SetFileInformationByHandle.restype = wintypes.BOOL
    return api


def final_path(api, handle) -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = api.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
    need(0 < length < len(buffer), "cannot identify result handle path")
    name = buffer.value
    need(name.startswith("\\\\?\\") and not name.startswith("\\\\?\\UNC\\"),
         "unexpected result handle path")
    return Path(name[4:])


def mark_delete(api, handle) -> None:
    disposition = FileDispositionInfo(True)
    need(api.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition),
                                        ctypes.sizeof(disposition)),
         "cannot remove failed private output")


@contextlib.contextmanager
def guarded_result_directories(parent: Path | None = None):
    """Reject directory reparses and retain handles without delete sharing."""
    need(os.name == "nt", "Windows required")
    parent = RESULTS if parent is None else parent
    need(parent.is_relative_to(RESULTS) and ".." not in parent.parts,
         "private result parent outside results")
    api = file_api()
    handles = []
    try:
        directories = [ROOT, RESULTS]
        current = RESULTS
        for component in parent.relative_to(RESULTS).parts:
            current = current / component
            directories.append(current)
        for directory in directories:
            handle = api.CreateFileW(str(directory), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                                     None, OPEN_EXISTING,
                                     FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                     None)
            need(handle != INVALID_HANDLE, "cannot lock private result directory")
            handles.append(handle)
            info = FileAttributeTagInfo()
            need(api.GetFileInformationByHandleEx(handle, 9, ctypes.byref(info),
                                                  ctypes.sizeof(info)),
                 "cannot inspect private result directory")
            need(not info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT,
                 "private result directory is a reparse point")
            need(os.path.normcase(str(final_path(api, handle))) ==
                 os.path.normcase(str(directory)), "private result directory moved")
        yield api
    finally:
        for handle in reversed(handles):
            api.CloseHandle(handle)


@contextlib.contextmanager
def secure_new_result(path: Path, security: SecurityAttributes | None = None,
                      delete_on_failure: bool = False):
    """Create and write through one handle while result directories are locked."""
    need(path.is_relative_to(RESULTS) and ".." not in path.parts and path.suffix == ".json",
         "private result must be JSON beneath results")
    need(path.name.isascii() and all(ch.isalnum() or ch in "-_." for ch in path.name)
         and ".." not in path.name, "invalid private result filename")
    with guarded_result_directories(path.parent) as api:
        handle = api.CreateFileW(str(path), GENERIC_WRITE | DELETE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 ctypes.byref(security) if security is not None else None, CREATE_NEW,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, None)
        need(handle != INVALID_HANDLE, "private result already exists or cannot be created")
        try:
            need(os.path.normcase(str(final_path(api, handle))) ==
                 os.path.normcase(str(path)), "private result escaped ignored results")
            fd = msvcrt.open_osfhandle(handle, os.O_WRONLY)
        except BaseException:
            try:
                mark_delete(api, handle)
            finally:
                api.CloseHandle(handle)
            raise
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            try:
                yield stream
                stream.flush()  # Catch buffered write failures while deletion can use this handle.
            except BaseException:
                if delete_on_failure:
                    mark_delete(api, msvcrt.get_osfhandle(stream.fileno()))
                raise


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
    identity = subprocess.run([str(SYSTEM32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                              check=True, capture_output=True, text=True)
    sid = next(csv.reader(identity.stdout.splitlines()))[1]
    with session_security(sid) as security:
        with secure_new_result(path, security=security, delete_on_failure=True) as stream:
            acl = subprocess.run([str(SYSTEM32 / "icacls.exe"), str(path)],
                                  capture_output=True, text=True)
            need(acl.returncode == 0 and "(I)" not in acl.stdout and
                 "CodexSandboxUsers" not in acl.stdout,
                 "private session DACL was not applied at creation")
            json.dump(value, stream)
            stream.write("\n")


def capture_once(mode: str, pid: int, thread: int | None, exe: Path,
                 sequence: int, implementation: dict) -> dict:
    output = RESULTS / f"reference37-auto-{int(time.time())}-{sequence:03d}.json"
    need(hashlib.sha256(CAPTURE.read_bytes()).hexdigest() == CAPTURE_SHA,
         "capture implementation changed")
    settings = argparse.Namespace(mode=mode, pid=pid, exe=exe, output=output,
                                  thread=thread, region=[], samples=1000,
                                  seconds=30.0, interval_ms=10, boundary=0x7023E3,
                                  synthetic_sha256=None)
    with secure_new_result(output, delete_on_failure=True) as stream:
        try:
            result = implementation["capture"](settings)
        except (implementation["CaptureError"], OSError, ValueError) as error:
            json.dump({"private": True, "capture_accepted": False,
                       "error": str(error)}, stream)
            stream.write("\n")
            return {"ok": False, "error": "bounded capture failed",
                    "private_output": str(output)}
        result["tool_sha256"] = CAPTURE_SHA  # executed bytes, not a later disk read
        json.dump(result, stream, indent=2)
        stream.write("\n")
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
            with guarded_result_directories():
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

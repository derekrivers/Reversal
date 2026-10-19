"""Private, bounded WOW64 sampling. Never launches, patches or writes a target.

The game profile always requires the pinned disk hash. Synthetic mode exists for
the companion checker and must be labelled separately in every receipt.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import time

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
PREFERRED_BASE = 0x400000
BOUNDARY = 0x7023E3
MAX_REGION = 4096
MAX_BYTES = 16384
MAX_THREADS = 64
ROOT = Path(__file__).resolve().parents[1]


class CaptureError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pe_identity(path):
    """Parse only bounded PE headers; file offsets are never called VAs."""
    with path.open("rb") as stream:
        header = stream.read(4096)
    require(header[:2] == b"MZ" and len(header) >= 64, "not a DOS image")
    nt = struct.unpack_from("<I", header, 60)[0]
    require(64 <= nt <= 2048 and header[nt:nt+4] == b"PE\0\0", "invalid bounded PE header")
    machine, count, stamp = struct.unpack_from("<HHI", header, nt+4)
    optional_size = struct.unpack_from("<H", header, nt+20)[0]
    optional = nt+24
    require(machine == 0x14C and 1 <= count <= 32 and optional_size >= 96,
            "only PE32 x86 images are supported")
    require(optional + optional_size + 40*count <= len(header), "PE headers exceed bound")
    require(struct.unpack_from("<H", header, optional)[0] == 0x10B, "not PE32")
    base = struct.unpack_from("<I", header, optional+28)[0]
    size = struct.unpack_from("<I", header, optional+56)[0]
    sections = []
    for index in range(count):
        offset = optional+optional_size+40*index
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", header, offset+8)
        sections.append((rva, virtual_size, raw_size, raw_offset))
    return {"preferred_base": base, "image_size": size, "timestamp": stamp,
            "nt_offset": nt, "sections": sections}


def map_boundary(pe, loaded_base, preferred_va):
    rva = preferred_va-pe["preferred_base"]
    require(0 <= rva < pe["image_size"], "boundary outside image")
    file_offset = None
    for start, virtual_size, raw_size, raw_offset in pe["sections"]:
        if start <= rva < start+max(virtual_size, raw_size):
            if rva-start < raw_size:
                file_offset = raw_offset+rva-start
            break
    return {"preferred_va": preferred_va, "rva": rva,
            "runtime_va": loaded_base+rva, "file_offset": file_offset}


class Module(C.Structure):
    _fields_ = [("dwSize", W.DWORD), ("th32ModuleID", W.DWORD),
                ("th32ProcessID", W.DWORD), ("GlblcntUsage", W.DWORD),
                ("ProccntUsage", W.DWORD), ("modBaseAddr", C.c_void_p),
                ("modBaseSize", W.DWORD), ("hModule", W.HMODULE),
                ("szModule", W.WCHAR*256), ("szExePath", W.WCHAR*260)]


class Thread(C.Structure):
    _fields_ = [("dwSize", W.DWORD), ("cntUsage", W.DWORD),
                ("th32ThreadID", W.DWORD), ("th32OwnerProcessID", W.DWORD),
                ("tpBasePri", W.LONG), ("tpDeltaPri", W.LONG), ("dwFlags", W.DWORD)]


class FloatSave(C.Structure):
    _fields_ = [(name, W.DWORD) for name in
                ("ControlWord", "StatusWord", "TagWord", "ErrorOffset", "ErrorSelector",
                 "DataOffset", "DataSelector")]+[("RegisterArea", C.c_ubyte*80),
                                               ("Cr0NpxState", W.DWORD)]


class Context(C.Structure):
    _fields_ = [("ContextFlags", W.DWORD)]+[(name, W.DWORD) for name in
                ("Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7")]+[("FloatSave", FloatSave)]+[
                (name, W.DWORD) for name in
                ("SegGs", "SegFs", "SegEs", "SegDs", "Edi", "Esi", "Ebx", "Edx", "Ecx",
                 "Eax", "Ebp", "Eip", "SegCs", "EFlags", "Esp", "SegSs")]+[
                ("ExtendedRegisters", C.c_ubyte*512)]


class Windows:
    def __init__(self):
        require(os.name == "nt" and C.sizeof(C.c_void_p) == 8,
                "requires 64-bit Python on Windows x64")
        require(C.sizeof(Context) == 716, "unexpected WOW64_CONTEXT layout")
        self.api = C.WinDLL("kernel32", use_last_error=True)
        specs = {
            "OpenProcess": (W.HANDLE, [W.DWORD, W.BOOL, W.DWORD]),
            "OpenThread": (W.HANDLE, [W.DWORD, W.BOOL, W.DWORD]),
            "CloseHandle": (W.BOOL, [W.HANDLE]),
            "QueryFullProcessImageNameW": (W.BOOL, [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]),
            "IsWow64Process2": (W.BOOL, [W.HANDLE, C.POINTER(W.WORD), C.POINTER(W.WORD)]),
            "GetExitCodeProcess": (W.BOOL, [W.HANDLE, C.POINTER(W.DWORD)]),
            "GetExitCodeThread": (W.BOOL, [W.HANDLE, C.POINTER(W.DWORD)]),
            "GetProcessIdOfThread": (W.DWORD, [W.HANDLE]),
            "CreateToolhelp32Snapshot": (W.HANDLE, [W.DWORD, W.DWORD]),
            "Module32FirstW": (W.BOOL, [W.HANDLE, C.POINTER(Module)]),
            "Module32NextW": (W.BOOL, [W.HANDLE, C.POINTER(Module)]),
            "Thread32First": (W.BOOL, [W.HANDLE, C.POINTER(Thread)]),
            "Thread32Next": (W.BOOL, [W.HANDLE, C.POINTER(Thread)]),
            "ReadProcessMemory": (W.BOOL, [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]),
            "Wow64SuspendThread": (W.DWORD, [W.HANDLE]),
            "Wow64GetThreadContext": (W.BOOL, [W.HANDLE, C.POINTER(Context)]),
            "ResumeThread": (W.DWORD, [W.HANDLE]),
        }
        for name, (result, args) in specs.items():
            function = getattr(self.api, name)
            function.restype, function.argtypes = result, args

    def check(self, ok, operation):
        if not ok:
            raise CaptureError(f"{operation} failed; WinError={C.get_last_error()}")

    @contextlib.contextmanager
    def handle(self, value, operation="open/snapshot"):
        require(value not in (None, 0, C.c_void_p(-1).value),
                f"{operation} failed; WinError={C.get_last_error()}")
        try:
            yield value
        finally:
            self.api.CloseHandle(value)

    def alive(self, process):
        code = W.DWORD()
        self.check(self.api.GetExitCodeProcess(process, C.byref(code)), "GetExitCodeProcess")
        require(code.value == 259, "target process has exited")

    def image_path(self, process):
        size = W.DWORD(32768)
        buffer = C.create_unicode_buffer(size.value)
        self.check(self.api.QueryFullProcessImageNameW(process, 0, buffer, C.byref(size)),
                   "QueryFullProcessImageNameW")
        return Path(buffer.value).resolve()

    def enumerate(self, flags, pid, entry_type, prefix, limit):
        with self.handle(self.api.CreateToolhelp32Snapshot(flags, pid), "CreateToolhelp32Snapshot") as snapshot:
            entry = entry_type()
            entry.dwSize = C.sizeof(entry)
            self.check(getattr(self.api, prefix+"First"+("W" if prefix == "Module32" else ""))(
                snapshot, C.byref(entry)), prefix+"First")
            result = []
            while True:
                if entry_type == Module:
                    item = {"name": entry.szModule, "path": Path(entry.szExePath).resolve(),
                            "base": entry.modBaseAddr, "size": entry.modBaseSize}
                    if item not in result:
                        result.append(item)
                elif entry.th32OwnerProcessID == pid:
                    result.append(entry.th32ThreadID)
                require(len(result) <= limit, "module/thread inventory exceeds hard limit")
                if not getattr(self.api, prefix+"Next"+("W" if prefix == "Module32" else ""))(
                        snapshot, C.byref(entry)):
                    require(C.get_last_error() == 18, "inventory failed before completion")
                    break
            return result

    def read(self, process, address, size):
        require(0 <= address <= 0xFFFFFFFF and 0 < size <= MAX_REGION
                and address+size <= 0x100000000, "invalid bounded x86 memory region")
        buffer, received = C.create_string_buffer(size), C.c_size_t()
        ok = self.api.ReadProcessMemory(process, address, buffer, size, C.byref(received))
        error = 0 if ok else C.get_last_error()
        data = buffer.raw[:received.value]
        return {"address": address, "requested": size, "received": len(data),
                "complete": bool(ok and len(data) == size), "winerror": error,
                "sha256": hashlib.sha256(data).hexdigest(), "hex": data.hex()}

    @contextlib.contextmanager
    def suspended_context(self, tid, owner_pid):
        # GET_CONTEXT | SUSPEND_RESUME | QUERY_INFORMATION; no SET_CONTEXT access.
        with self.handle(self.api.OpenThread(0x004A, False, tid), "OpenThread") as thread:
            # Bind the opened handle to the selected process, including if a
            # thread ID was recycled since the earlier inventory snapshot.
            owner = self.api.GetProcessIdOfThread(thread)
            self.check(owner, "GetProcessIdOfThread")
            require(owner == owner_pid, "opened thread is not owned by target")
            code = W.DWORD()
            self.check(self.api.GetExitCodeThread(thread, C.byref(code)), "GetExitCodeThread")
            require(code.value == 259, "target thread has exited")
            previous = self.api.Wow64SuspendThread(thread)
            require(previous != 0xFFFFFFFF, f"Wow64SuspendThread failed; WinError={C.get_last_error()}")
            try:
                require(previous == 0, "pre-suspended threads are unsupported")
                context = Context()
                context.ContextFlags = 0x1002F  # FULL | FLOATING_POINT | EXTENDED_REGISTERS
                self.check(self.api.Wow64GetThreadContext(thread, C.byref(context)),
                           "Wow64GetThreadContext")
                yield context
            finally:
                remaining = self.api.ResumeThread(thread)
                require(remaining != 0xFFFFFFFF,
                        f"ResumeThread failed; WinError={C.get_last_error()}; target may remain suspended")
                require(remaining == previous+1, "concurrent suspend-count change; capture unsupported")


def context_record(context):
    return {"registers": {name.lower(): getattr(context, name) for name in
                          ("Eax", "Ebx", "Ecx", "Edx", "Esi", "Edi", "Ebp", "Esp", "Eip", "EFlags")},
            "x87": {"control_word": context.FloatSave.ControlWord,
                    "status_word": context.FloatSave.StatusWord,
                    "tag_word": context.FloatSave.TagWord,
                    "legacy_register_area_hex": bytes(context.FloatSave.RegisterArea).hex()},
            "extended_registers_hex": bytes(context.ExtendedRegisters).hex()}


def capture(args):
    require(0 < args.pid <= 0xFFFFFFFF and args.pid != os.getpid(), "invalid/self target PID")
    require(1 <= args.samples <= 1000 and 0 <= args.interval_ms <= 1000
            and 0 < args.seconds <= 30, "capture bounds exceeded")
    require(args.mode != "watch" or args.thread is not None, "watch requires a selected --thread")
    require(len(args.region) <= 8 and sum(size for _, size in args.region)+128 <= MAX_BYTES,
            "requested memory exceeds capture budget")
    for address, size in args.region:
        require(0 <= address <= 0xFFFFFFFF and 0 < size <= MAX_REGION
                and address+size <= 0x100000000, "invalid region")
    expected = args.synthetic_sha256 or PINNED
    require(len(expected) == 64 and all(ch in "0123456789abcdef" for ch in expected), "invalid hash")
    require(not args.synthetic_sha256 or expected != PINNED,
            "pinned game cannot be labelled as a synthetic test")
    exe = args.exe.resolve(strict=True)
    require(sha256_file(exe) == expected, "disk executable SHA-256 mismatch")
    pe = pe_identity(exe)
    if not args.synthetic_sha256:
        require(pe["preferred_base"] == PREFERRED_BASE and args.boundary == BOUNDARY,
                "game profile permits only the reviewed 007023e3 boundary")
    win = Windows()
    with win.handle(win.api.OpenProcess(0x0410, False, args.pid), "OpenProcess(QUERY_INFORMATION|VM_READ)") as process:
        win.alive(process)
        require(win.image_path(process) == exe, "PID image path differs from requested executable")
        machine, native = W.WORD(), W.WORD()
        win.check(win.api.IsWow64Process2(process, C.byref(machine), C.byref(native)), "IsWow64Process2")
        require(machine.value == 0x14C and native.value == 0x8664, "target must be x86 WOW64 on x64")
        # Combined inventory duplicates the main x86 image on this host; exact
        # duplicate records are removed in enumerate, distinct records retained.
        modules = win.enumerate(0x18, args.pid, Module, "Module32", 128)
        matches = [module for module in modules if module["path"] == exe]
        require(len(matches) == 1, "executable module not uniquely identified")
        main = matches[0]
        require(main["size"] == pe["image_size"], "loaded module size differs from PE")
        live = win.read(process, main["base"], min(4096, pe["image_size"]))
        require(live["complete"], "cannot read live PE headers")
        header = bytes.fromhex(live["hex"])
        nt = pe["nt_offset"]
        require(header[:2] == b"MZ" and header[nt:nt+4] == b"PE\0\0"
                and struct.unpack_from("<H", header, nt+4)[0] == 0x14C
                and struct.unpack_from("<I", header, nt+8)[0] == pe["timestamp"]
                and struct.unpack_from("<I", header, nt+24+56)[0] == pe["image_size"],
                "live PE identity fields differ from disk")
        boundary = map_boundary(pe, main["base"], args.boundary)
        tids = win.enumerate(4, args.pid, Thread, "Thread32", MAX_THREADS)
        require(tids, "process has no discoverable threads")
        if args.thread is not None:
            require(args.thread in tids, "selected thread is not owned by target")
            tids = [args.thread]
        if args.mode != "inventory":
            require(len(tids) == 1, "snapshot/watch requires one --thread from inventory")
        result = {"schema": "reversal.reference-capture-37.v1", "private": True,
                  "captured_utc": datetime.now(timezone.utc).isoformat(),
                  "tool_sha256": sha256_file(Path(__file__)),
                  "profile": "synthetic-test" if args.synthetic_sha256 else "pinned-game",
                  "pid": args.pid, "mode": args.mode, "exe_sha256": expected,
                  "disk_bytes": exe.stat().st_size,
                  "identity_limit": "disk hash plus live PE identity fields; loaded code not authenticated",
                  "module": {key: main[key] for key in ("name", "base", "size")},
                  "module_scope": "Toolhelp SNAPMODULE | SNAPMODULE32; exact duplicates removed",
                  "modules": [{key: item[key] for key in ("name", "base", "size")} for item in modules],
                  "boundary": boundary, "threads": tids, "samples": [], "probe_count": 0,
                  "boundary_observed": False,
                  "consistency": ("inventory only; no thread or context sample" if args.mode == "inventory" else
                                  "one selected thread suspended per probe; other threads can mutate memory"),
                  "instrumentation": ("read-only module and thread inventory; no suspension" if args.mode == "inventory" else
                                      "WOW64 suspend/context/read/resume; scheduling is affected; no target writes"),
                  "limitations": ["sampled EIP can miss a brief boundary", "no call or event ordering trace",
                                  "no object graph traversal", "no deterministic replay claim",
                                  "pointers and sampled bytes are private, not portable fixtures"]}
        started = time.monotonic()
        maximum = args.samples if args.mode == "watch" else (1 if args.mode == "snapshot" else 0)
        for _ in range(maximum):
            if time.monotonic()-started >= args.seconds:
                break
            win.alive(process)
            with win.suspended_context(tids[0], args.pid) as context:
                result["probe_count"] += 1
                hit = context.Eip == boundary["runtime_va"]
                if hit or args.mode == "snapshot":
                    record = context_record(context)
                    record["thread"] = tids[0]
                    record["boundary_hit"] = hit
                    record["elapsed_seconds"] = time.monotonic()-started
                    requests = [(context.Esp, 128)]+args.region
                    record["memory"] = [win.read(process, address, size) for address, size in requests]
                    result["samples"].append(record)
                    result["boundary_observed"] = hit
            if hit or args.mode == "snapshot":
                break
            time.sleep(args.interval_ms/1000)
        win.alive(process)
        # Recheck disk identity after sampling, without holding any thread suspended.
        require(sha256_file(exe) == expected, "disk executable changed during capture")
        result["elapsed_seconds"] = time.monotonic()-started
        result["stop_reason"] = ("inventory-only" if args.mode == "inventory" else
                                 "boundary-hit" if result["boundary_observed"] else
                                 "snapshot-away-from-boundary" if args.mode == "snapshot" else
                                 "sample-or-time-limit-boundary-not-observed")
        result["memory_complete"] = (all(item["complete"] for sample in result["samples"] for item in sample["memory"])
                                     if result["samples"] else None)
        return result


def region(value):
    try:
        address, size = value.split(":")
        return int(address, 0), int(size, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("region must be runtime-address:size, both decimal or 0x hex") from error


def parser():
    argument = argparse.ArgumentParser(description=__doc__)
    argument.add_argument("mode", choices=("inventory", "snapshot", "watch"))
    argument.add_argument("--pid", required=True, type=int)
    argument.add_argument("--exe", required=True, type=Path)
    argument.add_argument("--output", required=True, type=Path, help="new private JSON beneath ignored results/")
    argument.add_argument("--thread", type=int)
    argument.add_argument("--boundary", type=lambda value: int(value, 0), default=BOUNDARY,
                          help="preferred image VA; game profile fixed to 0x7023e3")
    argument.add_argument("--region", type=region, action="append", default=[],
                          help="explicit runtime-address:size; maximum 8 regions, 4096 bytes each")
    argument.add_argument("--samples", type=int, default=100)
    argument.add_argument("--seconds", type=float, default=5)
    argument.add_argument("--interval-ms", type=int, default=10)
    argument.add_argument("--synthetic-sha256", help="explicit non-game test profile disk hash")
    return argument


def main():
    args = parser().parse_args()
    try:
        output = args.output.resolve()
        require(output.is_relative_to(ROOT/"results") and output.suffix == ".json",
                "output must be a new .json beneath this checkout's ignored results directory")
        require(not output.exists(), "refusing to overwrite output")
        # Reserve output before touching the target. A failed attempt records an
        # explicit rejection, never an apparently valid or empty capture.
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            try:
                result = capture(args)
            except (CaptureError, OSError, ValueError, AttributeError, KeyboardInterrupt) as error:
                message = str(error) if isinstance(error, CaptureError) else type(error).__name__
                json.dump({"private": True, "capture_accepted": False, "error": message}, stream)
                stream.write("\n")
                raise
            json.dump(result, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"profile": result["profile"], "stop_reason": result["stop_reason"],
                          "boundary_observed": result["boundary_observed"],
                          "probe_count": result["probe_count"], "private_output_written": True}))
    except (CaptureError, OSError, ValueError, AttributeError, KeyboardInterrupt) as error:
        # Avoid echoing OS exception text, which can contain private paths.
        message = str(error) if isinstance(error, CaptureError) else type(error).__name__
        print(json.dumps({"error": message, "capture_accepted": False}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

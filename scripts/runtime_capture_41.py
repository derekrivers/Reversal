"""Single-use WOW64 hardware execution breakpoint; private results only.

No elevation, code patching, arbitrary commands or broker. Debug registers are
restored before detach. Use only the task's disposable working process.
"""
from __future__ import annotations
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import struct
import subprocess
import time
from types import SimpleNamespace

import reference_capture_37 as base

GDI = "0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b"
ROOT = Path(__file__).resolve().parents[1]
DR_NAMES = ("Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7")


class Event(C.Structure):
    _fields_ = [("code", W.DWORD), ("pid", W.DWORD), ("tid", W.DWORD),
                ("payload", C.c_uint64 * 20)]

    def data(self):
        return bytes(self.payload)


class Debugger(base.Windows):
    def __init__(self):
        super().__init__()
        base.require(C.sizeof(Event) == 176 and Event.payload.offset == 16,
                     "unsupported DEBUG_EVENT ABI")
        for name, result, args in [
            ("DebugActiveProcess", W.BOOL, [W.DWORD]),
            ("DebugActiveProcessStop", W.BOOL, [W.DWORD]),
            ("DebugSetProcessKillOnExit", W.BOOL, [W.BOOL]),
            ("DebugBreakProcess", W.BOOL, [W.HANDLE]),
            ("WaitForDebugEvent", W.BOOL, [C.POINTER(Event), W.DWORD]),
            ("ContinueDebugEvent", W.BOOL, [W.DWORD, W.DWORD, W.DWORD]),
            ("Wow64SetThreadContext", W.BOOL, [W.HANDLE, C.POINTER(base.Context)]),
            ("Wow64GetThreadSelectorEntry", W.BOOL, [W.HANDLE, W.DWORD, C.c_void_p]),
        ]:
            fn = getattr(self.api, name)
            fn.restype, fn.argtypes = result, args

    def context(self, handle, flags=0x1003F):
        ctx = base.Context()
        ctx.ContextFlags = flags
        self.check(self.api.Wow64GetThreadContext(handle, C.byref(ctx)), "Wow64GetThreadContext")
        return ctx

    def set_debug(self, handle, values):
        ctx = base.Context()
        ctx.ContextFlags = 0x10010
        for name, value in zip(DR_NAMES, values):
            setattr(ctx, name, value)
        self.check(self.api.Wow64SetThreadContext(handle, C.byref(ctx)), "Wow64SetThreadContext(debug only)")


def inventory(args):
    expected = GDI if args.profile == "gdi" else base.sha256_file(args.exe)
    if args.profile == "gdi":
        base.require(args.exe.resolve().is_relative_to(ROOT / "results" / "game-copy"),
                     "GDI target must be inside this task's disposable game-copy")
    else:
        safe = Path(os.environ["WINDIR"]) / "SysWOW64/WindowsPowerShell/v1.0/powershell.exe"
        base.require(args.exe.resolve() == safe.resolve(), "synthetic profile requires system x86 PowerShell")
    base.require(base.sha256_file(args.exe) == expected, "disk identity mismatch")
    pe = base.pe_identity(args.exe)
    return base.capture(SimpleNamespace(pid=args.pid, exe=args.exe, mode="inventory",
        thread=None, samples=1, interval_ms=0, seconds=1, region=[],
        boundary=pe["preferred_base"], synthetic_sha256=expected))


def lookup_closure(dbg, process, ctx, loaded_base):
    """Bounded GDI lookup-entry graph; incomplete reads stay explicitly missing."""
    reads = []

    def read(label, address, size):
        item = dbg.read(process, address, size)
        item["label"] = label
        reads.append(item)
        return bytes.fromhex(item["hex"]) if item["complete"] else None

    def u32(data, offset=0):
        return struct.unpack_from("<I", data, offset)[0] if data is not None else None

    delta = loaded_base - 0x400000
    flags = read("lookup_flags", 0xB62C58 + delta, 1)
    count = u32(read("staff_count", 0xAE12B4 + delta, 4))
    read("current_date", 0xAE1BE0 + delta, 8)
    read("lookup_global", 0xB62C70 + delta, 4)
    read("staff_base", 0xAE130C + delta, 4)
    for label, preferred in (("rng_cursor", 0xDE0EA8), ("rng_offset", 0xDE0EA4),
                             ("rng_limit", 0xDE16E0), ("crt_seed", 0xAD5B80)):
        read(label, preferred + delta, 4)
    stack = read("entry_stack_below_and_arguments", ctx.Esp - 0x260, 0x300)
    staff = u32(stack, 0x264)
    receiver = read("lookup_receiver", ctx.Ecx, 0x2C) if ctx.Ecx else None
    record = read("staff_record", staff, 0x6E) if staff else None
    # R41-B effect consumer uses ESI for the slot at the actual lookup CALL.
    # A different caller may supply an unrelated ESI: record bytes, but assert
    # no slot semantics unless both caller provenance and pointer equalities hold.
    slot = None
    if ctx.Esi:
        if 0 < ctx.Esi and ctx.Esi + 0x1BE <= 2**32:
            slot = read("effect_esi_candidate_slot", ctx.Esi, 0x1BE)
        else:
            # An unrelated caller's ESI is optional evidence. Do not let its
            # invalid range discard the otherwise valid lookup entry.
            reads.append({"label": "effect_esi_candidate_slot", "address": ctx.Esi,
                          "requested": 0x1BE, "received": 0, "complete": False,
                          "winerror": None, "error": "outside-x86-address-space",
                          "sha256": base.hashlib.sha256(b"").hexdigest(), "hex": ""})
    index = struct.unpack_from("<i", record)[0] if record else None
    row_base = u32(receiver)
    if row_base and index is not None and count is not None and 0 <= index < count:
        row_address = row_base + 31 * index
        if row_address + 31 <= 2**32:
            row = read("selected_status_row", row_address, 31)
            mapped = struct.unpack_from("<i", row, 14)[0] if row else None
            cache = u32(receiver, 4)
            if cache and mapped is not None and mapped >= 0 and cache + 48 * mapped + 48 <= 2**32:
                read("selected_cache_record", cache + 48 * mapped, 48)
    return {"memory": reads, "all_requested_reads_complete": all(r["complete"] for r in reads),
            "staff": staff, "index": index, "count": count,
            "effect_return_address_matches": u32(stack, 0x260) == 0x6CF8F7 + delta,
            "slot_staff_pointer_matches": u32(slot, 0x69) == staff if slot and staff else None,
            "slot_attribute_pointer_matches": u32(slot, 0x6D) == u32(record, 0x61)
                if slot and record else None,
            "flags": flags.hex() if flags else None,
            "missing": ["staff attributes referent", "refresh-path closure",
                        "RNG table", "return and ordered effects"]}


def run(args, *, owned_test_child=None):
    base.require(0 < args.seconds <= 60, "deadline must be within 60 seconds")
    base.require(len(args.region) <= 8 and sum(size for _, size in args.region) <= 15872,
                 "region budget exceeded")
    for address, size in args.region:
        base.require(0 <= address < 2**32 and 0 < size <= 4096 and address + size <= 2**32,
                     "invalid region")
    if args.profile == "synthetic":
        base.require(isinstance(owned_test_child, subprocess.Popen) and
                     owned_test_child.pid == args.pid and owned_test_child.poll() is None,
                     "synthetic capture requires checker-owned child")
    info = inventory(args)
    pe = base.pe_identity(args.exe)
    boundary = base.map_boundary(pe, info["module"]["base"], args.boundary)
    if args.profile == "synthetic":
        # The checker owns this freshly allocated function; no arbitrary profile.
        base.require(args.synthetic_address is not None, "synthetic function address required")
        address = args.synthetic_address
        base.require(0 < address < 2**32, "invalid synthetic address")
    else:
        base.require(args.synthetic_address is None, "synthetic address forbidden for game")
        # Reviewed R40 entry anchors; additional entries require a source change/review.
        base.require(args.boundary in (0x701A80, 0x6FFe50, 0x6CF840, 0x90C860, 0x6B92F0, 0x62E6E0),
                     "unreviewed GDI boundary")
        address = boundary["runtime_va"]
    dbg = Debugger()
    result = {"schema": "reversal.runtime-capture-41.v1", "private": True,
        "profile": args.profile, "exe_sha256": info["exe_sha256"],
        "pid": args.pid, "module": info["module"], "boundary": boundary,
        "breakpoint_runtime_va": address, "hit": False, "events": [],
        "sample": None, "restored_threads": [], "detached": False,
        "closure_complete": False, "ordered_effects": None,
        "instrumentation": "DR0 execute breakpoint on each debug-event thread; process stopped at event",
        "missing_state": ["return effects", "ordered RNG draws", "object lifetime", "complete pointer closure"],
        "tool_sha256": base.sha256_file(Path(__file__))}
    # CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE | QUERY_INFORMATION:
    # DebugBreakProcess needs remote-break thread rights. No target memory writes
    # are exposed or issued by this tool.
    with dbg.handle(dbg.api.OpenProcess(0x43A, False, args.pid), "OpenProcess(debug boundary)") as process:
        if args.profile == "gdi":
            base.require(boundary["file_offset"] is not None, "boundary not file backed")
            with args.exe.open("rb") as source:
                source.seek(boundary["file_offset"])
                original = source.read(16)
            live = dbg.read(process, address, 16)
            base.require(live["complete"] and bytes.fromhex(live["hex"]) == original,
                         "live boundary bytes differ from identified disk")
            result["boundary_code_sha256"] = live["sha256"]
        threads = {}
        armed = {}
        pending = None
        pending_status = 0x10002
        attached = False
        started = time.monotonic()
        shutdown_requested = False
        thread_starts = {}
        bootstrap_break = None

        def arm(tid, handle):
            ctx = dbg.context(handle, 0x10010)
            old = tuple(getattr(ctx, name) for name in DR_NAMES)
            base.require(not (ctx.Dr7 & 0xFF), "existing hardware breakpoint; refusing interference")
            armed[tid] = old
            dbg.set_debug(handle, (address, ctx.Dr1, ctx.Dr2, ctx.Dr3, 0, (ctx.Dr7 & ~0xF0003) | 1))

        def restore():
            errors = []
            for tid, old in list(armed.items()):
                try:
                    if tid in threads:
                        dbg.set_debug(threads[tid], old)
                        restored = dbg.context(threads[tid], 0x10010)
                        # Reserved Dr6/Dr7 bits may be normalized by Windows.
                        base.require(all(getattr(restored, name) == old[i] for i, name in
                                         enumerate(DR_NAMES[:4])) and
                                     (restored.Dr7 & 0xFFFF00FF) == (old[5] & 0xFFFF00FF),
                                     "debug-register restoration readback mismatch")
                        result["restored_threads"].append(tid)
                    del armed[tid]
                except Exception as exc:
                    errors.append(str(exc))
            base.require(not errors, "restoration failed: " + "; ".join(errors))

        try:
            dbg.check(dbg.api.DebugActiveProcess(args.pid), "DebugActiveProcess")
            attached = True
            dbg.check(dbg.api.DebugSetProcessKillOnExit(False), "DebugSetProcessKillOnExit")
            ready = False
            while True:
                elapsed = time.monotonic() - started
                if elapsed >= args.seconds and not shutdown_requested:
                    dbg.check(dbg.api.DebugBreakProcess(process), "DebugBreakProcess(timeout)")
                    shutdown_requested = True
                base.require(elapsed <= args.seconds + 5, "debug-event cleanup deadline exceeded")
                event = Event()
                if not dbg.api.WaitForDebugEvent(C.byref(event), 100):
                    base.require(C.get_last_error() == 121, "WaitForDebugEvent failed")
                    continue
                pending = event
                pending_status = 0x80010001 if event.code == 1 else 0x10002
                base.require(event.pid == args.pid, "unexpected process debug event")
                data = event.data()
                result["events"].append({"code": event.code, "thread": event.tid})
                base.require(len(result["events"]) <= 2048, "debug-event limit exceeded")
                status = 0x10002
                if event.code in (2, 3):
                    offset = 16 if event.code == 3 else 0
                    threads[event.tid] = struct.unpack_from("<Q", data, offset)[0]
                    thread_starts[event.tid] = struct.unpack_from("<Q", data, 40 if event.code == 3 else 16)[0]
                    if event.code == 3:
                        file_handle = struct.unpack_from("<Q", data)[0]
                        if file_handle:
                            dbg.api.CloseHandle(file_handle)
                    if ready and not shutdown_requested:
                        arm(event.tid, threads[event.tid])
                elif event.code == 4:
                    threads.pop(event.tid, None)
                    thread_starts.pop(event.tid, None)
                    armed.pop(event.tid, None)
                elif event.code == 5:
                    armed.clear()
                    result["process_exited"] = True
                    break
                elif event.code == 6:
                    file_handle = struct.unpack_from("<Q", data)[0]
                    if file_handle:
                        dbg.api.CloseHandle(file_handle)
                elif event.code == 1:
                    exception = struct.unpack_from("<I", data)[0]
                    result["events"][-1]["exception"] = exception
                    if exception in (0x80000004, 0x4000001E) and event.tid in armed:
                        ctx = dbg.context(threads[event.tid])
                        if ctx.Eip == address and ctx.Dr6 & 1:
                            sample = base.context_record(ctx)
                            sample["captured_utc"] = base.datetime.now(base.timezone.utc).isoformat()
                            sample["thread"] = event.tid
                            descriptor = (C.c_ubyte * 8)()
                            fs_ok = dbg.api.Wow64GetThreadSelectorEntry(
                                threads[event.tid], ctx.SegFs, C.byref(descriptor))
                            sample["fs"] = {"selector": ctx.SegFs, "complete": bool(fs_ok),
                                            "winerror": 0 if fs_ok else C.get_last_error()}
                            if fs_ok:
                                raw = bytes(descriptor)
                                fs_base = struct.unpack_from("<H", raw, 2)[0] | raw[4] << 16 | raw[7] << 24
                                sample["fs"]["base"] = fs_base
                                sample["fs"]["head"] = dbg.read(process, fs_base, 4)
                                sample["fs"]["complete"] = sample["fs"]["head"]["complete"]
                            sample["memory"] = [dbg.read(process, ctx.Esp, 512)] + [
                                dbg.read(process, addr, size) for addr, size in args.region]
                            result["sample"], result["hit"] = sample, True
                            result["memory_complete"] = all(x["complete"] for x in sample["memory"])
                            if args.profile == "gdi" and args.boundary == 0x62E6E0:
                                sample["lookup_closure"] = lookup_closure(
                                    dbg, process, ctx, info["module"]["base"])
                            pending_status = 0x10002
                            break
                        status = 0x80010001
                    elif exception in (0x80000003, 0x4000001F):
                        identity = (struct.unpack_from("<Q", data, 16)[0],
                                    thread_starts.get(event.tid))
                        own_timeout = (shutdown_requested and event.tid not in info["threads"]
                                       and identity == bootstrap_break)
                        if own_timeout:
                            pending_status = 0x10002
                            break
                        if not ready:
                            pending_status = 0x10002
                            bootstrap_break = identity
                            for tid, handle in threads.items():
                                arm(tid, handle)
                            ready = True
                        else:
                            status = 0x80010001
                    else:
                        status = 0x80010001
                dbg.check(dbg.api.ContinueDebugEvent(event.pid, event.tid, status), "ContinueDebugEvent")
                pending = None
        finally:
            if attached:
                # A returned event freezes all process threads. Every normal,
                # hit, timeout and event-processing error exit restores here.
                # If failure arose while no event was pending, request a stop.
                try:
                    if armed and pending is None:
                        dbg.check(dbg.api.DebugBreakProcess(process), "DebugBreakProcess(cleanup)")
                        event = Event()
                        dbg.check(dbg.api.WaitForDebugEvent(C.byref(event), 5000), "cleanup WaitForDebugEvent")
                        pending = event
                        pending_status = 0x10002 if event.code != 1 or struct.unpack_from(
                            "<I", event.data())[0] in (0x80000003, 0x4000001F) else 0x80010001
                    restore()
                finally:
                    try:
                        if pending is not None:
                            dbg.check(dbg.api.ContinueDebugEvent(pending.pid, pending.tid, pending_status),
                                      "cleanup ContinueDebugEvent")
                    finally:
                        dbg.check(dbg.api.DebugActiveProcessStop(args.pid), "DebugActiveProcessStop")
                        result["detached"] = True
        result["elapsed_seconds"] = time.monotonic() - started
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--exe", type=Path, required=True)
    p.add_argument("--boundary", type=lambda s: int(s, 0), default=0x90C860)
    p.add_argument("--seconds", type=float, default=20)
    p.add_argument("--region", type=base.region, action="append", default=[])
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.profile, args.synthetic_address = "gdi", None
    import reference_capture_broker_37 as writer
    with writer.secure_new_result(args.output.absolute(), delete_on_failure=True) as stream:
        try:
            result = run(args)
        except Exception as exc:
            json.dump({"capture_accepted": False, "error": str(exc)}, stream)
            raise
        json.dump(result, stream, indent=2)
    print(json.dumps({"hit": result["hit"], "detached": result["detached"]}))


if __name__ == "__main__":
    main()

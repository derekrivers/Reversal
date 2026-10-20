"""Owned WOW64 entry/RET4 pairing, ambiguity, timeout and cleanup regression."""
import json
import os
from pathlib import Path
import struct
import subprocess
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch
import runtime_capture_41 as tool


def queued_entry_regression():
    """Deterministic event queue: no process, API injection, or executable launched."""
    entry, returned, esp, pid = 0x500000, 0x500100, 0x100000, 123
    results = []
    for finish in ("return", "timeout", "drain_failure"):
        class FakeDebugger:
            def __init__(self):
                self.api = self
                self.clock = 0
                self.pending = None
                self.detached = False
                self.failed = False
                self.continued = []
                self.contexts = {tid: tool.base.Context() for tid in (11, 22, 33, 44, 55)}
                # Threads22 and55 existed and were armed before the selected entry.
                # Thread22's trap is queued; thread55 never hits and must be restored.
                self.queue = [(3, 11, 0), (2, 22, 0), (2, 55, 0),
                              (1, 11, 0x80000003), (1, 11, 0x80000004),
                              (2, 33, 0), (1, 22, 0x80000004),
                              (1, 22, 0x80000003), (1, 22, 0x80000004)]
                if finish == "return":
                    self.queue.append((1, 11, 0x4000001E))
            def check(self, value, operation):
                tool.base.require(bool(value), operation)
            def handle(self, handle, operation):
                return nullcontext(handle)
            def OpenProcess(self, rights, inherit, process_id):
                tool.base.require(process_id == pid, "fake wrong process")
                return pid
            def DebugActiveProcess(self, process_id):
                return process_id == pid
            def DebugSetProcessKillOnExit(self, enabled):
                return enabled is False
            def CloseHandle(self, handle):
                return True
            def Wow64GetThreadSelectorEntry(self, *args):
                return False  # This queue regression does not exercise FS APIs.
            def DebugBreakProcess(self, handle):
                self.queue += [(2, 44, 0), (1, 44, 0x80000003)]
                return True
            def WaitForDebugEvent(self, destination, timeout):
                tool.base.require(self.pending is None and bool(self.queue),
                                  "fake queue exhausted or event not resumed")
                code, tid, exception = self.queue.pop(0)
                event = tool.Event()
                event.code, event.pid, event.tid = code, pid, tid
                payload = bytearray(160)
                if code in (2, 3):
                    struct.pack_into("<Q", payload, 16 if code == 3 else 0, tid)
                    struct.pack_into("<Q", payload, 40 if code == 3 else 16, 0x9000)
                else:
                    struct.pack_into("<I", payload, 0, exception)
                    struct.pack_into("<Q", payload, 16, 0x7000 if exception == 0x80000003 else entry)
                    ctx = self.contexts[tid]
                    ctx.Eip, ctx.Esp = entry, esp
                    if exception in (0x80000004, 0x4000001E):
                        ctx.Dr6 = 1
                    if exception == 0x4000001E:
                        ctx.Eip, ctx.Esp, ctx.Eax = returned, esp + 8, 42
                    if finish == "timeout" and tid == 22 and exception == 0x80000003:
                        self.clock = 3
                tool.C.memmove(tool.C.addressof(event) + tool.Event.payload.offset, bytes(payload), len(payload))
                tool.C.memmove(destination, tool.C.byref(event), tool.C.sizeof(event))
                self.pending = (code, tid, exception)
                return True
            def ContinueDebugEvent(self, process_id, tid, status):
                tool.base.require(self.pending is not None and self.pending[1] == tid,
                                  "fake mismatched resume")
                code, _, exception = self.pending
                self.continued.append((code, tid, exception, status))
                if tid == 22 and exception == 0x80000004:
                    seen = sum(item[1:3] == (22, 0x80000004) for item in self.continued)
                    tool.base.require(status == (0x10002 if seen == 1 else 0x80010001),
                                      "late owned hardware trap not handled exactly once")
                    tool.base.require(self.contexts[22].Dr7 == 0,
                                      "late entry resumed with breakpoint still enabled")
                self.pending = None
                return True
            def DebugActiveProcessStop(self, process_id):
                tool.base.require(self.pending is None, "detach left pending event")
                tool.base.require(all(all(getattr(ctx, name) == 0 for name in tool.DR_NAMES[:4]) and
                                      ctx.Dr7 == 0 for ctx in self.contexts.values()),
                                  "detach left an armed or modified thread")
                self.detached = True
                return True
            def context(self, handle, flags=0x1003F):
                return tool.base.Context.from_buffer_copy(self.contexts[handle])
            def set_debug(self, handle, values):
                for name, value in zip(tool.DR_NAMES, values):
                    setattr(self.contexts[handle], name, value)
                if finish == "drain_failure" and handle == 22 and values == (0, 0, 0, 0, 0, 0) and not self.failed:
                    self.failed = True
                    raise tool.base.CaptureError("injected late-entry disarm failure")
            def read(self, process, address, size):
                data = bytearray(size)
                if address == esp:
                    struct.pack_into("<I", data, 0, returned)
                return {"address": address, "requested": size, "received": size, "complete": True,
                        "hex": data.hex(), "sha256": tool.base.hashlib.sha256(data).hexdigest(), "winerror": 0}
        fake = FakeDebugger()
        child = Mock(spec=subprocess.Popen)
        child.pid, child.poll.return_value = pid, None
        args = SimpleNamespace(pid=pid, exe=Path(__file__), profile="synthetic", seconds=2,
                               boundary=0x400000, synthetic_address=entry,
                               synthetic_return_address=returned, paired_return=True, region=[])
        with patch.object(tool, "Debugger", return_value=fake), \
             patch.object(tool, "inventory", return_value={"module": {"base": 0x400000},
                          "exe_sha256": "0" * 64, "threads": [11, 22, 55]}), \
             patch.object(tool.base, "pe_identity", return_value={"preferred_base": 0x400000}), \
             patch.object(tool.base, "map_boundary", return_value={"runtime_va": entry}), \
             patch.object(tool.time, "monotonic", side_effect=lambda: fake.clock):
            if finish == "drain_failure":
                try:
                    tool.run(args, owned_test_child=child)
                except tool.base.CaptureError as exc:
                    tool.base.require("injected late-entry disarm failure" in str(exc), "wrong drain failure")
                else:
                    raise RuntimeError("late-entry failure was not injected")
            else:
                result = tool.run(args, owned_test_child=child)
                tool.base.require(result["late_entry_threads"] == [22] and
                                  result["sample"]["thread"] == 11 and
                                  sorted(result["restored_threads"]) == [11, 22, 55],
                                  "late entry replaced selected invocation or cleanup omitted thread")
                tool.base.require(result["return_observed"] == (finish == "return"),
                                  "wrong queued-event pairing outcome")
                tool.base.require((1, 22, 0x80000003, 0x80010001) in fake.continued,
                                  "queued application INT3 was swallowed")
                # A second event at the same address after disarm is not owned.
                statuses = [item[3] for item in fake.continued if item[1:3] == (22, 0x80000004)]
                tool.base.require(statuses == [0x10002, 0x80010001],
                                  "late trap not consumed once, or subsequent foreign trap swallowed")
            tool.base.require(fake.detached and (1, 22, 0x80000004, 0x10002) in fake.continued,
                              "late owned trap escaped or cleanup did not detach")
        results.append({"case": "queued_entry_" + finish, "passed": True})
    return results


def main():
    queued = queued_entry_regression()
    exe = Path(os.environ["WINDIR"]) / "SysWOW64/WindowsPowerShell/v1.0/powershell.exe"
    results = []
    faults = ("ReadFailure", "RearmFailure", "ContinueFailure")
    for mode in ("Normal", "WrongCaller", "WrongStack", "NestedMismatch", "Timeout", "Exception", *faults):
        target = subprocess.Popen([str(exe), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
            "Bypass", "-File",
            str(Path(__file__).with_name("runtime_paired_return_41_synthetic.ps1")),
            "-Mode", "Normal" if mode in faults else mode],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            creationflags=subprocess.CREATE_NO_WINDOW)
        original = tool.Debugger
        try:
            fixture = json.loads(target.stdout.readline())
            tool.base.require(fixture["pid"] == target.pid, "wrong owned fixture")
            args = SimpleNamespace(pid=target.pid, exe=exe, profile="synthetic", seconds=2,
                boundary=tool.base.pe_identity(exe)["preferred_base"],
                synthetic_address=fixture["entry"], synthetic_return_address=fixture["returnAddress"],
                paired_return=True, region=[(fixture["counter"], 4)])
            if mode in faults:
                class FailingDebugger(original):
                    failed = False
                    return_seen = False
                    rearmed = False
                    detached = False
                    def __init__(self):
                        super().__init__()
                        detach = self.api.DebugActiveProcessStop
                        def checked_detach(pid):
                            answer = detach(pid)
                            FailingDebugger.detached = bool(answer)
                            return answer
                        self.api.DebugActiveProcessStop = checked_detach
                        resume = self.api.ContinueDebugEvent
                        def checked_resume(pid, tid, status):
                            if mode == "ContinueFailure" and FailingDebugger.rearmed and not FailingDebugger.failed:
                                FailingDebugger.failed = True
                                return False  # Leave event pending; finally must resume and detach.
                            return resume(pid, tid, status)
                        self.api.ContinueDebugEvent = checked_resume
                    def set_debug(self, handle, values):
                        super().set_debug(handle, values)
                        if values[0] == fixture["returnAddress"]:
                            FailingDebugger.rearmed = True
                            if mode == "RearmFailure" and not FailingDebugger.failed:
                                FailingDebugger.failed = True
                                raise tool.base.CaptureError("injected rearm failure")
                    def context(self, handle, flags=0x1003F):
                        ctx = super().context(handle, flags)
                        if flags == 0x1003F and ctx.Eip == fixture["returnAddress"]:
                            FailingDebugger.return_seen = True
                        return ctx
                    def read(self, process, address, size):
                        if mode == "ReadFailure" and FailingDebugger.return_seen and not FailingDebugger.failed:
                            FailingDebugger.failed = True
                            raise tool.base.CaptureError("injected return read failure")
                        return super().read(process, address, size)
                tool.Debugger = FailingDebugger
                try:
                    tool.run(args, owned_test_child=target)
                except tool.base.CaptureError as exc:
                    expected_error = {"ReadFailure": "injected return read failure",
                                      "RearmFailure": "injected rearm failure",
                                      "ContinueFailure": "ContinueDebugEvent"}[mode]
                    tool.base.require(expected_error in str(exc), "wrong injected failure")
                else:
                    raise RuntimeError("injected failure not exercised")
                tool.base.require(FailingDebugger.failed and FailingDebugger.detached,
                                  "read-failure detach missing")
                tool.Debugger = original
                # Reattach succeeds only if old owned breakpoints were cleared and detach finished.
                result = tool.run(args, owned_test_child=target)
                tool.base.require(result["return_observed"], "cannot pair after injected cleanup")
            else:
                result = tool.run(args, owned_test_child=target)
            tool.base.require(result["hit"] and result["detached"] and result["restored_threads"],
                              "entry/restore/detach missing")
            tool.base.require(target.poll() is None, "debugger terminated owned target")
            if mode in ("Normal", "Exception", *faults):
                pair = result["pairing"]
                tool.base.require(result["return_observed"] and result["stop_reason"] == "paired_return" and
                    pair["thread_matches"] and pair["caller_matches"] and pair["return_address_matches"] and
                    pair["stack_matches_ret4"] and all(pair["nonvolatile_matches"].values()),
                    "paired boundary conditions failed")
                tool.base.require(result["return_sample"]["registers"]["eax"] == 42,
                                  "wrong synthetic return value")
                tool.base.require(result["sample"]["fs"]["complete"] and
                                  result["return_sample"]["fs"]["complete"], "FS closure unavailable")
                rereads = result["return_sample"]["entry_regions_after"]
                tool.base.require(len(rereads) == 2 and
                                  rereads[0]["address"] == pair["entry_esp"] and
                                  rereads[1]["address"] == fixture["counter"] and
                                  all(item["complete"] for item in rereads),
                                  "return did not reread the fixed entry regions")
                if mode == "Exception":
                    before = struct.unpack("<I", bytes.fromhex(result["sample"]["memory"][1]["hex"]))[0]
                    after = struct.unpack("<I", bytes.fromhex(result["return_sample"]["memory"][1]["hex"]))[0]
                    tool.base.require(after == before + 1, "intervening application INT3 suppressed")
                    tool.base.require(rereads[1]["unchanged"] is False,
                                      "changed counter incorrectly labelled unchanged")
                else:
                    tool.base.require(rereads[1]["unchanged"] is True, "stable counter changed")
            else:
                expected = {"WrongCaller": "entry_caller_or_stack_mismatch",
                            "WrongStack": "return_stack_mismatch",
                            "NestedMismatch": "return_stack_mismatch",
                            "Timeout": "return_not_observed"}[mode]
                tool.base.require(not result["return_observed"] and result["return_sample"] is None and
                                  result["stop_reason"] == expected, "false paired return")
            results.append({"case": mode, "passed": True, "stop_reason": result["stop_reason"]})
        finally:
            tool.Debugger = original
            target.terminate()
            target.wait(timeout=5)
    print(json.dumps({"schema": "reversal.runtime-paired-return-41.check.v1",
                      "optimized": not __debug__, "cases": results,
                      "deterministic_queued_event_cases": queued,
                      "scope": "owned synthetic WOW64 processes only; no game observation"}))


if __name__ == "__main__":
    main()

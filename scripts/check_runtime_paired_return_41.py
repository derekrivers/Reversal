"""Owned WOW64 entry/RET4 pairing, ambiguity, timeout and cleanup regression."""
import json
import os
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
import runtime_capture_41 as tool


def main():
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
                      "scope": "owned synthetic WOW64 processes only; no game observation"}))


if __name__ == "__main__":
    main()

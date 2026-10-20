"""Exercise a real single-use DR0 interception on an owned WOW64 child."""
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import struct
from types import SimpleNamespace
import runtime_capture_41 as tool


def optional_slot_regression():
    class FakeMemory:
        def __init__(self):
            self.calls = []

        def read(self, process, address, size):
            tool.base.require(0 <= address < 2**32 and address + size <= 2**32,
                              "optional slot attempted an out-of-range read")
            self.calls.append((address, size))
            complete = address != 0x200000
            data = bytes(size) if complete else b""
            return {"address": address, "requested": size, "received": len(data),
                    "complete": complete, "winerror": 0 if complete else 299,
                    "hex": data.hex(), "sha256": tool.base.hashlib.sha256(data).hexdigest()}

    for esi in (0xFFFFFFFF, 0, 0x200000):
        memory = FakeMemory()
        closure = tool.lookup_closure(memory, None,
                                     SimpleNamespace(Esp=0x100000, Ecx=0, Esi=esi), 0x400000)
        tool.base.require(closure["slot_staff_pointer_matches"] is None and
                          closure["slot_attribute_pointer_matches"] is None,
                          "missing optional slot manufactured an alias result")
        reads = {item["label"]: item for item in closure["memory"]}
        tool.base.require(reads["entry_stack_below_and_arguments"]["complete"] and
                          reads["current_date"]["complete"], "lookup evidence was discarded")
        if esi == 0xFFFFFFFF:
            missing = reads["effect_esi_candidate_slot"]
            tool.base.require(not missing["complete"] and missing["received"] == 0 and
                              missing["error"] == "outside-x86-address-space" and
                              missing["winerror"] is None and missing["hex"] == "" and
                              not closure["all_requested_reads_complete"],
                              "overflow candidate lacks explicit incomplete metadata")
        elif esi:
            tool.base.require(not reads["effect_esi_candidate_slot"]["complete"],
                              "unmapped optional slot was accepted")
        else:
            tool.base.require("effect_esi_candidate_slot" not in reads,
                              "null optional slot was dereferenced")


def main():
    optional_slot_regression()
    exe = Path(os.environ["WINDIR"]) / "SysWOW64/WindowsPowerShell/v1.0/powershell.exe"
    target = subprocess.Popen([str(exe), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
        "Bypass", "-File", str(Path(__file__).with_name("runtime_capture_41_synthetic.ps1"))],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        fixture = json.loads(target.stdout.readline())
        tool.base.require(fixture["pid"] == target.pid, "wrong test PID")
        args = SimpleNamespace(pid=target.pid, exe=exe, profile="synthetic", seconds=5,
            boundary=tool.base.pe_identity(exe)["preferred_base"],
            synthetic_address=fixture["address"], region=[])
        first = tool.run(args, owned_test_child=target)
        tool.base.require(first["hit"] and first["detached"] and first["restored_threads"],
                          "real hardware breakpoint did not hit/restore/detach")
        tool.base.require(first["sample"]["registers"]["eip"] == fixture["address"],
                          "wrong actual EIP")
        tool.base.require(first["sample"]["fs"]["complete"], "WOW64 FS descriptor/head unavailable")
        second = tool.run(args, owned_test_child=target)
        tool.base.require(second["hit"] and second["detached"], "repeat attach failed after restoration")
        args.synthetic_address += 128
        args.seconds = 0.4
        missed = tool.run(args, owned_test_child=target)
        tool.base.require(not missed["hit"] and missed["detached"] and missed["restored_threads"],
                          "timeout cleanup failed")
        tool.base.require(target.poll() is None, "target terminated by debugger")
        args.seconds = 61
        try:
            tool.run(args)
        except tool.base.CaptureError:
            pass
        else:
            raise RuntimeError("deadline negative accepted")
    finally:
        target.terminate()
        target.wait(timeout=5)
    target = subprocess.Popen([str(exe), "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
        "Bypass", "-File", str(Path(__file__).with_name("runtime_capture_41_synthetic.ps1")),
        "-ApplicationBreakpoint"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        fixture = json.loads(target.stdout.readline())
        args = SimpleNamespace(pid=target.pid, exe=exe, profile="synthetic", seconds=5,
            boundary=tool.base.pe_identity(exe)["preferred_base"],
            synthetic_address=fixture["address"] + 1, region=[(fixture["counter"], 4)])
        result = tool.run(args, owned_test_child=target)
        count = struct.unpack("<I", bytes.fromhex(result["sample"]["memory"][1]["hex"]))[0]
        tool.base.require(result["hit"] and count > 0, "application INT3 handler was suppressed")
        print(json.dumps({"real_hits": 3, "timeout_cleanup": True, "target_alive": True,
                          "application_breakpoint_handler_observed": True,
                          "optional_slot_regression_cases": 3,
                          "fs_head_complete": True, "optimized": not __debug__}))
    finally:
        target.terminate()
        target.wait(timeout=5)


if __name__ == "__main__":
    main()

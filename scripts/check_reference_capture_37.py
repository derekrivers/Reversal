"""Bounded real-Windows checks using only a child x86 PowerShell allocation."""
import argparse
import contextlib
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import tempfile
from types import SimpleNamespace

import reference_capture_37 as tool


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def rejected(function, text):
    try:
        function()
    except tool.CaptureError as error:
        check(text in str(error), f"wrong rejection: {error}")
    else:
        raise RuntimeError(f"missing rejection: {text}")


def main():
    argument = argparse.ArgumentParser(description=__doc__)
    argument.add_argument("--output", type=Path)
    args = argument.parse_args()
    check(os.name == "nt", "this check requires real Windows APIs")
    exe = Path(os.environ["WINDIR"])/"SysWOW64/WindowsPowerShell/v1.0/powershell.exe"
    check(exe.is_file(), "x86 Windows PowerShell is unavailable")
    support = Path(__file__).with_name("reference_capture_37_synthetic.ps1")
    target = subprocess.Popen([str(exe), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                               "-File", str(support)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    lines = []
    reader = threading.Thread(target=lambda: lines.append(target.stdout.readline()), daemon=True)
    reader.start()
    try:
        reader.join(20)
        check(not reader.is_alive() and lines and lines[0], "safe target did not become ready")
        fixture = json.loads(lines[0])
        check(fixture["pid"] == target.pid and fixture["size"] == 64, "wrong fixture identity")
        identity = tool.pe_identity(exe)
        baseline = SimpleNamespace(pid=target.pid, exe=exe, mode="inventory", thread=None,
                                   samples=3, interval_ms=1, seconds=2,
                                   region=[], boundary=identity["preferred_base"],
                                   synthetic_sha256=tool.sha256_file(exe))
        inventory = tool.capture(baseline)
        check(inventory["profile"] == "synthetic-test" and inventory["probe_count"] == 0,
              "inventory was mislabelled or sampled")
        check(not inventory["boundary_observed"], "inventory claimed a boundary")
        check(inventory["memory_complete"] is None and
              inventory["consistency"] == "inventory only; no thread or context sample" and
              inventory["instrumentation"] == "read-only module and thread inventory; no suspension",
              "inventory implied a context or memory sample")
        check(inventory["boundary"]["rva"] == 0 and
              inventory["module"]["size"] == identity["image_size"], "wrong module mapping")
        selected = min(inventory["threads"])
        baseline.mode, baseline.thread = "snapshot", selected
        baseline.region = [(fixture["address"], 64), (0, 32)]
        snapshot = tool.capture(baseline)
        sample = snapshot["samples"][0]
        check(sample["registers"]["eip"] != 0 and sample["registers"]["esp"] != 0,
              "missing x86 integer context")
        check(len(sample["extended_registers_hex"]) == 1024, "missing extended context")
        check(sample["x87"]["control_word"] != 0, "missing x87 control")
        stack, owned, invalid = sample["memory"]
        check(stack["complete"] and stack["received"] == 128, "stack sample incomplete")
        check(owned["complete"] and owned["hex"] == bytes(range(64)).hex(), "wrong synthetic allocation bytes")
        check(owned["sha256"] == hashlib.sha256(bytes(range(64))).hexdigest(), "wrong data digest")
        check(not invalid["complete"] and invalid["winerror"] != 0 and invalid["received"] == 0,
              "failed read silently accepted")
        check(not snapshot["memory_complete"], "incomplete memory not reported")
        baseline.mode, baseline.region = "watch", []
        missed = tool.capture(baseline)
        check(not missed["boundary_observed"] and missed["probe_count"] == 3 and not missed["samples"],
              "bounded miss incorrectly reported")
        check(missed["memory_complete"] is None, "miss implied a memory sample")
        check(missed["stop_reason"] == "sample-or-time-limit-boundary-not-observed", "missing stop reason")

        # EIP success path is tested with a mock only. Real API tests above do not
        # establish an exact application-boundary hit, even in the safe process.
        mapping = tool.map_boundary(identity, 0x12000000, identity["preferred_base"]+0x1000)
        check(mapping["rva"] == 0x1000 and mapping["runtime_va"] == 0x12001000,
              "ASLR mapping confused preferred VA with runtime VA")
        actual_windows = tool.Windows
        class SimulatedHit(actual_windows):
            @contextlib.contextmanager
            def suspended_context(self, tid, owner_pid):
                with super().suspended_context(tid, owner_pid) as context:
                    # Alter only the returned local copy, never the target.
                    context.Eip = inventory["boundary"]["runtime_va"]
                    yield context
        tool.Windows = SimulatedHit
        try:
            simulated_hit = tool.capture(baseline)
            check(simulated_hit["boundary_observed"] and simulated_hit["probe_count"] == 1
                  and simulated_hit["stop_reason"] == "boundary-hit"
                  and len(simulated_hit["samples"]) == 1, "mocked hit path failed")
        finally:
            tool.Windows = actual_windows
        negatives = 0
        def negative(changes, text):
            nonlocal negatives
            options = SimpleNamespace(**(vars(baseline) | changes))
            rejected(lambda: tool.capture(options), text)
            negatives += 1
        negative({"synthetic_sha256": "0"*64}, "SHA-256 mismatch")
        negative({"synthetic_sha256": None}, "SHA-256 mismatch")
        negative({"synthetic_sha256": tool.PINNED}, "cannot be labelled")
        negative({"thread": 0}, "not owned")
        negative({"thread": None}, "requires a selected")
        negative({"samples": 1001}, "bounds exceeded")
        negative({"seconds": 31}, "bounds exceeded")
        negative({"region": [(0, 4097)]}, "invalid region")
        negative({"region": [(0, 4096)]*4}, "budget")
        negative({"boundary": identity["preferred_base"]+identity["image_size"]}, "outside image")
        negative({"pid": os.getpid()}, "self target")
        rejected(lambda: tool.pe_identity(Path(sys.executable)), "only PE32 x86 images")
        negatives += 1
        class DeniedProcess(actual_windows):
            def __init__(self):
                super().__init__()
                def denied(*_):
                    C.set_last_error(5)
                    return 0
                self.api.OpenProcess = denied
            def suspended_context(self, *_):
                raise RuntimeError("access failure must never sample threads")
        tool.Windows = DeniedProcess
        try:
            negative({}, "OpenProcess(QUERY_INFORMATION|VM_READ) failed; WinError=5")
        finally:
            tool.Windows = actual_windows

        # A failed context and an already suspended thread must balance our own
        # suspension increment before returning an error.
        win = tool.Windows()
        def wrong_owner():
            with win.suspended_context(selected, os.getpid()):
                pass
        rejected(wrong_owner, "opened thread is not owned")
        negatives += 1
        with win.handle(win.api.OpenThread(0x004A, False, selected)) as thread:
            previous = win.api.Wow64SuspendThread(thread)
            check(previous == 0, "unexpected synthetic thread suspend count")
            try:
                rejected(lambda: tool.capture(baseline), "pre-suspended")
                negatives += 1
            finally:
                check(win.api.ResumeThread(thread) == 1, "tool leaked its suspend increment")
        original = win.api.Wow64GetThreadContext
        win.api.Wow64GetThreadContext = lambda *_: 0
        try:
            def failed_context():
                with win.suspended_context(selected, target.pid):
                    pass
            rejected(failed_context, "Wow64GetThreadContext failed")
            negatives += 1
        finally:
            win.api.Wow64GetThreadContext = original
        # Exercise CLI privacy paths, refusal to overwrite, and explicit failed
        # output. No local paths or private sample bytes enter the public receipt.
        (tool.ROOT/"results").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="reference37-cli-", dir=tool.ROOT/"results") as directory:
            output = Path(directory)/"inventory.json"
            python_flags = [] if __debug__ else ["-O"]
            command = [sys.executable, *python_flags, str(Path(tool.__file__)), "inventory", "--pid", str(target.pid),
                       "--exe", str(exe), "--synthetic-sha256", baseline.synthetic_sha256,
                       "--boundary", hex(identity["preferred_base"]),
                       "--output", str(output)]
            run = subprocess.run(command, capture_output=True, text=True, timeout=15)
            check(run.returncode == 0 and json.loads(run.stdout)["private_output_written"], "CLI inventory failed")
            retained = output.read_bytes()
            serialized = json.loads(retained)
            check("path" not in json.dumps(serialized["modules"]).lower(), "module paths leaked")
            collision = subprocess.run(command, capture_output=True, text=True, timeout=15)
            check(collision.returncode == 1 and output.read_bytes() == retained, "CLI overwrote evidence")
            negatives += 1
            wrong_hash = command.copy()
            wrong_hash[wrong_hash.index("--synthetic-sha256")+1] = "0"*64
            failed = Path(directory)/"failed.json"
            wrong_hash[-1] = str(failed)
            failure = subprocess.run(wrong_hash, capture_output=True, text=True, timeout=15)
            check(failure.returncode == 1 and json.loads(failed.read_text())["capture_accepted"] is False,
                  "CLI failure left an apparently valid capture")
            negatives += 1
            forbidden = command.copy()
            forbidden[-1] = str(tool.ROOT/"public-capture-must-not-exist.json")
            outside = subprocess.run(forbidden, capture_output=True, text=True, timeout=15)
            check(outside.returncode == 1 and not Path(forbidden[-1]).exists(), "CLI wrote outside ignored results")
            negatives += 1
        # Verify the thread remains resumable and the target exits normally.
        target.stdin.write("done\n")
        target.stdin.flush()
        check(target.wait(timeout=10) == 0, "safe target failed to resume and exit")
        rejected(lambda: tool.capture(baseline), "exited")
        negatives += 1
        summary = {"schema": "reversal.reference-capture-37-check.v1", "synthetic_only": True,
                   "game_runtime_observed": False, "api_test_target": "x86 Windows PowerShell",
                   "module_inventory": True, "context_and_x87": True,
                   "synthetic_allocation_bytes": 64, "stack_bytes": 128,
                   "failed_read_explicit": True, "watch_miss_probes": 3,
                   "real_exact_boundary_hit_tested": False, "negative_checks": negatives,
                   "mocked_hit_path_tested": True, "cli_privacy_and_no_overwrite": True,
                   "target_resumed_and_exited": True,
                   "public_receipt_contains_no_context_or_memory": True}
        if args.output:
            output = args.output.resolve()
            check(output.is_relative_to(tool.ROOT/"results"), "receipt must remain in ignored results")
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8") as stream:
                json.dump(summary, stream, indent=2)
                stream.write("\n")
        print(json.dumps(summary, sort_keys=True))
    finally:
        if target.poll() is None:
            target.kill()  # Only the child process created by this checker.
        target.communicate(timeout=10)


if __name__ == "__main__":
    main()

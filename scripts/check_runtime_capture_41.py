"""Exercise a real single-use DR0 interception on an owned WOW64 child."""
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import runtime_capture_41 as tool


def main():
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
        print(json.dumps({"real_hits": 2, "timeout_cleanup": True, "target_alive": True,
                          "optimized": not __debug__}))
    finally:
        target.terminate()
        target.wait(timeout=5)


if __name__ == "__main__":
    main()

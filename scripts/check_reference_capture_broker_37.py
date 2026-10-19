#!/usr/bin/env python3
"""Exercise broker framing, authentication and test-only capture rejection."""
import csv
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import reference_capture_broker_37 as broker


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def query(port, message):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        broker.send(connection, message)
        return broker.read_line(connection)


def check_output_confinement():
    original_root, original_results = broker.ROOT, broker.RESULTS
    with tempfile.TemporaryDirectory(prefix="reference37-broker-guard-") as temporary:
        root = Path(temporary) / "checkout"
        outside = Path(temporary) / "outside"
        results = root / "results"
        results.mkdir(parents=True)
        outside.mkdir()
        broker.ROOT, broker.RESULTS = root, results
        try:
            path = results / "capture.json"
            with broker.secure_new_result(path) as stream:
                try:
                    results.rename(root / "moved")
                except OSError:
                    pass
                else:
                    raise RuntimeError("results directory moved while private handle was open")
                stream.write('{"private":true}\n')
            check(json.loads(path.read_text(encoding="utf-8"))["private"],
                  "guarded output was not valid JSON")
            try:
                with broker.secure_new_result(path):
                    pass
            except ValueError:
                pass
            else:
                raise RuntimeError("existing private result was overwritten")
            identity = subprocess.run([str(broker.SYSTEM32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                                      check=True, capture_output=True, text=True)
            sid = next(csv.reader(identity.stdout.splitlines()))[1]
            session = results / "session.json"
            with broker.session_security(sid) as security:
                with broker.secure_new_result(session, security=security) as stream:
                    acl = subprocess.run([str(broker.SYSTEM32 / "icacls.exe"), str(session)],
                                         check=True, capture_output=True, text=True).stdout
                    check("(I)" not in acl and "CodexSandboxUsers" not in acl,
                          "session was readable through inherited ACL before token write")
                    stream.write('{"token":"test"}\n')
            session.unlink()
            path.unlink()
            results.rmdir()
            junction = subprocess.run(["cmd", "/c", "mklink", "/J", str(results), str(outside)],
                                      capture_output=True, text=True)
            check(junction.returncode == 0 and results.is_junction(),
                  "could not create disposable junction fixture")
            try:
                with broker.secure_new_result(results / "leak.json"):
                    pass
            except ValueError:
                pass
            else:
                raise RuntimeError("junction result directory was accepted")
            check(not (outside / "leak.json").exists(), "private output escaped through junction")
            results.rmdir()
        finally:
            broker.ROOT, broker.RESULTS = original_root, original_results


def main():
    check(broker.MAX_WIRE == 4096, "wire bound changed")
    check_output_confinement()
    for value in ({"mode": "ping"}, {"token": "bad", "mode": "ping"}):
        try:
            broker.bounded_request(value, "a" * 64)
        except ValueError:
            pass
        else:
            raise RuntimeError("unauthenticated request accepted")
    first, second = socket.socketpair()
    def drip():
        try:
            for item in b'{"x":1}\n':
                second.send(bytes([item]))
                time.sleep(0.02)
        except OSError:
            pass
    sender = threading.Thread(target=drip)
    sender.start()
    started = time.monotonic()
    try:
        try:
            broker.read_line(first, timeout=0.05)
        except (OSError, ValueError):
            pass
        else:
            raise RuntimeError("slow-drip frame bypassed total deadline")
        check(time.monotonic()-started < 0.15, "framing deadline took too long")
    finally:
        first.close()
        second.close()
        sender.join(timeout=1)
    for value in ({"token": "a" * 64, "mode": "shell"},
                  {"token": "a" * 64, "mode": "snapshot", "pid": 1},
                  {"token": "a" * 64, "mode": "inventory", "pid": 1, "output": "escape"}):
        try:
            broker.bounded_request(value, "a" * 64)
        except ValueError:
            pass
        else:
            raise RuntimeError("unbounded request accepted")
    session = broker.RESULTS / f"reference37-broker-test-{uuid.uuid4().hex}.json"
    command = [sys.executable, "-B", str(Path(broker.__file__)), "--serve", "--test-only",
               "--session", str(session), "--exe", str(Path(sys.executable))]
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        status = None
        for _ in range(100):
            if session.exists():
                try:
                    status = json.loads(session.read_text(encoding="utf-8"))
                    break
                except json.JSONDecodeError:
                    pass
            if child.poll() is not None:
                raise RuntimeError("broker test exited before ready: " +
                                   child.stderr.read().decode(errors="replace"))
            time.sleep(0.05)
        check(status is not None, "broker did not become ready")
        acl = subprocess.run([str(broker.SYSTEM32 / "icacls.exe"), str(session)],
                             check=True, capture_output=True, text=True).stdout
        check("(I)" not in acl and "CodexSandboxUsers" not in acl,
              "session bearer secret retained inherited or sandbox-group access")
        port, token = status["port"], status["token"]
        check(query(port, {"token": token, "mode": "ping"})["status"] == "ready", "ping failed")
        check(not query(port, {"token": "0" * 64, "mode": "ping"})["ok"], "bad token accepted")
        check(not query(port, {"token": "é", "mode": "ping"})["ok"], "non-ASCII token accepted")
        check(query(port, {"token": token, "mode": "ping"})["status"] == "ready",
              "malformed token terminated broker")
        check(not query(port, {"token": token, "mode": "inventory", "pid": 1})["ok"],
              "test broker allowed capture")
        check(query(port, {"token": token, "mode": "stop"})["status"] == "stopping",
              "stop failed")
        child.wait(timeout=5)
        check(child.returncode == 0 and not session.exists(), "broker did not cleanly stop")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        session.unlink(missing_ok=True)
    print(json.dumps({"status": "passed", "authentication": "required",
                      "non_ascii_token": "rejected without server exit",
                      "slow_frame": "total deadline enforced",
                      "capture": "test-only rejected", "shutdown": "clean"}))


if __name__ == "__main__":
    main()

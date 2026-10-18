#!/usr/bin/env python3
"""Check receipt alias rejection using synthetic private-input stand-ins only."""
import argparse
import json
import os
from pathlib import Path
import runpy
from types import SimpleNamespace
import subprocess
import sys
import tempfile

CHECK = Path(__file__).with_name("extractor-integrity-20-check.py")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run():
    harness = runpy.run_path(str(CHECK))
    env = dict(os.environ)
    env.pop("PYTHONOPTIMIZE", None)
    results = []
    skipped = []
    with tempfile.TemporaryDirectory(prefix="extractor-integrity-20-alias-") as directory:
        root = Path(directory)
        exports = root / "exports"
        exports.mkdir()
        nested = exports / "nested"
        nested.mkdir()
        binary = root / "synthetic-binary.bin"
        preflight = root / "synthetic-preflight.json"
        manifest = exports / "manifest.json"
        assembly = nested / "synthetic-export.asm"
        protected = [binary, preflight, manifest, assembly]
        for index, path in enumerate(protected):
            path.write_bytes(f"synthetic private-input stand-in {index}\n".encode())
        original = {path: path.read_bytes() for path in protected}
        args = SimpleNamespace(binary=binary, preflight=preflight, exports=exports)
        cases = []
        for target, path in zip(("binary", "preflight", "export-manifest", "nested-export"), protected):
            cases.append((target + ":direct", path))
            symbolic = root / (target + "-symlink")
            try:
                symbolic.symlink_to(path)
            except OSError as error:
                if getattr(error, "winerror", None) != 1314:
                    raise
                skipped.append(target + ":symlink:Windows privilege unavailable")
            else:
                cases.append((target + ":symlink", symbolic))
            hard = root / (target + "-hardlink")
            hard.hardlink_to(path)
            cases.append((target + ":hardlink", hard))
        cases.append(("export-directory:new-output", exports / "new-receipt.json"))
        export_link = root / "export-directory-link"
        try:
            export_link.symlink_to(exports, target_is_directory=True)
        except OSError as error:
            if getattr(error, "winerror", None) != 1314:
                raise
            skipped.append("export-directory:symlink-parent:Windows privilege unavailable")
        else:
            cases.append(("export-directory:symlink-parent", export_link / "new-receipt.json"))
        alias_parent = root / "alias-parent"
        alias_parent.mkdir()
        cases.append(("binary:normalized-path", alias_parent / ".." / binary.name))
        for label, output in cases:
            args.receipt = output
            # The writer independently rechecks aliases even if called without run().
            try:
                harness["write_receipt"](args, {"synthetic": True})
            except RuntimeError as error:
                require(str(error) == harness["ALIAS_REFUSAL"], label + ": unexpected rejection")
            else:
                raise RuntimeError(label + ": writer accepted an input alias")
            for mode in ("normal", "-O", "-OO", "PYTHONOPTIMIZE=1"):
                mode_env = dict(env)
                flags = [mode] if mode.startswith("-") else []
                if mode == "PYTHONOPTIMIZE=1":
                    mode_env["PYTHONOPTIMIZE"] = "1"
                result = subprocess.run([sys.executable, *flags, str(CHECK),
                                         "--binary", str(binary), "--exports", str(exports),
                                         "--preflight", str(preflight), "--receipt", str(output)],
                                        env=mode_env, capture_output=True, text=True)
                require(result.returncode != 0 and not result.stdout and
                        harness["ALIAS_REFUSAL"] in result.stderr and
                        "check requires pinned specimen" not in result.stderr,
                        label + ": CLI failed to reject before specimen validation")
                require(all(path.read_bytes() == data for path, data in original.items()),
                        label + ": private stand-in changed")
            require(not (exports / "new-receipt.json").exists(), label + ": export output created")
            results.append(label)
        # Valid receipt destinations support both new files and replacement.
        output = root / "safe-receipt.json"
        args.receipt = output
        for value in (1, 2):
            harness["write_receipt"](args, {"synthetic": value})
            require(json.loads(output.read_text()) == {"synthetic": value}, "valid receipt write failed")
        require(all(path.read_bytes() == data for path, data in original.items()), "private stand-in changed")
    return dict(work_unit="R20-V2", synthetic_inputs_only=True,
                python_version=sys.version.split()[0], platform=sys.platform,
                alias_cases=results, cli_modes=["normal", "-O", "-OO", "PYTHONOPTIMIZE=1"],
                cli_rejections=len(results) * 4, writer_rejections=len(results),
                skipped=skipped,
                private_stand_ins_unchanged=True, valid_receipt_create_and_replace="passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.parse_args()
    print(json.dumps(run(), indent=2))

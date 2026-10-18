#!/usr/bin/env python3
"""Prove R23-B's specimen and native operand gates reject altered private inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

import extract_exit_runtime_23 as core


def reject(binary, exports, preflight, expected):
    try:
        core.run(binary, exports, preflight)
    except ValueError as error:
        if expected not in str(error):
            raise ValueError("unexpected rejection: " + str(error)) from error
        return str(error)
    raise ValueError("altered input was accepted")


def run(args):
    baseline = core.run(args.binary, args.exports, args.preflight)
    results = {}
    with tempfile.TemporaryDirectory(prefix="r23-exit-negative-") as directory:
        tmp = Path(directory)
        changed_pe = tmp / "changed.exe"
        raw = bytearray(args.binary.read_bytes())
        raw[0x545983] ^= 1
        changed_pe.write_bytes(raw)
        results["altered_specimen"] = reject(changed_pe, args.exports, args.preflight,
                                               "specimen size/SHA-256 mismatch")
        for case, old, new in (
            ("changed_write_width", "00945983  MOV byte ptr", "00945983  MOV dword ptr"),
            ("changed_import_slot", "009459e7  CALL dword ptr [0x00967164]",
             "009459e7  CALL dword ptr [0x00967168]"),
        ):
            clone = tmp / case
            clone.mkdir()
            for source in args.exports.iterdir():
                if source.is_file():
                    shutil.copy2(source, clone / source.name)
            asm = clone / "00945956.asm"
            text = asm.read_text(encoding="utf-8")
            changed = text.replace(old, new, 1)
            if changed == text:
                raise ValueError("native mutation target missing: " + case)
            asm.write_text(changed, encoding="utf-8", newline="\n")
            manifest_file = clone / "manifest.json"
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            altered = asm.read_bytes()
            manifest["files"][asm.name] = {"bytes": len(altered),
                                           "sha256": hashlib.sha256(altered).hexdigest()}
            manifest_file.write_text(json.dumps(manifest)+"\n", encoding="utf-8", newline="\n")
            original_sha = core.MANIFEST_SHA
            try:
                # The changed export and its manifest agree, so the PE/native
                # operand comparison itself must reject the mutation.
                core.MANIFEST_SHA = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
                results[case] = reject(args.binary, clone, args.preflight,
                                       "native mnemonic/operand mismatch at " +
                                       ("00945983" if case == "changed_write_width" else "009459e7"))
            finally:
                core.MANIFEST_SHA = original_sha
    return {
        "schema_version": 1, "unit": "R23-B", "specimen_sha256": core.SPECIMEN_SHA,
        "positive_complete_local_bodies": len(baseline["bodies"]),
        "rejections": results, "no_negative_evidence_output_written": True,
        "python_optimization": "explicit exceptions; checks active under -O",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/exit-runtime-23-negative.json"))
    args = parser.parse_args()
    receipt = run(args)
    args.output.write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8", newline="\n")
    print("wrote", args.output)

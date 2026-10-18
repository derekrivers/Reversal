#!/usr/bin/env python3
"""Prove R24-C static checks reject changed specimen and native operands."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

import extract_path_format_24 as core


def reject(binary, exports, preflight, expected):
    try:
        core.run(binary, exports, preflight)
    except ValueError as error:
        if expected not in str(error):
            raise ValueError("unexpected rejection: "+str(error)) from error
        return str(error)
    raise ValueError("altered input was accepted")


def run(args):
    baseline = core.run(args.binary, args.exports, args.preflight)
    rejections = {}
    with tempfile.TemporaryDirectory(prefix="r24-path-negative-") as directory:
        tmp = Path(directory)
        changed_pe = tmp / "changed.exe"
        raw = bytearray(args.binary.read_bytes())
        raw[0x544D5C] ^= 1
        changed_pe.write_bytes(raw)
        rejections["altered_specimen"] = reject(
            changed_pe, args.exports, args.preflight, "specimen size/SHA-256 mismatch")
        previous = core.EXPECTED_SITE_OPERANDS
        try:
            core.EXPECTED_SITE_OPERANDS = {**previous,
                0x944D4D: "MOV ESI,0xfe"}
            rejections["wrong_copy_cap_expectation"] = reject(
                args.binary, args.exports, args.preflight,
                "critical operand mismatch at 00944d4d")
        finally:
            core.EXPECTED_SITE_OPERANDS = previous
        for case, filename, old, new, site in (
            ("changed_scan_table", "00944cff.asm",
             "00944d5c  TEST byte ptr [EDX + 0xde4521],0x4",
             "00944d5c  TEST byte ptr [EDX + 0xde4521],0x8", "00944d5c"),
            ("changed_formatter_call", "00944c9f.asm",
             "00944cc8  CALL 0x00947c67",
             "00944cc8  CALL 0x00947b52", "00944cc8"),
        ):
            clone = tmp / case
            clone.mkdir()
            for source in args.exports.iterdir():
                if source.is_file():
                    shutil.copy2(source, clone / source.name)
            asm = clone / filename
            native = asm.read_text(encoding="utf-8")
            altered = native.replace(old, new, 1)
            if altered == native:
                raise ValueError("native mutation target missing: "+case)
            asm.write_text(altered, encoding="utf-8", newline="\n")
            manifest_file = clone / "manifest.json"
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            changed = asm.read_bytes()
            manifest["files"][filename] = {"bytes": len(changed),
                                           "sha256": hashlib.sha256(changed).hexdigest()}
            manifest_file.write_text(json.dumps(manifest)+"\n", encoding="utf-8", newline="\n")
            original_sha = core.MANIFEST_SHA
            try:
                core.MANIFEST_SHA = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
                rejections[case] = reject(args.binary, clone, args.preflight,
                                           "native mnemonic/operand mismatch at "+site)
            finally:
                core.MANIFEST_SHA = original_sha
    return {"schema_version": 1, "unit": "R24-C",
            "specimen_sha256": core.SPECIMEN_SHA,
            "positive_complete_local_bodies": len(baseline["bodies"]),
            "rejections": rejections, "no_negative_evidence_output_written": True,
            "python_optimization": "explicit exceptions; checks active under -O"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("evidence/path-format-24-negative.json"))
    args = p.parse_args()
    receipt = run(args)
    args.output.write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8", newline="\n")
    print("wrote", args.output)

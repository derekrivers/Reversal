#!/usr/bin/env python3
"""Reproduce R22-D negative integrity/operand checks without retaining private inputs."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

import extract_match_runtime_22 as core


def rejection(binary, exports, preflight, needle):
    try:
        core.run(binary, exports, preflight)
    except ValueError as error:
        message = str(error)
        if needle not in message:
            raise ValueError(f"unexpected rejection: {message}") from error
        return message
    raise ValueError("mutated input was accepted")


def run(args):
    # Positive baseline first; all private input copies remain in a temporary directory.
    baseline = core.run(args.binary, args.exports, args.preflight)
    with tempfile.TemporaryDirectory(prefix="r22-runtime-negative-") as directory:
        tmp = Path(directory)
        bad_pe = tmp / "mutated.exe"
        pe = bytearray(args.binary.read_bytes())
        pe[0x1a8f60] ^= 1
        bad_pe.write_bytes(pe)
        specimen_reason = rejection(bad_pe, args.exports, args.preflight, "specimen SHA-256 mismatch")

        changed_exports = tmp / "exports"
        changed_exports.mkdir()
        for source in args.exports.iterdir():
            if source.is_file():
                shutil.copy2(source, changed_exports / source.name)
        assembly = changed_exports / "00945934.asm"
        text = assembly.read_text(encoding="utf-8")
        altered = text.replace("00945934  PUSH 0x0", "00945934  PUSH 0x1", 1)
        if altered == text:
            raise ValueError("operand-mutation target missing")
        assembly.write_text(altered, encoding="utf-8", newline="\n")
        manifest_file = changed_exports / "manifest.json"
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        raw = assembly.read_bytes()
        manifest["files"][assembly.name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        manifest_file.write_text(json.dumps(manifest) + "\n", encoding="utf-8", newline="\n")
        old_manifest_sha = core.MANIFEST_SHA
        try:
            # A self-consistent replacement manifest still must fail PE/native
            # operand comparison. This changes the in-memory test constant only.
            core.MANIFEST_SHA = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
            operand_reason = rejection(args.binary, changed_exports, args.preflight,
                                       "native mnemonic/operand mismatch at 00945934")
        finally:
            core.MANIFEST_SHA = old_manifest_sha
    return {
        "unit": "R22-D", "specimen_sha256": core.SPECIMEN_SHA,
        "positive_complete_local_bodies": len(baseline["bodies"]),
        "changed_specimen": {"rejected": True, "reason": specimen_reason},
        "self_consistent_manifest_with_changed_native_operand":
            {"rejected": True, "reason": operand_reason},
        "no_negative_output_written": True,
        "python_optimization": "checks use ValueError and remain active with -O",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/match-runtime-22-negative.json"))
    opts = parser.parse_args()
    receipt = run(opts)
    opts.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("wrote", opts.output)

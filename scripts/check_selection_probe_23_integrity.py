#!/usr/bin/env python3
"""Repeat R23-C extraction under normal/-O and reject specimen/native mutations."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from extract_selection_probe_23 import extract, normalized


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, changed_exports):
    script = Path(__file__).with_name("extract_selection_probe_23.py")
    expected = json.dumps(extract(args.binary, args.exports, args.preflight), indent=2) + "\n"
    if normalized("MOV EAX,dword ptr [ESP + 0x8]") == normalized("MOV EAX,dword ptr [ESP + 0xc]"):
        raise ValueError("operand normalization failed to distinguish changed stack offset")
    result = {"work_unit": "R23-C", "normal_and_optimized_equal": False,
              "wrong_specimen_rejected": {}, "changed_native_operand_rejected": {},
              "operand_normalizer_rejects_offset_change": True}
    with tempfile.TemporaryDirectory(prefix="probe23-negative-") as temporary:
        root = Path(temporary)
        sample = root / "mutated.exe"
        image = bytearray(args.binary.read_bytes())
        image[0x201] ^= 1
        sample.write_bytes(image)
        good_outputs = []
        for optimized in (False, True):
            label = "optimized" if optimized else "normal"
            mode = ["-O"] if optimized else []
            def launch(binary, exports, output):
                return subprocess.run([sys.executable, *mode, str(script), str(binary),
                    "--exports", str(exports), "--preflight", str(args.preflight), "--output", str(output)],
                    capture_output=True, text=True)
            good = root / (label + "-valid.json")
            p = launch(args.binary, args.exports, good)
            if p.returncode or good.read_text(encoding="utf-8") != expected:
                raise ValueError("valid extraction changed in " + label)
            good_outputs.append(sha(good))
            bad = root / (label + "-specimen.json")
            p = launch(sample, args.exports, bad)
            if p.returncode == 0 or bad.exists() or "specimen size/SHA-256 mismatch" not in p.stderr:
                raise ValueError("wrong specimen accepted in " + label)
            result["wrong_specimen_rejected"][label] = True
            bad = root / (label + "-native.json")
            p = launch(args.binary, changed_exports, bad)
            if p.returncode == 0 or bad.exists() or "native export changed" not in p.stderr:
                raise ValueError("native mutation accepted in " + label)
            result["changed_native_operand_rejected"][label] = True
        result["normal_and_optimized_equal"] = good_outputs[0] == good_outputs[1]
        result["site_evidence_sha256"] = good_outputs[0]
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    # Mutate only after all original-input integrity checks have succeeded.
    extract(a.binary, a.exports, a.preflight)
    with tempfile.TemporaryDirectory(prefix="probe23-native-mutation-") as temporary:
        altered = Path(temporary)
        shutil.copytree(a.exports, altered / "exports")
        native = altered / "exports" / "00601070.asm"
        text = native.read_text(encoding="utf-8")
        changed = text.replace("[ESP + 0x8]", "[ESP + 0xc]", 1)
        if text == changed:
            raise ValueError("native mutation target absent")
        native.write_text(changed, encoding="utf-8")
        result = run(a, altered / "exports")
    a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")

#!/usr/bin/env python3
"""Confirm R25-C integrity gates reject changed specimen and native evidence."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from extract_copy_helper_25 import extract, need, ENTRY


def rejected(binary, exports, preflight, fragment):
    try:
        extract(binary, exports, preflight)
    except ValueError as exc:
        need(fragment in str(exc), "unexpected integrity rejection: "+str(exc))
        return str(exc)
    raise ValueError("mutation incorrectly accepted: "+fragment)


def run(binary, exports, preflight):
    original = extract(binary, exports, preflight)
    with tempfile.TemporaryDirectory(prefix="cm0102-copy-negative-") as directory:
        base = Path(directory)
        changed_binary = base/"changed.exe"
        shutil.copyfile(binary, changed_binary)
        data = bytearray(changed_binary.read_bytes())
        data[int(original["file_offset"], 16)+(0x94888d-ENTRY)] ^= 1
        changed_binary.write_bytes(data)
        specimen = rejected(changed_binary, exports, preflight, "pinned specimen mismatch")

        changed_exports = base/"exports"
        shutil.copytree(exports, changed_exports)
        asm = changed_exports/"00948851.asm"
        text = asm.read_text(encoding="utf-8")
        need("MOV byte ptr [EDI],AL" in text, "mutation operand absent")
        asm.write_text(text.replace("MOV byte ptr [EDI],AL", "XOV byte ptr [EDI],AL", 1),
                       encoding="utf-8")
        native = rejected(binary, changed_exports, preflight, "native export mismatch")

        changed_preflight = base/"preflight.json"
        text = preflight.read_text(encoding="utf-8")
        need("FUN_00948851" in text, "exact-old name absent")
        changed_preflight.write_text(text.replace("FUN_00948851", "FUN_00948852", 1),
                                     encoding="utf-8")
        old = rejected(binary, exports, changed_preflight,
                       "native manifest/preflight SHA-256 mismatch")
    return {"schema_version": 1, "unit": "R25-C", "optimized_python_safe": True,
            "specimen_byte_mutation": specimen, "native_operand_mutation": native,
            "exact_old_name_mutation": old}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("evidence/copy-helper-25-negative.json"))
    a = p.parse_args()
    result = run(a.binary, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")
    print("R25-C specimen/native/preflight mutations rejected")

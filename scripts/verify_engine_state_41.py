"""Reproduce R41-B evidence normally/optimized and reject altered contracts."""
from __future__ import annotations
import argparse
import base64
import copy
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

import replay_engine_state_41 as unit


TASK_FILES = (
    "scripts/replay_engine_state_41.py", "scripts/verify_engine_state_41.py",
    "reconstruction/engine-state-41.ts", "reconstruction/check-engine-state-41.ts",
    "reports/engine-state-41.md",
)


def patterns(images):
    raw, hexadecimal, encoded = set(), set(), set()
    for build, image in images.items():
        for _, left, right, length in unit.RANGES:
            body = unit.code_at(image, left if build == "pinned" else right, length)[0]
            for size in range(12, 33):
                for offset in range(len(body) - size + 1):
                    sample = body[offset:offset + size]
                    raw.add(sample); hexadecimal.add(sample.hex().encode())
            # Every 9-byte interior covers an aligned base64 group within any
            # 12-byte source excerpt, regardless of its embedding alignment.
            for size in range(9, 31, 3):
                for offset in range(len(body) - size + 1):
                    encoded.add(base64.b64encode(body[offset:offset + size]))
    return raw, hexadecimal, encoded


def privacy(data, masks):
    raw, hexadecimal, encoded = masks
    lower = data.lower()
    unit.need(not any(p in data for p in raw), "private raw code excerpt")
    unit.need(not any(p in lower for p in hexadecimal), "private hex code excerpt")
    unit.need(not any(p in data for p in encoded), "private base64 code excerpt")


def verify(args):
    images, decoded, mapping = unit.evidence(args.pinned, args.gdi)
    retained = args.oracle.read_bytes()
    masks = patterns(images)
    checked = []
    for name in TASK_FILES:
        path = unit.ROOT / name
        if path.exists():
            privacy(path.read_bytes(), masks); checked.append(name)
    privacy(retained, masks)
    negatives = []

    def reject(name, operation):
        try:
            operation()
        except (ValueError, OSError):
            negatives.append(name)
            return
        raise ValueError("negative probe accepted: " + name)

    with tempfile.TemporaryDirectory(prefix="engine-state-41-") as tmp:
        temp = Path(tmp)
        for suffix, switches in (("normal", []), ("optimized", ["-O"])):
            output = temp / (suffix + ".json")
            subprocess.run([sys.executable, "-B", *switches, str(Path(unit.__file__)),
                            str(args.pinned), str(args.gdi), "--output", str(output)],
                           check=True, capture_output=True, text=True)
            unit.need(output.read_bytes() == retained, suffix + " reproduction differs")
        wrong = temp / "wrong.exe"
        content = bytearray(args.pinned.read_bytes()); content[0x62ed70 - 0x400000] ^= 1
        wrong.write_bytes(content)
        reject("changed-pinned-PE", lambda: unit.evidence(wrong, args.gdi))
        reject("wrong-build-identity", lambda: unit.evidence(args.gdi, args.gdi))

    original_code_at = unit.code_at
    def changed_width(image, va, size):
        body, offset = original_code_at(image, va, size)
        if image["sha256"] == unit.EXPECTED["gdi"][0] and va == 0x6cf8e8:
            # 8b 46 69 is MOV EAX,[ESI+69]; 8a changes its operand to BYTE.
            body = bytes([0x8a]) + body[1:]
        return body, offset
    unit.code_at = changed_width
    try:
        reject("GDI-participant-read-width", lambda: unit.evidence(args.pinned, args.gdi))
    finally:
        unit.code_at = original_code_at

    old = unit.EXTERNAL_MAP[0xb63d28]
    unit.EXTERNAL_MAP[0xb63d28] += 4
    try:
        reject("wrong-lookup-global-map", lambda: unit.evidence(args.pinned, args.gdi))
    finally:
        unit.EXTERNAL_MAP[0xb63d28] = old

    case = unit.synthetic_schedule()[1]
    write = lambda uc, address, value: uc.mem_write(address, struct.pack("<I", value))
    for name, mutate in (
        ("original-missing-init-bit", lambda uc: uc.mem_write(0xb63d10, b"\x06")),
        ("original-stale-row", lambda uc: write(uc, unit.ROWS, case["date"] ^ 1)),
        ("original-null-attributes", lambda uc: write(uc, unit.PLAYER + 0x61, 0)),
        ("original-out-of-count", lambda uc: write(uc, unit.PLAYER, case["count"])),
    ):
        reject(name, lambda mutate=mutate: unit.execute(images, decoded, "pinned", case, mutate))

    body = original_code_at(images["pinned"], 0x62c680, 0x116)[0]
    late = body[-40:-8]
    reject("late-raw-excerpt", lambda: privacy(b"prefix" + late, masks))
    reject("late-uppercase-hex", lambda: privacy(b"prefix" + late.hex().upper().encode(), masks))
    for padding in range(3):
        reject("base64-alignment-" + str(padding),
               lambda padding=padding: privacy(base64.b64encode(b"x"*padding + late + b"suffix"), masks))
    result = {"schema": "reversal.engine-state-41.integrity.v1",
              "oracle_sha256": unit.sha(retained), "normal_and_optimized_identical": True,
              "negative_probes": negatives, "privacy_scanned_files": checked + [str(args.oracle.name)],
              "privacy": "all overlapping 12..32-byte raw/hex and 9..30-byte aligned base64 source windows",
              "source_sha256": {name: unit.sha((unit.ROOT / name).read_bytes()) for name in checked},
              "specimens": mapping["specimens"], "captured_runtime_cases": 0}
    privacy(json.dumps(result).encode(), masks)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"negative_probes": len(negatives), "reproductions": 2, "private_code": "absent"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pinned", type=Path); parser.add_argument("gdi", type=Path)
    parser.add_argument("--oracle", type=Path, default=unit.ROOT / "evidence/engine-state-41-oracle.json")
    parser.add_argument("--output", type=Path, required=True)
    verify(parser.parse_args())

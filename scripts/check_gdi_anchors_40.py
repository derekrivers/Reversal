"""Compare bounded code anchors in the pinned and runnable GDI PE32 builds.

Only identities, offsets and digests are printed. The executables stay local;
this checker neither writes them nor publishes instruction bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct


EXPECTED = {
    "pinned": ("0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86", 7_192_576),
    "gdi": ("0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b", 7_188_480),
}

# Virtual addresses, not file offsets. These are independent local anchors;
# bytes outside each admitted interval have not been compared by this checker.
ANCHORS = (
    ("action33-entry", 0x702050, 0x701A80, 64),
    ("action33-keeper-through-effect", 0x702416, 0x701E46, 222),
    ("keeper-entry", 0x700420, 0x6FFE50, 64),
    ("effect-entry", 0x6CFE10, 0x6CF840, 32),
    ("score-effect-entry", 0x6D0980, 0x6D03B0, 24),
    ("bounded-rng-entry", 0x90CFC0, 0x90C860, 16),
)


class EvidenceError(ValueError):
    pass


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_pe(path: Path, kind: str) -> dict:
    data = path.read_bytes()
    expected_hash, expected_size = EXPECTED[kind]
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_hash:
        raise EvidenceError(f"{kind} executable identity mismatch")
    if len(data) < 4096 or data[:2] != b"MZ":
        raise EvidenceError(f"{kind} missing DOS header")
    nt = u32(data, 0x3C)
    if not 64 <= nt <= 2048 or data[nt:nt + 4] != b"PE\0\0":
        raise EvidenceError(f"{kind} missing bounded PE header")
    coff = nt + 4
    count = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    opt = coff + 20
    if u16(data, coff) != 0x14C or u16(data, opt) != 0x10B or not 1 <= count <= 32:
        raise EvidenceError(f"{kind} is not supported PE32 x86")
    if opt_size < 96 or opt + opt_size + count * 40 > len(data):
        raise EvidenceError(f"{kind} truncated section table")
    base = u32(data, opt + 28)
    if base != 0x400000:
        raise EvidenceError(f"{kind} unexpected preferred image base")
    sections = []
    for index in range(count):
        off = opt + opt_size + index * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, off + 8)
        flags = u32(data, off + 36)
        if raw_offset + raw_size > len(data):
            raise EvidenceError(f"{kind} section {name} exceeds file")
        sections.append((name, virtual_size, rva, raw_size, raw_offset, flags))
    return {"data": data, "sha256": expected_hash, "base": base, "sections": sections}


def code_at(pe: dict, va: int, size: int) -> tuple[bytes, int]:
    if size <= 0:
        raise EvidenceError("empty code anchor")
    rva = va - pe["base"]
    candidates = [section for section in pe["sections"]
                  if section[0] == ".text" and section[2] <= rva
                  and rva - section[2] + size <= section[3]
                  and section[5] & 0x20000000]
    if len(candidates) != 1:
        raise EvidenceError(f"code anchor {va:08x} is not uniquely mapped in executable .text")
    section = candidates[0]
    offset = section[4] + rva - section[2]
    return pe["data"][offset:offset + size], offset


def compare(pinned: Path, gdi: Path) -> dict:
    left, right = read_pe(pinned, "pinned"), read_pe(gdi, "gdi")
    anchors = []
    for name, pinned_va, gdi_va, length in ANCHORS:
        first, first_offset = code_at(left, pinned_va, length)
        second, second_offset = code_at(right, gdi_va, length)
        if first != second:
            mismatch = next(i for i, (a, b) in enumerate(zip(first, second)) if a != b)
            raise EvidenceError(f"{name} differs at relative offset {mismatch}")
        if right["data"].count(first) != 1:
            raise EvidenceError(f"{name} does not have a unique GDI file match")
        anchors.append({"name": name, "pinned_va": f"0x{pinned_va:08x}",
                        "gdi_va": f"0x{gdi_va:08x}", "bytes": length,
                        "pinned_file_offset": f"0x{first_offset:x}",
                        "gdi_file_offset": f"0x{second_offset:x}",
                        "sha256": hashlib.sha256(first).hexdigest()})
    return {"schema": "reversal.gdi-code-anchors-40.v1",
            "pinned_sha256": left["sha256"], "gdi_sha256": right["sha256"],
            "identity": "exact disk hashes; no runtime memory authentication",
            "scope": "bounded exact code bytes only; no state, callee, outcome or complete-build equivalence",
            "anchors": anchors}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pinned_exe", type=Path)
    parser.add_argument("gdi_exe", type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(args.pinned_exe, args.gdi_exe), indent=2))


if __name__ == "__main__":
    main()

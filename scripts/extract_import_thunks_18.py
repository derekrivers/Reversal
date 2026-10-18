#!/usr/bin/env python3
"""Characterize all six-byte absolute-IAT jump thunks in the pinned PE."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import x86

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "5ca2aa2d28e4bd92880421876d2f9f3aa69866761b8c4c91feb4c7bc06b0695b"
PREFLIGHT = "5a5d559926751b77b50a1e9797f047f19748b70af0dd1b73a1dfe141cbc0f298"
EXPECTED = tuple(f"{0x944c10 + 6*i:08x}" for i in range(22)) + ("009532a0",)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pe_reader(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", data, pe + 4)[0] == 0x14c
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x10b
    base = struct.unpack_from("<I", data, optional + 28)[0]
    sections = [struct.unpack_from("<IIII", data, optional + optional_size + 40*i + 8)
                for i in range(count)]

    def read(va: int, size: int) -> bytes:
        rva = va - base
        for _vsize, section_rva, raw_size, raw_offset in sections:
            if section_rva <= rva and rva + size <= section_rva + raw_size:
                start = raw_offset + rva - section_rva
                assert start + size <= len(data)
                return data[start:start + size]
        raise ValueError(f"Unmapped PE span {va:08x}+{size}")

    return read


def main():
    ap = argparse.ArgumentParser()
    for name in ("binary", "atlas", "exports", "preflight", "summary", "rows"):
        ap.add_argument("--" + name, type=Path, required=True)
    args = ap.parse_args()
    data = args.binary.read_bytes()
    assert len(data) == 7192576 and digest(data) == SPECIMEN
    read = pe_reader(data)
    atlas = [json.loads(line) for line in args.atlas.read_text(encoding="utf-8").splitlines()]
    assert len(atlas) == 9241
    by_entry = {row["entry"]: row for row in atlas}
    assert len(by_entry) == len(atlas)
    assert digest((args.exports / "manifest.json").read_bytes()) == MANIFEST
    manifest = json.loads((args.exports / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["specimen_sha256"] == SPECIMEN
    assert manifest["checkpoint_archive_sha256"] == "dcde69cbad630e36cc9779c1fcd5dbe3b4802ed4e51c3fa0d8e559b7e9381cd3"
    assert digest(args.preflight.read_bytes()) == PREFLIGHT == manifest["preflight_sha256"]
    preflight = json.loads(args.preflight.read_text(encoding="utf-8"))
    assert preflight["sha256"] == SPECIMEN
    sites = {row["address"]: row for row in preflight["sites"]}
    assert set(sites) == set(EXPECTED)
    assert set(manifest["files"]) == {addr + ext for addr in EXPECTED for ext in (".asm", ".c")}
    for filename, meta in manifest["files"].items():
        blob = (args.exports / filename).read_bytes()
        assert len(blob) == meta["bytes"] and digest(blob) == meta["sha256"], filename

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    out = []
    discovered = set()
    for f in atlas:
        if f["body_bytes"] != 6 or int(f["body_min"],16) != int(f["entry"],16) or int(f["body_max"],16) - int(f["entry"],16) + 1 != 6:
            continue
        entry = int(f["entry"], 16)
        body = read(entry, 6)
        if body[:2] != b"\xff\x25":
            continue
        ins = list(md.disasm(body, entry))
        assert len(ins) == 1 and ins[0].size == 6 and ins[0].mnemonic == "jmp"
        op = ins[0].operands[0]
        assert op.type == x86.X86_OP_MEM and op.size == 4 and not op.mem.base and not op.mem.index
        slot = op.mem.disp & 0xffffffff
        assert slot == struct.unpack_from("<I", body, 2)[0]
        read(slot, 4)  # Existing mapped image slot, not an asserted runtime pointer value.
        address = f["entry"]
        discovered.add(address)
        assert f["direct_callees"] == [] and f["call_instruction_count"] == 0 and not f["unresolved_indirect_call_sites"]
        native = (args.exports / (address + ".asm")).read_text(encoding="utf-8").strip()
        match = re.fullmatch(r"([0-9A-Fa-f]{8})\s+JMP dword ptr \[0x([0-9A-Fa-f]{8})\]", native)
        assert match and match[1].lower() == address and int(match[2],16) == slot, address
        site = sites[address]
        assert site["function_name"] == f["name"] and site["instruction_exists"] and not site.get("function_comment")
        out.append({"entry": address, "native_name": f["name"], "body_bytes": 6,
                    "body_sha256": digest(body), "iat_slot": f"{slot:08x}",
                    "local_contract": "unconditional indirect jump through absolute dword slot"})
    assert discovered == set(EXPECTED) and len(out) == 23
    assert len({row["iat_slot"] for row in out}) == 23
    evidence_dir = args.atlas.parent.parent
    semantic = json.loads((args.atlas.parent / "semantic-coverage.json").read_text(encoding="utf-8"))
    classified = {row["address"] for row in semantic["functions"]}
    for family in ("unwind-family-15-rows.jsonl", "delete-wrapper-family-17-rows.jsonl", "cleanup-family-18-rows.jsonl"):
        classified.update(json.loads(line)["entry"] for line in (evidence_dir / family).read_text(encoding="utf-8").splitlines())
    assert not discovered & classified
    out.sort(key=lambda row: row["entry"])
    summary = {"specimen_sha256": SPECIMEN, "checkpoint": "2026-10-18-investigation-17",
               "native_export_manifest_sha256": MANIFEST, "private_preflight_sha256": PREFLIGHT,
               "total": len(out), "contiguous_group": 22, "separate_entry": "009532a0",
               "unique_iat_slots": 23,
               "scope": "Complete six-byte local jump bodies only; imported target code, ordinal namespace and runtime IAT contents are outside scope."}
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.rows.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    args.rows.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in out), encoding="utf-8", newline="\n")
    print(f"Verified {len(out)} original-PE jump thunks and all native exports")


if __name__ == "__main__":
    main()

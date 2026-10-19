#!/usr/bin/env python3
"""Seal the two tactical-word PE bodies against checkpoint-28 native exports."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "ced03a8f3d9da3cc61fcb9d63e0be55cb1cc39776615c038e0320836a526c0da"
PREFLIGHT = "cee6d3c36808bd69afb14796fa22314a8900909e3b59e08544e5bdfe58063a0c"
ROWS = [(0x6c38c0, 0x8ebc), (0x6c38f0, 0x8ec4)]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError(f"SHA-256 mismatch: {path}")
    return raw


def norm(s):
    s = s.lower()
    s = re.sub(r"\bjz\b", "je", s)
    s = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0], 16)), s)
    return re.sub(r"\s+", "", s).replace("+0]", "]")


def extract(exe, exports, preflight):
    if capstone.__version__ != "5.0.7":
        raise ValueError("Capstone 5.0.7 required")
    data = checked(exe, PINNED)
    manifest = json.loads(checked(exports / "manifest.json", MANIFEST))
    prior = json.loads(checked(preflight, PREFLIGHT))
    if (manifest["specimen_sha256"] != PINNED or manifest["preflight_sha256"] != PREFLIGHT
            or prior["sha256"] != PINNED):
        raise ValueError("provenance mismatch")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if (data[:2] != b"MZ" or data[pe:pe+4] != b"PE\0\0"
            or struct.unpack_from("<H", data, pe+4)[0] != 0x14c
            or struct.unpack_from("<H", data, pe+24)[0] != 0x10b):
        raise ValueError("not PE32 x86")
    opt = pe + 24
    base = struct.unpack_from("<I", data, opt+28)[0]
    count = struct.unpack_from("<H", data, pe+6)[0]
    opt_size = struct.unpack_from("<H", data, pe+20)[0]
    sections = [struct.unpack_from("<8sIIII", data, opt+opt_size+40*i) for i in range(count)]

    def offset(va):
        for _, virtual_size, rva, raw_size, raw_offset in sections:
            delta = va-base-rva
            if 0 <= delta < raw_size and delta < max(virtual_size, raw_size):
                return raw_offset+delta
        raise ValueError(f"unbacked VA {va:08x}")

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    before = {r["address"]: r for r in prior["sites"]}
    out = []
    for entry, table_offset in ROWS:
        key = f"{entry:08x}"
        old = before[key]
        if old["body_addresses"] != 42 or not old["instruction_exists"]:
            raise ValueError("native preflight body mismatch " + key)
        if entry == 0x6c38f0 and old["function_name"] != "FUN_006c38f0":
            raise ValueError("new-body exact-old name mismatch")
        if entry == 0x6c38c0 and (old["function_name"] != "cm0102_lookup_tactical_position_word"
                or "return width2 measured" not in old["function_comment"]):
            raise ValueError("existing native annotation changed")
        hashes = {}
        for extension in ("asm", "c"):
            name = f"{key}.{extension}"
            raw = (exports / name).read_bytes()
            row = manifest["files"][name]
            if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
                raise ValueError("native export mismatch " + name)
            hashes[extension] = sha(raw)
        if old["function_name"] + "(" not in (exports / f"{key}.c").read_text():
            raise ValueError("native pseudocode identity mismatch")
        pos = offset(entry)
        if offset(entry+41) != pos+41:
            raise ValueError("noncontiguous PE body")
        body = data[pos:pos+42]
        ins = list(cs.disasm(body, entry))
        native = {}
        for line in (exports / f"{key}.asm").read_text().splitlines():
            address, instruction = line.split(None, 1)
            va = int(address, 16)
            if va in native:
                raise ValueError("duplicate native instruction")
            native[va] = norm(instruction)
        own = {i.address: norm(i.mnemonic + " " + i.op_str) for i in ins}
        if len(ins) != 13 or sum(i.size for i in ins) != 42 or own != native:
            raise ValueError(f"complete original/native instruction mismatch {key}: {own!r} != {native!r}")
        pointer = next(i for i in ins if i.address == entry+0x16)
        mem = pointer.operands[1].mem
        if (pointer.mnemonic != "mov" or mem.disp != table_offset
                or mem.scale != 4 or pointer.operands[1].size != 4):
            raise ValueError("table pointer operand mismatch")
        starts = set(own)
        edges = []
        for i in ins:
            targets = []
            if i.group(capstone.CS_GRP_JUMP):
                if i.operands[0].type != capstone.x86.X86_OP_IMM:
                    raise ValueError("indirect branch")
                targets.append(i.operands[0].imm)
            if i.mnemonic not in ("ret", "jmp"):
                targets.append(i.address+i.size)
            if any(t not in starts for t in targets):
                raise ValueError("CFG edge leaves local body")
            edges.extend([[f"{i.address:08x}", f"{t:08x}"] for t in targets])
        reached = {entry}
        while True:
            added = {int(b, 16) for a, b in edges if int(a, 16) in reached}-reached
            if not added:
                break
            reached |= added
        if reached != starts:
            raise ValueError("unreachable instruction start")
        out.append({"entry_va": key, "file_offset": f"0x{pos:x}", "body_bytes": 42,
                    "body_sha256": sha(body), "native_export_sha256": hashes,
                    "instruction_count": len(ins), "matched_native_instructions": len(ins),
                    "reachable_instruction_starts": len(reached), "edges": edges,
                    "return_sites": [f"{i.address:08x}" for i in ins if i.mnemonic == "ret"],
                    "table_pointer_offset": table_offset,
                    "memory_operands": [[f"{i.address:08x}", i.mnemonic, i.op_str]
                                        for i in ins if "[" in i.op_str]})
    return {"work_unit": "R29-B", "specimen_sha256": PINNED,
            "checkpoint_archive_sha256": manifest["checkpoint_archive_sha256"],
            "export_manifest_sha256": MANIFEST, "preflight_sha256": PREFLIGHT,
            "method": "Capstone 5.0.7 complete PE/native instruction, operand and local CFG comparison",
            "functions": out}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "output"):
        parser.add_argument(name, type=Path)
    a = parser.parse_args()
    a.output.write_text(json.dumps(extract(a.exe, a.exports, a.preflight), indent=2)+"\n", encoding="utf-8", newline="\n")

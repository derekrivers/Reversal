#!/usr/bin/env python3
"""Verify three common unwind targets against the pinned PE and private native export.

The public output contains structural metadata and selected sites, never code bytes.
Requires Capstone 5.0.7 and the ignored specimen and Ghidra export.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import CS_ARCH_X86, CS_MODE_32, CS_OP_IMM

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "aa9c7d6c9c9cd06d5dfe8de02c75ac561737f26cc1fcf36930e1149881ad35fb"
PREFLIGHT = "12d10d6ba68468a8b44f3756f7ac638758fa82523cb7685df16db742548cb93d"
SPAN = {"005a53c0": 1, "00682300": 115, "00944c94": 11}
SITES = {"0068231d", "00682323", "00682335", "00682345", "0068234b", "0068235e",
         "00682372", "00944c98", "00944c9e", "005a53c0"}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def normalize(text: str) -> str:
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    text = text.replace("eax, dword ptr fs:", "eax, fs:")
    text = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0], 16)), text)
    text = re.sub(r"\s+", "", text)
    text = text.replace("+-", "-")
    for old, new in (("jnz", "jne"), ("jz", "je")):
        if text.startswith(old):
            text = new + text[len(old):]
    return text


def mapper(data: bytes):
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

    def read(va: int, length: int) -> bytes:
        rva = va - base
        for _virtual, start, size, raw in sections:
            if start <= rva and rva + length <= start + size:
                return data[raw + rva - start:raw + rva - start + length]
        raise ValueError(f"unmapped PE span {va:08x}+{length}")

    return read


def run(binary: Path, atlas: Path, unwind: Path, exports: Path, preflight: Path, output: Path):
    data = binary.read_bytes()
    assert digest(data) == SPECIMEN
    assert capstone.__version__ == "5.0.7"
    raw_manifest = (exports / "manifest.json").read_bytes()
    assert digest(raw_manifest) == MANIFEST
    manifest = json.loads(raw_manifest)
    assert manifest["specimen_sha256"] == SPECIMEN
    raw_preflight = preflight.read_bytes()
    assert digest(raw_preflight) == PREFLIGHT
    old_rows = json.loads(raw_preflight)["sites"]
    assert {r["address"] for r in old_rows} == set(SPAN)
    assert all(r["function_name"] == "FUN_" + r["address"] and r["instruction_exists"]
               and not r.get("function_comment") for r in old_rows)
    native = manifest["files"]
    inventory = {json.loads(line)["entry"]: json.loads(line)
                 for line in atlas.read_text(encoding="utf-8").splitlines()}
    assert len(inventory) == 9241
    target_counts = Counter(json.loads(line)["direct_target"]
                            for line in unwind.read_text(encoding="utf-8").splitlines())
    assert sum(target_counts.values()) == 3873
    md = capstone.Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    functions = []
    for address, size in SPAN.items():
        row = inventory[address]
        assert row["body_bytes"] == size and row["body_min"] == address
        assert int(row["body_max"], 16) == int(address, 16) + size - 1
        body = mapper(data)(int(address, 16), size)
        instructions = list(md.disasm(body, int(address, 16)))
        assert instructions and sum(i.size for i in instructions) == size
        assert instructions[-1].address + instructions[-1].size == int(address, 16) + size
        assert all(instructions[i].address + instructions[i].size == instructions[i+1].address
                   for i in range(len(instructions)-1))
        asm_name = address + ".asm"
        c_name = address + ".c"
        for name in (asm_name, c_name):
            raw = (exports / name).read_bytes()
            assert len(raw) == native[name]["bytes"] and digest(raw) == native[name]["sha256"]
        asm = (exports / asm_name).read_text(encoding="utf-8-sig")
        exported = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", asm, re.M)]
        assert [a for a, _ in exported] == [i.address for i in instructions]
        differences = [(f"{a:08x}", text, i.mnemonic + " " + i.op_str)
                       for (a, text), i in zip(exported, instructions)
                       if normalize(text) != normalize(i.mnemonic + " " + i.op_str)]
        assert not differences, differences
        calls = [[f"{i.address:08x}", f"{i.operands[0].imm & 0xffffffff:08x}"]
                 for i in instructions if i.mnemonic == "call" and i.operands[0].type == CS_OP_IMM]
        assert sorted({target for _, target in calls}) == row["direct_callees"]
        sites = [{"address": f"{i.address:08x}", "mnemonic": i.mnemonic,
                  "operands": i.op_str} for i in instructions if f"{i.address:08x}" in SITES]
        functions.append({"address": address, "body_bytes": size,
                          "body_sha256": digest(body), "instructions": len(instructions),
                          "native_asm_sha256": native[asm_name]["sha256"],
                          "native_c_sha256": native[c_name]["sha256"],
                          "direct_calls": calls, "unwind_direct_entries": target_counts[address],
                          "selected_sites": sites})
    assert sum(f["unwind_direct_entries"] for f in functions) == 3410
    out = {"specimen_sha256": SPECIMEN,
           "scope": "Complete local-body instruction and native-export comparison for three common unwind targets; transitive effects and unwind parent frames unresolved.",
           "atlas_sha256": digest(atlas.read_bytes()),
           "unwind_registry_sha256": digest(unwind.read_bytes()),
           "functions": functions}
    output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": "passed", "functions": len(functions),
                      "direct_unwind_entries": 3410, "output_sha256": digest(output.read_bytes())}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--atlas", type=Path, required=True)
    p.add_argument("--unwind", type=Path, required=True)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    run(a.binary, a.atlas, a.unwind, a.exports, a.preflight, a.output)

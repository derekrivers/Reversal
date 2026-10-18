#!/usr/bin/env python3
"""Classify Ghidra's Unwind@ entries from the pinned PE, without exporting code."""
from __future__ import annotations

# Integrity assertions must remain active before reading or writing evidence.
if not __debug__:
    raise SystemExit("Integrity checks require assertions; rerun without Python optimization (-O/-OO).")

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

import capstone
from capstone import x86

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
EXPECTED_ATLAS = 9241
EXPECTED_UNWIND = 3873
EXPECTED_TEMPLATES = 20


def pe_mapper(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x10B
    base = struct.unpack_from("<I", data, optional + 28)[0]
    sections = [struct.unpack_from("<IIII", data, optional + optional_size + 40 * i + 8)
                for i in range(count)]

    def get(va: int, length: int) -> bytes:
        rva = va - base
        for _virtual_size, virtual_address, raw_size, raw_address in sections:
            if virtual_address <= rva and rva + length <= virtual_address + raw_size:
                start = raw_address + rva - virtual_address
                assert start + length <= len(data)
                return data[start:start + length]
        raise ValueError(f"Unmapped PE span {va:08x}+{length}")

    return get


def operand_shape(ins, operand):
    if operand.type == x86.X86_OP_REG:
        return "reg:" + str(ins.reg_name(operand.reg))
    if operand.type == x86.X86_OP_MEM:
        mem = operand.mem
        return (f"mem{operand.size * 8}:" + str(ins.reg_name(mem.base)) + ":"
                + str(ins.reg_name(mem.index)) + f":{mem.scale}")
    if operand.type == x86.X86_OP_IMM:
        return "imm"
    raise ValueError(f"Unsupported operand at {ins.address:08x}")


def scan(binary: Path, atlas: Path):
    data = binary.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SPECIMEN
    get = pe_mapper(data)
    functions = [json.loads(line) for line in atlas.read_text(encoding="utf-8").splitlines()]
    assert len(functions) == EXPECTED_ATLAS
    unwind = [row for row in functions if row["name"].startswith("Unwind@")]
    assert len(unwind) == EXPECTED_UNWIND
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    rows = []
    shapes = Counter()
    for f in unwind:
        entry = int(f["entry"], 16)
        size = f["body_bytes"]
        assert f["body_min"] == f["entry"]
        assert int(f["body_max"], 16) - entry + 1 == size
        assert not f["direct_source_units"] and not f["unresolved_indirect_call_sites"]
        assert len(f["direct_callees"]) == 1
        body = get(entry, size)
        instructions = list(decoder.disasm(body, entry))
        assert instructions and instructions[-1].address + instructions[-1].size == entry + size
        assert sum(ins.size for ins in instructions) == size
        shape = tuple((ins.mnemonic, tuple(operand_shape(ins, op) for op in ins.operands))
                      for ins in instructions)
        key = (size, shape)
        shapes[key] += 1
        direct = []
        branches = []
        frame_displacements = []
        literals = []
        for ins in instructions:
            for op in ins.operands:
                if op.type == x86.X86_OP_MEM and ins.reg_name(op.mem.base) == "ebp":
                    frame_displacements.append(op.mem.disp)
                if op.type == x86.X86_OP_IMM:
                    if ins.mnemonic in ("call", "jmp", "je"):
                        branches.append([ins.mnemonic, f"{op.imm & 0xFFFFFFFF:08x}"])
                        if ins.mnemonic in ("call", "jmp"):
                            direct.append(f"{op.imm & 0xFFFFFFFF:08x}")
                    else:
                        literals.append(op.imm)
        assert set(direct) == set(f["direct_callees"]), f["entry"]
        assert len(direct) == 1, f["entry"]
        rows.append({"entry": f["entry"], "body_bytes": size, "shape": key,
                     "body_sha256": hashlib.sha256(body).hexdigest(),
                     "direct_target": direct[0], "branches": branches,
                     "ebp_displacements": frame_displacements, "literals": literals})
    assert len(shapes) == EXPECTED_TEMPLATES
    ordered = sorted(shapes, key=lambda key: (-shapes[key], json.dumps(key)))
    ids = {key: f"U{i:02d}" for i, key in enumerate(ordered, 1)}
    templates = [{"id": ids[key], "count": shapes[key], "body_bytes": key[0],
                  "shape": [[mnemonic, list(ops)] for mnemonic, ops in key[1]]}
                 for key in ordered]
    for row in rows:
        row["template"] = ids[row["shape"]]
        del row["shape"]
    rows.sort(key=lambda row: row["entry"])
    summary = {
        "specimen_sha256": SPECIMEN,
        "atlas_sha256": hashlib.sha256(atlas.read_bytes()).hexdigest(),
        "population": "Ghidra-inferred entries named Unwind@ in the investigation-08 structural atlas",
        "scope": "Complete local instruction shapes and parameters; direct target effects, parent frame validity and runtime invocation are unresolved.",
        "counts": {"atlas_internal_functions": len(functions), "unwind_entries": len(rows),
                   "templates": len(templates), "direct_targets": len({row["direct_target"] for row in rows}),
                   "decoded_instructions": sum(item["count"] * len(item["shape"]) for item in templates),
                   "call_entries": sum(any(branch[0] == "call" for branch in row["branches"]) for row in rows),
                   "tail_jump_entries": sum(any(branch[0] == "jmp" for branch in row["branches"]) for row in rows),
                   "original_bytes_redistributed": 0},
        "templates": templates,
    }
    return summary, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--atlas", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--rows", type=Path, required=True)
    args = parser.parse_args()
    summary, rows = scan(args.binary, args.atlas)
    args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n")
    args.rows.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
                         encoding="utf-8", newline="\n")
    print(json.dumps(summary["counts"]))


if __name__ == "__main__":
    main()

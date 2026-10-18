#!/usr/bin/env python3
"""Classify 30-byte conditional receiver-release wrappers from the pinned PE.

Requires Capstone 5.0.7. Publishes compact structure and hashes, not code bytes.
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
MANIFEST = "afcbab808d685d44e4a93ef4988d06f15072458a2b8b5a67b32baea105a27a6c"
SAMPLES = ("00401200", "00639de0", "0092ff60")
MNEMONICS = ("push", "mov", "call", "test", "je", "push", "call", "add", "mov", "pop", "ret")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pe_reader(data: bytes):
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe+4] == b"PE\0\0"
    assert struct.unpack_from("<H", data, pe+4)[0] == 0x14c
    count = struct.unpack_from("<H", data, pe+6)[0]
    optional_size = struct.unpack_from("<H", data, pe+20)[0]
    optional = pe+24
    assert struct.unpack_from("<H", data, optional)[0] == 0x10b
    base = struct.unpack_from("<I", data, optional+28)[0]
    sections = [struct.unpack_from("<IIII", data, optional+optional_size+40*i+8)
                for i in range(count)]

    def read(va: int, length: int) -> bytes:
        rva = va-base
        for _virtual, start, size, raw in sections:
            if start <= rva and rva+length <= start+size:
                return data[raw+rva-start:raw+rva-start+length]
        raise ValueError(f"unmapped PE span {va:08x}+{length}")

    return read


def matches(ins, entry: int) -> bool:
    if len(ins) != 11 or tuple(i.mnemonic for i in ins) != MNEMONICS:
        return False
    expected_offsets = (0,1,3,8,13,15,16,21,24,26,27)
    if tuple(i.address-entry for i in ins) != expected_offsets:
        return False
    fixed = {0:"esi", 1:"esi, ecx", 3:"byte ptr [esp + 8], 1", 5:"esi",
             7:"esp, 4", 8:"eax, esi", 9:"esi", 10:"4"}
    if any(ins[i].op_str != value for i,value in fixed.items()):
        return False
    if ins[2].operands[0].type != CS_OP_IMM or ins[6].operands[0].type != CS_OP_IMM:
        return False
    return (ins[4].operands[0].imm == entry+24 and
            ins[6].operands[0].imm == 0x944c94)


def normalize(text: str) -> str:
    text = text.lower()
    text = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0],16)), text)
    text = re.sub(r"\s+", "", text)
    return text.replace("jz", "je", 1) if text.startswith("jz") else text


def run(binary: Path, atlas: Path, exports: Path, summary: Path, rows_path: Path):
    data = binary.read_bytes()
    assert digest(data) == SPECIMEN and capstone.__version__ == "5.0.7"
    raw_manifest = (exports/"manifest.json").read_bytes()
    assert digest(raw_manifest) == MANIFEST
    manifest = json.loads(raw_manifest)
    assert manifest["specimen_sha256"] == SPECIMEN
    inventory = [json.loads(line) for line in atlas.read_text(encoding="utf-8").splitlines()]
    assert len(inventory) == 9241
    candidates = [f for f in inventory if not f["name"].startswith("Unwind@") and f["body_bytes"] == 30]
    assert len(candidates) == 197
    read = pe_reader(data)
    md = capstone.Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    rows, excluded, sample_rows = [], [], {}
    for f in candidates:
        address = f["entry"]
        entry = int(address, 16)
        assert f["body_min"] == address and int(f["body_max"],16) == entry+29
        body = read(entry, 30)
        ins = list(md.disasm(body, entry))
        assert ins and sum(i.size for i in ins) == 30 and ins[-1].address+ins[-1].size == entry+30
        assert all(ins[i].address+ins[i].size == ins[i+1].address for i in range(len(ins)-1))
        if not matches(ins, entry):
            excluded.append(address)
            continue
        direct = f"{ins[2].operands[0].imm & 0xffffffff:08x}"
        assert sorted(f["direct_callees"]) == sorted((direct,"00944c94"))
        assert f["call_instruction_count"] == 2 and not f["unresolved_indirect_call_sites"]
        rows.append({"entry":address,"body_sha256":digest(body),"destructor_target":direct,
                     "release_wrapper":"00944c94","flag_offset":4,"flag_mask":1,
                     "normal_return":"receiver EAX; RET 4"})
        if address in SAMPLES:
            sample_rows[address] = ins
    assert len(rows) == 192 and len(excluded) == 5
    assert len({r["entry"] for r in rows}) == 192
    assert len({r["destructor_target"] for r in rows}) == 192
    assert set(sample_rows) == set(SAMPLES)
    for address, ins in sample_rows.items():
        name = address+".asm"
        raw = (exports/name).read_bytes()
        spec = manifest["files"][name]
        assert len(raw) == spec["bytes"] and digest(raw) == spec["sha256"]
        c_name = address+".c"
        c_raw = (exports/c_name).read_bytes()
        c_spec = manifest["files"][c_name]
        assert len(c_raw) == c_spec["bytes"] and digest(c_raw) == c_spec["sha256"]
        exported = [(int(m[1],16),m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$",raw.decode("utf-8-sig"),re.M)]
        assert [a for a,_ in exported] == [i.address for i in ins]
        assert all(normalize(text) == normalize(i.mnemonic+" "+i.op_str)
                   for (_,text),i in zip(exported,ins))
    rows.sort(key=lambda row:row["entry"])
    rows_path.write_text("".join(json.dumps(row,separators=(",",":"))+"\n" for row in rows),
                         encoding="utf-8",newline="\n")
    summary_data = {
        "specimen_sha256":SPECIMEN,
        "scope":"Complete local wrapper shape for 192 inferred functions; callee effects, parent object types and runtime invocation unresolved.",
        "atlas_sha256":digest(atlas.read_bytes()),
        "counts":{"atlas_internal_functions":len(inventory),"non_unwind_30_byte_candidates":len(candidates),
                  "verified_conditional_release_wrappers":len(rows),"other_30_byte_functions":len(excluded),
                  "distinct_first_callees":len({r["destructor_target"] for r in rows}),
                  "native_sample_exports":len(sample_rows)},
        "other_30_byte_entries":sorted(excluded),
        "native_sample_addresses":list(SAMPLES),
        "registry_sha256":digest(rows_path.read_bytes())
    }
    summary.write_text(json.dumps(summary_data,indent=2)+"\n",encoding="utf-8",newline="\n")
    print(json.dumps({"status":"passed","wrappers":len(rows),"excluded":len(excluded),
                      "summary_sha256":digest(summary.read_bytes()),
                      "registry_sha256":digest(rows_path.read_bytes())}))


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary",type=Path,required=True)
    p.add_argument("--atlas",type=Path,required=True)
    p.add_argument("--exports",type=Path,required=True)
    p.add_argument("--summary",type=Path,required=True)
    p.add_argument("--rows",type=Path,required=True)
    a=p.parse_args()
    run(a.binary,a.atlas,a.exports,a.summary,a.rows)

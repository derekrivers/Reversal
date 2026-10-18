#!/usr/bin/env python3
"""Reproduce selected sites from pinned PE32 instructions; no game execution.

Requires capstone==5.0.7. All owned instructions are decoded and compared with
hash-pinned private Ghidra exports before a compact selection is emitted.
Usage: python db-wrapper-family-14-extract.py SPECIMEN EXPORT_DIR OUTPUT
Original bytes, complete listings and decompiled source are never emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "233ec2078dc3eacf0d1b83a3d093028caf57c634329bacce4af4ea2efb5c7f86"
# Independently reviewed boundaries and contracts. Sizes concern the direct read
# branch only; descriptor==1 delegates do not contain a fixed-size block read.
ROWS = [
    (0x54d8a0,241,0x38,[1,2],None),
    (0x54da00,235,0x4e,[1],None),
    (0x54db50,314,0x245,[1,2],0x54dc90),
    (0x54e630,237,0x6e,[2],None),
    (0x54e780,241,0x9d,[1],None),
    (0x54e880,283,0x44,[1,2],0x54e9a0),
    (0x54f030,283,0x46,[1,2],0x54f150),
    (0x54fc10,235,0x34,[1],None),
    (0x54fd60,235,0x11,[1],None),
    (0x54feb0,283,0x6b,[1,2],0x54ffd0),
    (0x550230,235,0x1a,[1],None),
    (0x550380,237,0x65,[2],None),
    (0x5504d0,235,0x3a,[1],None),
    (0x5505c0,235,0x2b,[1],None),
    (0x550710,235,0x3a,[1],None),
    (0x550860,235,0x3c,[1],None),
]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def normalize(text):
    text = text.lower()
    for old, new in [("jz","je"),("jnz","jne"),("setz","sete")]:
        text = re.sub(r"\b"+old+r"\b",new,text)
    text = re.sub(r"\b0x[0-9a-f]+\b",lambda m:str(int(m[0],16)),text)
    return re.sub(r"\s+","",text)


def extract(specimen, exports):
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires capstone==5.0.7")
    data = specimen.read_bytes()
    if digest(data) != PINNED:
        raise ValueError("specimen mismatch")
    manifest_raw = (exports / "EXPORT-MANIFEST.json").read_bytes()
    if digest(manifest_raw) != MANIFEST:
        raise ValueError("native export manifest mismatch")
    manifest = json.loads(manifest_raw)
    if manifest["specimen_sha256"] != PINNED:
        raise ValueError("native specimen mismatch")
    files = {row["name"]:row for row in manifest["files"]}
    pe = struct.unpack_from("<I",data,0x3c)[0]
    opt = pe+24
    if data[:2] != b"MZ" or data[pe:pe+4] != b"PE\0\0" or struct.unpack_from("<H",data,opt)[0] != 0x10b:
        raise ValueError("not PE32")
    base = struct.unpack_from("<I",data,opt+28)[0]
    count = struct.unpack_from("<H",data,pe+6)[0]
    opt_size = struct.unpack_from("<H",data,pe+20)[0]
    sections = [struct.unpack_from("<8sIIII",data,opt+opt_size+40*i) for i in range(count)]

    def offset(va):
        for _, _, rva, raw_size, raw_offset in sections:
            delta = va-base-rva
            if 0 <= delta < raw_size:
                return raw_offset+delta
        raise ValueError(f"VA {va:08x} is not file-backed")

    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    md.detail = True

    def decode(va, size):
        raw = data[offset(va):offset(va)+size]
        ins = list(md.disasm(raw,va))
        if sum(i.size for i in ins) != size:
            raise ValueError(f"incomplete decode at {va:08x}")
        return raw, ins

    functions = []
    for start, size, width, guards, delegate in ROWS:
        entry = f"{start:08x}"
        raw, ins = decode(start,size)
        native_digests = {}
        for suffix in ["asm","c","refs"]:
            name = entry+"."+suffix
            exported = (exports/name).read_bytes()
            if digest(exported) != files[name]["sha256"] or len(exported) != files[name]["bytes"]:
                raise ValueError(f"native file mismatch: {name}")
            native_digests[suffix] = digest(exported)
        native = {}
        for line in (exports/(entry+".asm")).read_text().splitlines():
            address, text = line.split(None,1)
            native[int(address,16)] = normalize(text)
        own = {i.address:normalize(i.mnemonic+" "+i.op_str) for i in ins}
        if own != native:
            mismatch = [f"{va:08x}" for va in set(own)|set(native) if own.get(va) != native.get(va)]
            raise ValueError(f"native instruction mismatch: {entry} {mismatch}")
        calls = [i for i in ins if i.mnemonic == "call"]
        reads = [i for i in calls if i.operands[0].imm in [0x932c30,0x945bfe]]
        if len(reads) != 2:
            raise ValueError("read pair missing")
        # Confirm the actual four pushes and literal width independently per body.
        for read in reads:
            index = ins.index(read)
            pushes = ins[index-4:index]
            if [i.mnemonic for i in pushes] != ["push"]*4 or pushes[1].op_str != "esi" or pushes[2].operands[0].imm != width:
                raise ValueError(f"read marshalling mismatch: {entry}")
        # Select evidence by semantic role after complete instruction comparison.
        # Diagnostics are shared; retain only their per-body constant/state/exit.
        selected = {}
        first_diag = next(i.address for i in calls if i.operands[0].imm == 0x944cff)
        exit_call = next(i.address for i in calls if i.operands[0].imm == 0x945934)
        for index, i in enumerate(ins):
            keep = i.address in [start,start+11,start+14]
            if not first_diag <= i.address < exit_call:
                if i.mnemonic in ["test","cmp","dec","sub","je","jle","jg","jbe","jne","sete"]:
                    keep = i.op_str not in ["esp, 0x200"]
            if i.mnemonic == "push" and i.operands[0].type == capstone.x86.X86_OP_IMM:
                keep |= i.operands[0].imm == width and any(0 < r.address-i.address < 12 for r in reads)
                keep |= index+3 < len(ins) and ins[index+3].mnemonic == "call" and ins[index+3].operands[0].imm == 0x90d130
            if i.mnemonic == "mov" and "[0xb67a34]" in i.op_str:
                keep = True
            if i.mnemonic == "mov" and index+1 < len(ins) and ins[index+1].mnemonic == "test" and "[esp + " in i.op_str:
                keep = True
            if i.mnemonic == "xor" and index+1 < len(ins) and ins[index+1].mnemonic == "cmp":
                keep = True
            if i.mnemonic == "call" and i.operands[0].imm in [0x945934,0x932c30,0x945bfe,delegate]:
                keep = True
            if delegate and any(c.operands[0].imm == delegate and 0 < c.address-i.address <= 4 for c in calls):
                keep = True
            if start == 0x54db50 and 0x54dc35 <= i.address <= 0x54dc58:
                keep = True
            if keep:
                selected[f"{i.address:08x}"] = (i.mnemonic+" "+i.op_str).strip()
        refs = []
        for line in (exports/(entry+".refs")).read_text().splitlines():
            address, kind = line.split(None,1)
            refs.append({"site_va":address,"kind":kind})
        functions.append({"entry_va":entry,"file_offset":f"{offset(start):08x}",
                          "span_bytes":size,"last_instruction_va":f"{ins[-1].address:08x}",
                          "span_sha256":digest(raw),"instruction_count":len(ins),
                          "native_comparison":{"matched_instructions":len(ins),"file_sha256":native_digests},
                          "direct_callees":sorted({f"{i.operands[0].imm:08x}" for i in calls}),
                          "incoming_native_refs":refs,"selected_instructions":selected})
    # Existing R09 direction/exit boundaries, re-decoded from this pinned PE.
    context = {}
    for start in [0x932cc6,0x932df7,0x945c5c,0x945cb2,0x945ce1,0x9459e7]:
        i = next(md.disasm(data[offset(start):offset(start)+15],start))
        context[f"{i.address:08x}"] = (i.mnemonic+" "+i.op_str).strip()
    helper_boundaries = {}
    # Only entry, first transfer and observed exit boundary sites are selected.
    # These do not establish complete helper layouts or total disk record widths.
    for start, prefix_end, exits, picks in [
        (0x54dc90,0x54dcfc,(0x54e5ba,0x54e5cd),[0x54dc91,0x54dc98,0x54dcb5,0x54dcc8,0x54dcca,0x54dcd0,0x54dceb,0x54dcf3,0x54e5bd,0x54e5c8]),
        (0x54e9a0,0x54e9fe,(0x54efbe,0x54efcf),[0x54e9a0,0x54e9aa,0x54e9ba,0x54e9ca,0x54e9cc,0x54e9d2,0x54e9ed,0x54e9f5,0x54efc1,0x54efcb]),
        (0x54f150,0x54f1b1,(0x54fb9b,0x54fbac),[0x54f150,0x54f15a,0x54f16a,0x54f17c,0x54f181,0x54f187,0x54f1a0,0x54f1a8,0x54fb9e,0x54fba8]),
        (0x54ffd0,0x55001a,(0x5501bd,0x5501ce),[0x54ffd0,0x54ffda,0x54fff2,0x54fff4,0x54fff6,0x54fffe,0x550009,0x550011,0x5501c0,0x5501ca]),
    ]:
        decoded = []
        spans = []
        for lo, hi in [(start,prefix_end),exits]:
            raw, instructions = decode(lo,hi-lo)
            decoded.extend(instructions)
            spans.append({"start_va":f"{lo:08x}","span_bytes":hi-lo,"sha256":digest(raw)})
        selected = {f"{i.address:08x}":(i.mnemonic+" "+i.op_str).strip() for i in decoded if i.address in picks}
        if len(selected) != len(picks):
            raise ValueError("helper boundary site missing")
        helper_boundaries[f"{start:08x}"] = {"scope":"immediate dependency boundaries only; no native whole-body comparison",
                                               "spans":spans,"selected_instructions":selected}
    return {"specimen_sha256":PINNED,"native_manifest_sha256":MANIFEST,
            "method":"static PE32 x86 decode; capstone==5.0.7; complete owned-body native comparison; no execution",
            "address_space":"virtual addresses unless file_offset is explicit",
            "functions":functions,"read_and_termination_dependency_sites":context,
            "delegate_dependency_boundaries":helper_boundaries}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen",type=Path)
    parser.add_argument("exports",type=Path)
    parser.add_argument("output",type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen,args.exports),indent=2)+"\n",encoding="utf-8",newline="\n")

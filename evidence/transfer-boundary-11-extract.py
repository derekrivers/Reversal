#!/usr/bin/env python3
"""Regenerate compact static evidence; capstone==5.0.7, no execution.

The executable and optional Ghidra exports remain read-only. Output contains
selected sites, operand widths, hashes and comparison receipts; no code bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
ENTRY, END = 0x8bba30, 0x8bbe1a
SITES = [
    0x8bba4f,0x8bba51,0x8bba56,0x8bba5b,0x8bba60,0x8bba63,0x8bba6a,
    0x8bba71,0x8bba7e,0x8bba83,0x8bba91,0x8bba96,0x8bbaa4,
    0x8bbabf,0x8bbac4,0x8bbaed,0x8bbaef,0x8bbb16,0x8bbb2c,0x8bbb36,
    0x8bbb40,0x8bbb4c,0x8bbb52,0x8bbb9a,0x8bbba2,0x8bbc36,
    0x8bbc41,0x8bbc4f,0x8bbc5e,0x8bbc64,0x8bbc69,0x8bbc6e,0x8bbc71,
    0x8bbc7b,0x8bbc81,0x8bbca3,0x8bbcaf,0x8bbcba,0x8bbcc0,0x8bbcc3,
    0x8bbccd,0x8bbcd3,0x8bbd01,0x8bbd0d,0x8bbd14,0x8bbd1e,
    0x8bbd22,0x8bbd23,0x8bbd25,0x8bbd2a,0x8bbd2c,0x8bbd32,0x8bbd37,
    0x8bbd4d,0x8bbd4f,0x8bbd50,0x8bbd52,0x8bbd65,0x8bbd6b,
    0x8bbd9d,0x8bbda4,0x8bbded,0x8bbdf5,0x8bbdf7,0x8bbdf9,
    0x8bbe05,0x8bbe18,
]
# Dependencies are selected boundary/context sites, not whole-function contracts.
CONTEXT = [
    (0x54a110,0x54a124),(0x68d020,0x68d030),
    (0x829895,0x8298cf),(0x82c834,0x82c86c),
    (0x82876e,0x82876e),(0x82b9bd,0x82b9bd),(0x82bb10,0x82bb21),
    (0x9463dd,0x9463f6),(0x946416,0x946416),
    (0x945505,0x94550c),(0x94556c,0x945575),(0x945597,0x94559d),
    (0x8bc04d,0x8bc081),(0x8bc10e,0x8bc11e),
    (0x8bc1c0,0x8bc1c2),(0x8bc7a1,0x8bc7de),
    (0x8bd3e9,0x8bd413),(0x8bd4a7,0x8bd4a9),
]


def normalize(text):
    text = text.lower()
    for old,new in [("jz","je"),("jnz","jne")]:
        text = re.sub(r"\b"+old+r"\b",new,text)
    text = re.sub(r"\b0x[0-9a-f]+\b",lambda m:str(int(m[0],16)),text)
    text = re.sub(r"\s+","",text).replace("dwordptr","")
    return re.sub(r"\*1(?![0-9])","",text).replace("+0]","]")


def extract(specimen,native_dir):
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires capstone==5.0.7")
    data = specimen.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED:
        raise ValueError("specimen SHA-256 mismatch")
    pe = struct.unpack_from("<I",data,0x3c)[0]
    opt = pe+24
    if data[:2] != b"MZ" or data[pe:pe+4] != b"PE\0\0" or struct.unpack_from("<H",data,opt)[0] != 0x10b:
        raise ValueError("not PE32")
    base = struct.unpack_from("<I",data,opt+28)[0]
    count = struct.unpack_from("<H",data,pe+6)[0]
    opt_size = struct.unpack_from("<H",data,pe+20)[0]
    sections = [struct.unpack_from("<8sIIII",data,opt+opt_size+40*i) for i in range(count)]

    def offset(va):
        for _,_,rva,raw_size,raw_offset in sections:
            delta = va-base-rva
            if 0 <= delta < raw_size:
                return raw_offset+delta
        raise ValueError(f"VA {va:08x} not file-backed")

    def ascii_at(va):
        return data[offset(va):offset(va)+256].split(b"\0",1)[0].decode("ascii")

    imports = {}
    import_rva = struct.unpack_from("<I",data,opt+104)[0]
    descriptor = offset(base+import_rva)
    while True:
        lookup,stamp,chain,name,iat = struct.unpack_from("<IIIII",data,descriptor)
        if not any((lookup,stamp,chain,name,iat)):
            break
        index = 0
        while True:
            thunk = struct.unpack_from("<I",data,offset(base+(lookup or iat)+4*index))[0]
            if not thunk:
                break
            address = base+iat+4*index
            if address in (0x9670f8,0x967100,0x967154):
                imports[f"{address:08x}"] = {"dll":ascii_at(base+name),
                    "name":f"ordinal:{thunk&0xffff}" if thunk&0x80000000 else ascii_at(base+thunk+2)}
            index += 1
        descriptor += 20

    md = Cs(CS_ARCH_X86,CS_MODE_32)
    md.detail = True

    def decode(start,end):
        rows = list(md.disasm(data[offset(start):offset(end)+1],start))
        if not rows or rows[-1].address+rows[-1].size != end+1:
            raise ValueError(f"decode does not exactly cover {start:08x}..{end:08x}")
        return rows

    owned = decode(ENTRY,END)
    instructions = {f"{i.address:08x}":(i.mnemonic+" "+i.op_str).strip() for i in owned}
    selected = {f"{a:08x}":instructions[f"{a:08x}"] for a in SITES}
    writes = []
    for i in owned:
        if i.mnemonic == "mov" and i.operands[0].type == capstone.x86.X86_OP_MEM:
            dst = i.operands[0]
            if dst.mem.base == capstone.x86.X86_REG_ESI:
                writes.append({"site":f"{i.address:08x}","receiver_offset":f"{dst.mem.disp:x}",
                               "width_bytes":dst.size,"source":i.op_str.split(", ",1)[1]})
    calls = [{"site":f"{i.address:08x}","target":i.op_str} for i in owned if i.mnemonic == "call"]
    context = {}
    for start,last in CONTEXT:
        # Decode through the final selected instruction without retaining extras.
        rows = list(md.disasm(data[offset(start):offset(last)+16],start))
        kept = [i for i in rows if i.address <= last]
        if not kept or kept[-1].address != last:
            raise ValueError(f"context endpoint is not an instruction: {last:08x}")
        context.update({f"{i.address:08x}":(i.mnemonic+" "+i.op_str).strip() for i in kept})
    receipt = None
    if native_dir:
        asm = native_dir/"008bba30.asm"
        listing = {l[:8]:l[10:] for l in asm.read_text(encoding="utf-8").splitlines() if l}
        if {a:normalize(t) for a,t in listing.items()} != {a:normalize(t) for a,t in instructions.items()}:
            raise ValueError("owned native listing disagrees with PE decode")
        callee_listing = {l[:8]:l[10:] for l in (native_dir/"008bc020.asm").read_text(encoding="utf-8").splitlines() if l}
        callee_sites = {a:t for a,t in context.items() if 0x8bc020 <= int(a,16) <= 0x8bd4ad}
        for a,t in callee_sites.items():
            if normalize(callee_listing[a]) != normalize(t):
                raise ValueError(f"callee boundary disagrees at {a}")
        refs = [l.split()[0] for l in (native_dir/"008bba30.refs").read_text().splitlines() if l]
        if refs != ["008298b8","0082c854"]:
            raise ValueError("incoming refs changed")
        receipt = {"owned_asm_sha256":hashlib.sha256(asm.read_bytes()).hexdigest(),
                   "owned_all_instructions_match":True,"incoming_direct_call_sites":refs,
                   "callee_selected_instruction_matches":len(callee_sites),
                   "normalization":"mnemonic aliases, numeric spelling, whitespace, redundant DWORD PTR/scale1/+0"}
        manifest_path = native_dir/"EXPORT-MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        relevant = [r for r in manifest if r["name"].startswith(("008bba30.","008bc020."))]
        for row in relevant:
            payload = (native_dir/row["name"]).read_bytes()
            if len(payload) != row["bytes"] or hashlib.sha256(payload).hexdigest() != row["sha256"]:
                raise ValueError("native export manifest mismatch")
        if len(relevant) != 6:
            raise ValueError("expected six relevant exports")
        receipt["exports_verified_against_coordinator_manifest"] = relevant
    source_path = data[offset(0xa8d514):offset(0xa8d514)+256].split(b"\0",1)[0].decode("ascii")
    assert len(calls) == 29
    assert instructions["008bbe18"] == "ret 4"
    assert max(int(w["receiver_offset"],16)+w["width_bytes"] for w in writes) == 0x94a
    assert {w["width_bytes"] for w in writes} == {1,4}
    # Validate the explicit caller register definitions; calls rely on the
    # observed x86 nonvolatile-register convention, not audited callee bodies.
    for start,end,register in [(0x82876e,0x8298bc,capstone.x86.X86_REG_EBP),
                               (0x82bb21,0x82c858,capstone.x86.X86_REG_EDI)]:
        rows = decode(start,end)
        writers = [i.address for i in rows if register in i.regs_access()[1]]
        if writers != [start]:
            raise ValueError(f"caller register clobbered after {start:08x}: {writers}")
    assert context["008298b8"] == context["0082c854"] == "call 0x8bba30"
    return {"sha256":digest,"baseline_commit":"2c6bb83f13c92a3f9d2309e71e5e77aac7715383",
            "method":"static PE32 x86 Capstone 5.0.7 decode; no execution or numerical oracle",
            "address_space":"virtual addresses unless file_offset is explicit",
            "owned_function":{"entry_va":f"{ENTRY:08x}","last_body_byte_va":f"{END:08x}",
                              "file_offset":f"{offset(ENTRY):08x}","span_bytes":END-ENTRY+1,
                              "span_sha256":hashlib.sha256(data[offset(ENTRY):offset(END)+1]).hexdigest(),
                              "instruction_count":len(owned)},
            "selected_instructions":selected,"direct_receiver_writes":writes,
            "call_sites":calls,"dependency_caller_sites":context,
            "caller_nonvolatile_register_definition_checks":"EBP last written at0082876e; EDI last written at0082bb21 (alternate0082bb10 loads same frame slot); no later explicit writes before calls",
            "source_path_anchor":{"00a8d514":source_path},"import_slots":imports,
            "native_corroboration":receipt}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--native-dir",type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen,args.native_dir),indent=2)+"\n",encoding="utf-8")

#!/usr/bin/env python3
"""Read-only static PE evidence; requires capstone==5.0.7. No game execution.

Use: python contract-boundary-12-extract.py SPECIMEN OUTPUT --native-dir EXPORTS
Private original bytes and bulk exports are never copied into the output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
BODIES = [(0x4c7560, 0x4c7944), (0x4c79a0, 0x4c7abd)]
SELECTED = [
    0x4c757c,0x4c7580,0x4c7587,0x4c758c,0x4c759a,0x4c759d,0x4c75a0,
    0x4c75a4,0x4c75ac,0x4c75ae,0x4c75b0,0x4c7640,0x4c7645,0x4c7648,
    0x4c764d,0x4c7653,0x4c7659,0x4c7666,0x4c7671,0x4c7675,0x4c7678,
    0x4c767c,0x4c7681,0x4c7688,0x4c768b,0x4c7690,
    0x4c76b2,0x4c76b7,0x4c76bb,0x4c76c8,0x4c76d1,0x4c76d8,
    0x4c7721,0x4c7732,0x4c7736,0x4c7739,0x4c773d,0x4c774a,
    0x4c774d,0x4c774f,0x4c7753,0x4c7783,0x4c778f,0x4c7794,
    0x4c7797,0x4c7799,0x4c779d,0x4c77a0,0x4c77a5,0x4c77be,
    0x4c77c0,0x4c77c5,0x4c77e0,0x4c77e5,0x4c77e9,0x4c77f2,
    0x4c77f7,0x4c7802,0x4c780c,0x4c7817,0x4c7832,0x4c7837,
    0x4c783d,0x4c7864,0x4c7866,0x4c786c,0x4c786f,0x4c7878,
    0x4c787a,0x4c788e,0x4c789b,0x4c78a7,0x4c78ac,0x4c78ae,
    0x4c78b1,0x4c78b3,0x4c78b5,0x4c78bc,0x4c78c3,0x4c78c5,
    0x4c78d0,0x4c78d8,0x4c78da,0x4c78dc,0x4c78ed,0x4c78f0,
    0x4c78f2,0x4c78f4,0x4c78f8,0x4c7900,0x4c7902,0x4c7904,
    0x4c7915,0x4c7916,0x4c7919,0x4c791c,0x4c7926,0x4c7944,
    0x4c79a0,0x4c79aa,0x4c79ad,0x4c79af,0x4c79b1,0x4c79b4,
    0x4c79ba,0x4c79bc,0x4c79bf,0x4c79c6,0x4c79c9,0x4c79cb,
    0x4c79cd,0x4c79d0,0x4c79d3,0x4c79d5,0x4c79dd,0x4c79e4,
    0x4c79e7,0x4c79e9,0x4c79ec,0x4c79f1,0x4c7a02,0x4c7a0a,
    0x4c7a0c,0x4c7a0e,0x4c7a9b,0x4c7aa5,0x4c7aa8,0x4c7aab,
    0x4c7aac,0x4c7ab1,0x4c7abb,
]
# Only immediate caller/callee evidence, not contracts for their full bodies.
CONTEXT = [(0x82876e,0x82876e),(0x8297ca,0x829809),(0x4c7950,0x4c795c),
           (0x417c1d,0x417c3c),(0x417c40,0x417c40),
           (0x549ef0,0x549efd),(0x549f54,0x549f54),
           (0x54a10b,0x54a10b),(0x85e97b,0x85e987),
           (0x85f787,0x85f79c)]


def normalize(text):
    text = text.lower()
    for old, new in [("jz","je"),("jnz","jne"),("jc","jb")]:
        text = re.sub(r"\b"+old+r"\b",new,text)
    text = re.sub(r"\b0x[0-9a-f]+\b",lambda m:str(int(m[0],16)),text)
    text = re.sub(r"\s+","",text).replace("dwordptr","")
    text = re.sub(r"\*1(?![0-9])","",text).replace("+0]","]")
    return text.replace("+-","-")


def extract(specimen, native_dir):
    assert capstone.__version__ == "5.0.7"
    data = specimen.read_bytes()
    assert hashlib.sha256(data).hexdigest() == PINNED, "specimen mismatch"
    pe = struct.unpack_from("<I",data,0x3c)[0]
    opt = pe+24
    assert data[:2] == b"MZ" and data[pe:pe+4] == b"PE\0\0"
    assert struct.unpack_from("<H",data,opt)[0] == 0x10b
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

    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32)
    md.detail = True

    def decode(start,end):
        rows = list(md.disasm(data[offset(start):offset(end)+1],start))
        assert rows and rows[-1].address+rows[-1].size == end+1
        return rows

    def text(i):
        return (i.mnemonic+" "+i.op_str).strip()

    functions, instructions = [], {}
    for start,end in BODIES:
        owned = decode(start,end)
        all_sites = {f"{i.address:08x}":text(i) for i in owned}
        instructions.update(all_sites)
        writes = []
        receiver = capstone.x86.X86_REG_EBX if start == 0x4c7560 else capstone.x86.X86_REG_ESI
        for i in owned:
            if i.mnemonic == "mov" and i.operands[0].type == capstone.x86.X86_OP_MEM:
                dst = i.operands[0]
                if dst.mem.base == receiver:
                    writes.append({"site":f"{i.address:08x}","offset":f"{dst.mem.disp:x}",
                                   "width_bytes":dst.size,"source":i.op_str.split(", ",1)[1]})
        row = {"entry_va":f"{start:08x}","last_body_byte_va":f"{end:08x}",
               "file_offset":f"{offset(start):08x}","span_bytes":end-start+1,
               "span_sha256":hashlib.sha256(data[offset(start):offset(end)+1]).hexdigest(),
               "instruction_count":len(owned),"direct_receiver_stores":writes,
               "calls":[{"site":f"{i.address:08x}","target":i.op_str} for i in owned if i.mnemonic == "call"]}
        if native_dir:
            asm = native_dir/f"{start:08x}.asm"
            native = {l[:8]:l[10:] for l in asm.read_text().splitlines() if l}
            assert {a:normalize(t) for a,t in native.items()} == {a:normalize(t) for a,t in all_sites.items()}, "native mismatch"
            refs = [l.split()[0] for l in (native_dir/f"{start:08x}.refs").read_text().splitlines() if l]
            expected_refs = ["00829809"] if start == 0x4c7560 else ["004c7955","004c7873"]
            assert refs == expected_refs
            row["native_corroboration"] = {"all_instructions_match":True,"incoming_direct_call_sites":refs,
                "exports":[{"name":p.name,"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
                           for p in [native_dir/f"{start:08x}.{suffix}" for suffix in ["asm","c","refs"]]]}
        functions.append(row)
    context = {}
    for start,last in CONTEXT:
        rows = list(md.disasm(data[offset(start):offset(last)+16],start))
        kept = [i for i in rows if i.address <= last]
        assert kept[-1].address == last
        context.update({f"{i.address:08x}":text(i) for i in kept})
    anchors = {}
    for va in [0x9a8134,0x9a81c4]:
        anchors[f"{va:08x}"] = data[offset(va):offset(va)+256].split(b"\0",1)[0].decode("ascii")
    assert "contract_manager.cpp" in data[offset(0x9a8190):offset(0x9a8190)+128].split(b"\0",1)[0].decode("ascii")
    assert [len(f["calls"]) for f in functions] == [26,8]
    assert instructions["004c7944"] == "ret"
    assert instructions["004c7abb"] == instructions["004c7aa5"] == "ret 4"
    assert context["00829809"] == "call 0x4c7560"
    caller = decode(0x82876e,0x82980d)
    assert [i.address for i in caller if capstone.x86.X86_REG_EBP in i.regs_access()[1]] == [0x82876e]
    assert context["0082876e"] == "xor ebp, ebp"
    return {"sha256":PINNED,"baseline_commit":"a5972e1659afa4b2937490cdc57ebd8f4a5887d3",
            "method":"PE32 Capstone 5.0.7 decode with optional complete native-export comparison; static only",
            "address_space":"virtual addresses unless file_offset is explicit; field offsets are hexadecimal bytes",
            "functions":functions,"selected_instructions":{f"{a:08x}":instructions[f"{a:08x}"] for a in SELECTED},
            "dependency_caller_sites":context,"diagnostic_labels":anchors,
            "caller_ebp_check":"EBP zeroed at0082876e; no later explicit writes through00829809 call; opaque callees assumed to preserve nonvolatile EBP",
            "source_path_anchor":{"va":"009a8190","suffix":"contract_manager.cpp"},
            "normalization":"mnemonic aliases, numeric spelling, whitespace, redundant DWORD PTR/scale1/+0 and plus-negative displacement",
            "limits":"No native writes, execution, runtime trace, numerical oracle, full callee analysis or bulk code retention. Export hashes identify supplied files; no independent coordinator export manifest was supplied."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--native-dir",type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen,args.native_dir),indent=2)+"\n",encoding="utf-8")

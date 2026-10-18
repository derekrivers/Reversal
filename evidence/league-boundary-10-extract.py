#!/usr/bin/env python3
"""Regenerate compact static sites from pinned PE (capstone==5.0.7); no execution.

Optional --native-dir compares private Ghidra assembly/references and retains
only comparison counts, digests and resolved incoming call sites, never exports.
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
BODIES = [(0x682b30, 0x682e09), (0x682e10, 0x682f61), (0x682f70, 0x683006)]
# Selected address-specific instruction text only; no bulk disassembly/code bytes.
SITES = [
 0x682b37,0x682b3a,0x682b3c,0x682b45,0x682b4f,0x682bb7,
 0x682bc1,0x682be5,0x682be8,0x682bfe,0x682c1b,0x682c20,0x682c3c,
 0x682c4d,0x682c6d,0x682c83,0x682c89,0x682c95,0x682c9b,0x682ca7,
 0x682cad,0x682cb9,0x682cbf,0x682cc7,0x682ccc,0x682cd5,0x682cda,
 0x682ce3,0x682ce8,0x682d1a,0x682d1e,0x682d23,0x682d27,0x682d72,
 0x682d94,0x682dd2,0x682dda,0x682ddc,0x682dde,0x682df5,0x682e07,
 0x682e19,0x682e1b,0x682e21,0x682e29,0x682e31,0x682ea7,0x682eab,
 0x682ead,0x682eb0,0x682eb2,0x682ebf,0x682ecc,0x682ed1,0x682ed6,
 0x682ed9,0x682edf,0x682ee8,0x682eee,0x682efa,0x682f01,0x682f08,
 0x682f0e,0x682f11,0x682f12,0x682f18,0x682f1d,0x682f1f,0x682f24,
 0x682f38,0x682f39,0x682f3a,0x682f3b,0x682f46,0x682f48,0x682f61,
 0x682f78,0x682f7c,0x682f80,0x682f91,0x682fa9,0x682fd8,0x682fde,
 0x682fe5,0x682fe7,0x682ff0,0x682ff3,0x682ff5,0x682ff8,0x682ffa,0x683004,
]
# Dependencies/callers support only; not newly owned function contracts.
CONTEXT = [(0x574b1c,0x574b2b),(0x40563c,0x405651),(0x6471a9,0x6471b0),(0x64720d,0x647213),(0x68281e,0x68281e),
 (0x682874,0x682877),(0x689b98,0x689ba4),(0x68350e,0x683524),
 (0x683528,0x683528),(0x683550,0x68355c),(0x5999a0,0x5999ce),
 (0x5a0639,0x5a0645),(0x945597,0x94559d),(0x94556c,0x945575)]

def normalize(text):
    text = text.lower()
    for old, new in [("jz", "je"), ("jnz", "jne"), ("setz", "sete")]:
        text = re.sub(r"\b"+old+r"\b", new, text)
    text = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0],16)), text)
    text = re.sub(r"\s+", "", text).replace("dwordptr", "")
    return re.sub(r"\*1(?![0-9])", "", text).replace("+0]", "]")

def extract(specimen, native_dir):
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires capstone==5.0.7")
    data = specimen.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED:
        raise ValueError("specimen SHA-256 mismatch")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
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
        raise ValueError(f"VA {va:08x} not file-backed")
    md = Cs(CS_ARCH_X86,CS_MODE_32)
    def decode(start,end):
        return {f"{i.address:08x}": (i.mnemonic+" "+i.op_str).strip()
                for i in md.disasm(data[offset(start):offset(end)+1],start)}
    functions, selected, native = [], {}, []
    for start,end in BODIES:
        decoded = decode(start,end)
        functions.append({"entry_va":f"{start:08x}","last_body_byte_va":f"{end:08x}",
                          "file_offset":f"{offset(start):08x}","span_bytes":end-start+1,
                          "span_sha256":hashlib.sha256(data[offset(start):offset(end)+1]).hexdigest(),
                          "instruction_count":len(decoded)})
        selected.update({a:t for a,t in decoded.items() if int(a,16) in SITES})
        if native_dir:
            asm = native_dir/f"{start:08x}.asm"
            listing = {l[:8]:l[10:] for l in asm.read_text(encoding="utf-8").splitlines() if l}
            if {a:normalize(t) for a,t in listing.items()} != {a:normalize(t) for a,t in decoded.items()}:
                raise ValueError(f"native instruction mismatch {start:08x}")
            refs = []
            for line in (native_dir/f"{start:08x}.refs").read_text(encoding="utf-8").splitlines():
                site, kind = line.split()
                text = decode(int(site,16),int(site,16)+4).get(site)
                if kind != "UNCONDITIONAL_CALL" or text != f"call 0x{start:x}":
                    raise ValueError(f"incoming ref mismatch: {site}")
                refs.append(site)
            native.append({"entry":f"{start:08x}","all_instructions_match":True,
                           "asm_sha256":hashlib.sha256(asm.read_bytes()).hexdigest(),
                           "incoming_direct_call_sites":refs})
    if len(selected) != len(SITES):
        raise ValueError("selected instruction missing")
    context = {}
    for start,end in CONTEXT:
        context.update(decode(start,end+8))
        context = {a:t for a,t in context.items() if not end < int(a,16) <= end+8}
    string = data[offset(0x9f15f4):offset(0x9f15f4)+256].split(b"\0",1)[0].decode("ascii")
    return {"sha256":digest,"method":"static PE32 x86 decode; capstone==5.0.7; no execution",
            "address_space":"virtual addresses unless file_offset is explicit",
            "functions":functions,"selected_instructions":selected,"dependency_caller_sites":context,
            "source_path_anchor":{"009f15f4":string},"native_corroboration":native,
            "native_normalization":"mnemonic aliases, numeric spelling, whitespace, redundant scale1/+0, and redundant DWORD PTR (register operands retain width)"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen",type=Path)
    parser.add_argument("output",type=Path)
    parser.add_argument("--native-dir",type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen,args.native_dir),indent=2)+"\n",encoding="utf-8")

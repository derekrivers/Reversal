#!/usr/bin/env python3
"""Emit compact static evidence from the pinned PE; never execute or export its code.

Requires Python 3.12+ and capstone==5.0.7. Output contains selected instruction
text and digests, not raw code, bulk disassembly or original record data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
RANGES = [(0x0054d5e0, 0x0054d6d0), (0x0054d740, 0x0054d832)]
# Only addresses needed to substantiate the contract; not a whole-function dump.
SITES = [
    0x54d5e0, 0x54d5eb, 0x54d5ee, 0x54d5f1, 0x54d5f2, 0x54d605,
    0x54d61d, 0x54d663, 0x54d668, 0x54d66f, 0x54d671,
    0x54d673, 0x54d67a, 0x54d681, 0x54d682, 0x54d683, 0x54d688,
    0x54d689, 0x54d68e, 0x54d693, 0x54d695, 0x54d698, 0x54d6a1,
    0x54d6b2, 0x54d6b8, 0x54d6c2, 0x54d6c4,
    0x54d740, 0x54d74b, 0x54d74e, 0x54d751, 0x54d754, 0x54d767,
    0x54d77f, 0x54d7c5, 0x54d7d1, 0x54d7d3, 0x54d7e5, 0x54d7eb,
    0x54d7f5, 0x54d7f7, 0x54d803, 0x54d814, 0x54d81a, 0x54d824,
    0x54d826,
]

def extract(path):
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires capstone==5.0.7")
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != PINNED:
        raise ValueError("specimen SHA-256 mismatch")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[:2] != b"MZ" or data[pe:pe+4] != b"PE\0\0":
        raise ValueError("not PE")
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x10b:
        raise ValueError("not PE32")
    base = struct.unpack_from("<I", data, opt+28)[0]
    count = struct.unpack_from("<H", data, pe+6)[0]
    opt_size = struct.unpack_from("<H", data, pe+20)[0]
    sections = [struct.unpack_from("<8sIIII", data, opt+opt_size+40*i)
                for i in range(count)]
    def offset(va):
        for _, _, rva, raw_size, raw_offset in sections:
            delta = va-base-rva
            if 0 <= delta < raw_size:
                return raw_offset+delta
        raise ValueError(f"VA {va:08x} is not file-backed")
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    funcs, instructions = [], {}
    for start, end in RANGES:
        raw = data[offset(start):offset(end)+1]
        funcs.append({"entry_va": f"{start:08x}", "last_instruction_va": f"{end:08x}",
                      "file_offset": f"{offset(start):08x}", "body_span_bytes": len(raw),
                      "body_span_sha256": hashlib.sha256(raw).hexdigest()})
        for ins in md.disasm(raw, start):
            if ins.address in SITES:
                instructions[f"{ins.address:08x}"] = f"{ins.mnemonic} {ins.op_str}".strip()
    if len(instructions) != len(SITES):
        raise ValueError("selected instruction site missing")
    # Decode caller/dependency excerpts only at independently known boundaries.
    excerpts = [(0x52b437,0x52b458), (0x52c058,0x52c07a),
                (0x932cbf,0x932cc6), (0x932df3,0x932df7),
                (0x945c58,0x945c5c), (0x945cb2,0x945cb2),
                (0x945ce1,0x945ce1), (0x9459dd,0x9459e7)]
    context = {}
    for start, end in excerpts:
        for ins in md.disasm(data[offset(start):offset(end)+16],start):
            if ins.address > end:
                break
            context[f"{ins.address:08x}"] = f"{ins.mnemonic} {ins.op_str}".strip()
    strings = {}
    for va in [0x9b8dc0, 0x9870e0, 0x9870e8]:
        strings[f"{va:08x}"] = data[offset(va):offset(va)+256].split(b"\0",1)[0].decode("ascii")
    imports = {}
    import_rva, import_bytes = struct.unpack_from("<II", data, opt+104)
    for desc in range(offset(base+import_rva), offset(base+import_rva)+import_bytes, 20):
        original, _, _, name_rva, thunk = struct.unpack_from("<IIIII", data, desc)
        if not name_rva:
            break
        dll = data[offset(base+name_rva):].split(b"\0",1)[0].decode("ascii")
        index = 0
        while True:
            value = struct.unpack_from("<I", data, offset(base+(original or thunk))+4*index)[0]
            if not value:
                break
            if base+thunk+4*index == 0x967164 and not value & 0x80000000:
                name = data[offset(base+value+2):].split(b"\0",1)[0].decode("ascii")
                imports["00967164"] = dll+"!"+name
            index += 1
    return {"sha256": digest, "method": "static PE32 x86 decode; capstone==5.0.7; no execution",
            "address_space": "virtual addresses unless file_offset is explicit",
            "functions": funcs, "selected_instructions": instructions,
            "supporting_context": context, "bounded_strings": strings, "bounded_imports": imports}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen",type=Path)
    parser.add_argument("output",type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen),indent=2)+"\n",encoding="utf-8")

#!/usr/bin/env python3
"""Reproduce selected static finance sites; capstone==5.0.7, no execution.

Full disassembly and original bytes are never written. Optional private native
exports are compared completely but only digests/counts/call addresses survive.
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
BODIES = [(0x5999a0, 0x5999d3), (0x59a370, 0x59a59a),
          (0x59b2a0, 0x59b3ae), (0x5a0590, 0x5a0647)]
SITES = [
    0x5999a0,0x5999a4,0x5999ab,0x5999b1,0x5999b3,0x5999b5,0x5999bb,
    0x5999c1,0x5999c3,0x5999c4,0x5999c6,0x5999c8,0x5999cb,0x5999ce,0x5999d1,
    0x59a38e,0x59a3a5,0x59a3be,0x59a3c0,0x59a3fe,0x59a408,0x59a465,
    0x59a46d,0x59a472,0x59a478,0x59a47b,0x59a47e,0x59a481,0x59a483,
    0x59a487,0x59a495,0x59a49e,0x59a4a0,0x59a4a5,0x59a4aa,0x59a4ad,
    0x59a4ae,0x59a4b3,0x59a4b4,0x59a4b6,0x59a4ca,0x59a4cd,0x59a52b,
    0x59a531,0x59a54b,0x59a54e,0x59a555,0x59a557,0x59a55c,0x59a563,
    0x59a565,0x59a56a,0x59a570,0x59a573,0x59a575,0x59a57a,0x59a57f,
    0x59a584,0x59a585,0x59a58b,0x59a591,0x59a593,0x59a595,
    0x59b2a0,0x59b2aa,0x59b2ad,0x59b2af,0x59b2b5,0x59b2b7,0x59b2b9,
    0x59b2bb,0x59b2c0,0x59b2c1,0x59b2c9,0x59b2cf,0x59b302,0x59b308,
    0x59b30a,0x59b30b,0x59b30c,0x59b311,0x59b312,0x59b317,0x59b320,
    0x59b322,0x59b37d,0x59b387,0x59b390,0x59b393,0x59b398,0x59b3a0,0x59b3ac,
    0x5a0597,0x5a059f,0x5a05a1,0x5a05a3,0x5a05cc,0x5a05fb,0x5a0601,
    0x5a060b,0x5a060e,0x5a0612,0x5a0614,0x5a0615,0x5a0616,0x5a061b,
    0x5a061e,0x5a0620,0x5a0622,0x5a0626,0x5a0628,0x5a062a,
    0x5a062c,0x5a062e,0x5a0631,0x5a0634,0x5a0637,0x5a0639,0x5a063c,0x5a0645,
]
# Supporting dependency/caller sites, not complete newly owned contracts.
CONTEXT = [
    (0x682f0e,0x682f1f),
    (0x540aca,0x540aeb),(0x54129c,0x5412a7),(0x541871,0x54187c),
    (0x541861,0x541868),(0x541e32,0x541e39),(0x541e42,0x541e52),
    (0x5961c0,0x5961c2),(0x5a8f60,0x5a8f60),
    (0x59a5a0,0x59a5c8),(0x9463dd,0x9463f6),
    (0x932cc6,0x932cc6),(0x932df7,0x932df7),
    (0x932c01,0x932c1e),
    (0x82974f,0x829781),(0x82c740,0x82c770),
]


def normalize(text):
    text = text.lower()
    for old, new in [("jz", "je"), ("jnz", "jne"), ("setz", "sete")]:
        text = re.sub(r"\b" + old + r"\b", new, text)
    text = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0], 16)), text)
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
    opt = pe + 24
    if data[:2] != b"MZ" or data[pe:pe+4] != b"PE\0\0" or struct.unpack_from("<H", data, opt)[0] != 0x10b:
        raise ValueError("not PE32")
    base = struct.unpack_from("<I", data, opt+28)[0]
    count = struct.unpack_from("<H", data, pe+6)[0]
    opt_size = struct.unpack_from("<H", data, pe+20)[0]
    sections = [struct.unpack_from("<8sIIII", data, opt+opt_size+40*i) for i in range(count)]

    def offset(va):
        for _, _, rva, raw_size, raw_offset in sections:
            delta = va-base-rva
            if 0 <= delta < raw_size:
                return raw_offset+delta
        raise ValueError(f"VA {va:08x} not file-backed")

    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def decode(start, end):
        return {f"{i.address:08x}": (i.mnemonic+" "+i.op_str).strip()
                for i in md.disasm(data[offset(start):offset(end)+1], start)}

    functions, selected, native = [], {}, []
    for start, end in BODIES:
        decoded = decode(start, end)
        functions.append({"entry_va": f"{start:08x}", "last_body_byte_va": f"{end:08x}",
                          "file_offset": f"{offset(start):08x}", "span_bytes": end-start+1,
                          "span_sha256": hashlib.sha256(data[offset(start):offset(end)+1]).hexdigest(),
                          "instruction_count": len(decoded)})
        selected.update({a: t for a, t in decoded.items() if int(a, 16) in SITES})
        if native_dir:
            asm = native_dir/f"{start:08x}.asm"
            listing = {l[:8]: l[10:] for l in asm.read_text(encoding="utf-8").splitlines() if l}
            if {a: normalize(t) for a, t in listing.items()} != {a: normalize(t) for a, t in decoded.items()}:
                raise ValueError(f"native instruction mismatch {start:08x}")
            refs_file = native_dir/f"{start:08x}.refs"
            refs = []
            for line in refs_file.read_text(encoding="utf-8").splitlines():
                site, kind = line.split()
                instruction = decode(int(site, 16), int(site, 16)+4).get(site)
                if kind != "UNCONDITIONAL_CALL" or instruction != f"call 0x{start:x}":
                    raise ValueError(f"incoming ref mismatch: {site}")
                refs.append(site)
            native.append({"entry": f"{start:08x}", "all_instructions_match": True,
                           "asm_sha256": hashlib.sha256(asm.read_bytes()).hexdigest(),
                           "refs_sha256": hashlib.sha256(refs_file.read_bytes()).hexdigest(),
                           "incoming_direct_call_count": len(refs), "incoming_direct_call_sites": refs})
    if len(selected) != len(SITES):
        raise ValueError("selected instruction missing")
    context = {}
    for start, end in CONTEXT:
        context.update({a: t for a, t in decode(start, end+15).items() if int(a, 16) <= end})
    strings = {}
    for va in [0x9c8784, 0x9c87b0]:
        strings[f"{va:08x}"] = data[offset(va):offset(va)+128].split(b"\0", 1)[0].decode("ascii")
    return {"sha256": digest, "method": "static PE32 x86 decode; capstone==5.0.7; no execution",
            "address_space": "virtual addresses unless file_offset is explicit",
            "functions": functions, "selected_instructions": selected,
            "dependency_caller_sites": context, "source_anchors": strings,
            "native_corroboration": native,
            "native_normalization": "mnemonic aliases, numeric spelling, whitespace, redundant scale1/+0 and DWORD PTR; registers retain width"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--native-dir", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen, args.native_dir), indent=2)+"\n", encoding="utf-8")

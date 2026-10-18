#!/usr/bin/env python3
"""Verify complete R16 stream-helper bodies and emit compact static evidence.

Requires capstone==5.0.7. Inputs are the pinned PE32 specimen, private exports-16
directory, and private annotation preflight. No original bytes or full listings
are emitted. Usage: python extract_db_stream_16.py EXE EXPORTS PREFLIGHT OUTPUT
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "fc92c27bcc9f2f15bedebb4aadbebba7bf0ed5f8801c787e2f0e262c48a7e960"
PREFLIGHT = "2be810e149b9d5ebe8de028bf9542aab932afd31514e2ec8d737bef8450374bc"
# Only selected decision/write sites are retained after whole-body comparison.
ROWS = [
    (0x945bfe, 232, [0x945c08, 0x945c19, 0x945c25, 0x945c35,
                    0x945c50, 0x945c64, 0x945c67, 0x945c73, 0x945c82,
                    0x945c96, 0x945c9a, 0x945cb2, 0x945cbe, 0x945cc8,
                    0x945cd0, 0x945cd6, 0x945ce1]),
    (0x932c30, 468, [0x932c37, 0x932c43, 0x932c5c, 0x932c6e,
                    0x932c78, 0x932c7a, 0x932c80, 0x932c91, 0x932c94,
                    0x932c9f, 0x932cb2, 0x932cc6, 0x932cd3, 0x932ce2,
                    0x932ce9, 0x932cfe, 0x932d0c, 0x932d1d, 0x932d2a,
                    0x932d30, 0x932d35, 0x932d43, 0x932d45, 0x932d4c,
                    0x932d68, 0x932d70, 0x932d73, 0x932d7d, 0x932d80,
                    0x932d9e, 0x932da4, 0x932da9, 0x932db3, 0x932dd5,
                    0x932ddf, 0x932dec]),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalize(text):
    text = text.lower()
    for old, new in [("jz", "je"), ("jnz", "jne"), ("jc", "jb")]:
        text = re.sub(r"\b" + old + r"\b", new, text)
    text = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0], 16)), text)
    compact = re.sub(r"\s+", "", text).replace("+-", "-")
    return re.sub(r"\*1(?=[+\-\]])", "", compact)


def extract(specimen, exports, preflight):
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires capstone==5.0.7")
    data = specimen.read_bytes()
    manifest_raw = (exports / "manifest.json").read_bytes()
    preflight_raw = preflight.read_bytes()
    for actual, expected, label in [(digest(data), PINNED, "specimen"),
                                     (digest(manifest_raw), MANIFEST, "manifest"),
                                     (digest(preflight_raw), PREFLIGHT, "preflight")]:
        if actual != expected:
            raise ValueError(label + " hash mismatch")
    manifest = json.loads(manifest_raw)
    preflight_doc = json.loads(preflight_raw)
    if manifest["specimen_sha256"] != PINNED or preflight_doc["sha256"] != PINNED:
        raise ValueError("native specimen mismatch")
    old_names = {row["address"]: row for row in preflight_doc["sites"]}
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    opt = pe + 24
    if (data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0"
            or struct.unpack_from("<H", data, opt)[0] != 0x10b):
        raise ValueError("not PE32")
    base = struct.unpack_from("<I", data, opt + 28)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<8sIIII", data, opt + opt_size + 40 * i)
                for i in range(count)]

    def offset(va):
        for _, _, rva, raw_size, raw_offset in sections:
            delta = va - base - rva
            if 0 <= delta < raw_size:
                return raw_offset + delta
        raise ValueError(f"VA {va:08x} is not file-backed")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    functions = []
    for start, size, picks in ROWS:
        entry = f"{start:08x}"
        raw = data[offset(start):offset(start) + size]
        ins = list(md.disasm(raw, start))
        if sum(i.size for i in ins) != size:
            raise ValueError("incomplete decode: " + entry)
        native_hashes = {}
        for suffix in ["asm", "c"]:
            name = entry + "." + suffix
            exported = (exports / name).read_bytes()
            row = manifest["files"][name]
            if digest(exported) != row["sha256"] or len(exported) != row["bytes"]:
                raise ValueError("native export mismatch: " + name)
            native_hashes[suffix] = digest(exported)
        native = {}
        for line in (exports / (entry + ".asm")).read_text().splitlines():
            address, instruction = line.split(None, 1)
            native[int(address, 16)] = normalize(instruction)
        own = {i.address: normalize(i.mnemonic + " " + i.op_str) for i in ins}
        if own != native:
            mismatch = {f"{va:08x}": [own.get(va), native.get(va)]
                        for va in set(own) | set(native) if own.get(va) != native.get(va)}
            raise ValueError("native instruction mismatch: " + str(mismatch))
        name = old_names[entry]
        if not name["instruction_exists"] or name["function_name"] != "FUN_" + entry:
            raise ValueError("unexpected old annotation: " + entry)
        if name["function_name"] + "(" not in (exports / (entry + ".c")).read_text():
            raise ValueError("decompiler header disagrees: " + entry)
        branches = [i for i in ins if i.group(capstone.CS_GRP_JUMP)]
        for branch in branches:
            if len(branch.operands) != 1 or branch.operands[0].type != capstone.x86.X86_OP_IMM:
                raise ValueError("unresolved branch: " + entry)
            if branch.operands[0].imm not in own:
                raise ValueError("branch target outside owned instructions: " + entry)
        calls = []
        for index, i in enumerate(ins):
            if i.mnemonic == "call":
                calls.append({"site_va": f"{i.address:08x}",
                              "target_va": f"{i.operands[0].imm:08x}",
                              "argument_pushes": [j.op_str for j in ins[max(0, index - 4):index]
                                                  if j.mnemonic == "push"]})
        selected = {f"{i.address:08x}": (i.mnemonic + " " + i.op_str).strip()
                    for i in ins if i.address in picks}
        if len(selected) != len(picks):
            raise ValueError("selected site not an instruction")
        functions.append({"entry_va": entry, "file_offset": f"{offset(start):08x}",
                          "span_bytes": size, "span_sha256": digest(raw),
                          "last_instruction_va": f"{ins[-1].address:08x}",
                          "instruction_count": len(ins),
                          "native_matched_instructions": len(ins),
                          "native_file_sha256": native_hashes,
                          "old_function_name": name["function_name"],
                          "verified_internal_branch_count": len(branches),
                          "return_sites_va": [f"{i.address:08x}" for i in ins if i.mnemonic == "ret"],
                          "calls": calls, "selected_instructions": selected})
    return {"specimen_sha256": PINNED, "native_manifest_sha256": MANIFEST,
            "private_preflight_sha256": PREFLIGHT,
            "address_space": "virtual addresses unless file_offset is explicit",
            "method": "capstone==5.0.7 complete body/native comparison and internal branch target verification; static only",
            "functions": functions}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specimen", type=Path)
    parser.add_argument("exports", type=Path)
    parser.add_argument("preflight", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen, args.exports, args.preflight), indent=2)
                           + "\n", encoding="utf-8", newline="\n")

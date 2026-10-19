#!/usr/bin/env python3
"""Verify complete R27-B PE/native instructions and emit compact static sites."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "bbd00280029a738f4f4dfa6462c7d34a4379887626749d9f20eef20873655f14"
PREFLIGHT = "fb1be5075c72e92045f4d802f649665801d8ebc85b049a25e0f652e282f6015d"
CHECKPOINT = "4acf11ca1ab79b275436c6365813904d87634436de1723ce24a2274f83a087c4"
ENTRY, SIZE = 0x9488e0, 123


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(n):
    return f"{n:08x}"


def normalized(s):
    s = s.lower().strip()
    s = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0], 16)), s)
    s = re.sub(r"\s+", "", s).replace("+-", "-")
    for a, b in (("jnz", "jne"), ("jz", "je")):
        if s.startswith(a):
            s = b+s[len(a):]
    return s


def extract(binary, exports, preflight):
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    pe = binary.read_bytes()
    need(len(pe) == 7192576 and sha(pe) == SPECIMEN, "pinned specimen mismatch")
    manifest_raw, preflight_raw = (exports/"manifest.json").read_bytes(), preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST and sha(preflight_raw) == PREFLIGHT,
         "native manifest/preflight SHA-256 mismatch")
    manifest, old = json.loads(manifest_raw), json.loads(preflight_raw)
    need(manifest["specimen_sha256"] == old["sha256"] == SPECIMEN and
         manifest["checkpoint_archive_sha256"] == CHECKPOINT and
         manifest["preflight_sha256"] == PREFLIGHT, "native provenance mismatch")
    need(set(manifest["files"]) == {hx(va)+ext for va in
         (0x682b30, 0x68d1b0, 0x68d1d0, 0x68d1f0, 0x945333, ENTRY) for ext in (".asm", ".c")},
         "native export inventory mismatch")
    for name, meta in manifest["files"].items():
        raw = (exports/name).read_bytes()
        need(len(raw) == meta["bytes"] and sha(raw) == meta["sha256"],
             "native export mismatch: "+name)
    sites = {int(s["address"], 16): s for s in old["sites"]}
    need(len(sites) == 5 and sites[ENTRY] ==
         {"address": hx(ENTRY), "function_name": "_strlen",
          "function_comment": "Library Function - Single Match\n _strlen\n\nLibraries: Visual Studio 1998 Debug, Visual Studio 1998 Release",
          "instruction_exists": True, "body_addresses": SIZE}, "exact-old native metadata mismatch")
    pe_offset = struct.unpack_from("<I", pe, 0x3c)[0]
    need(pe[:2] == b"MZ" and pe[pe_offset:pe_offset+4] == b"PE\0\0", "invalid PE")
    need(struct.unpack_from("<H", pe, pe_offset+4)[0] == 0x14c and
         struct.unpack_from("<H", pe, pe_offset+24)[0] == 0x10b, "requires PE32 x86")
    count = struct.unpack_from("<H", pe, pe_offset+6)[0]
    opt_size = struct.unpack_from("<H", pe, pe_offset+20)[0]
    base = struct.unpack_from("<I", pe, pe_offset+24+28)[0]
    sections = [struct.unpack_from("<8sIIII", pe, pe_offset+24+opt_size+40*i)
                for i in range(count)]
    locations = [raw_off+(ENTRY-base-rva) for _, virtual_size, rva, raw_size, raw_off
                 in sections if 0 <= ENTRY-base-rva and ENTRY-base-rva+SIZE <= min(virtual_size, raw_size)]
    need(len(locations) == 1, "body is not uniquely raw-backed")
    offset = locations[0]
    body = pe[offset:offset+SIZE]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    ins = list(md.disasm(body, ENTRY))
    need(ins and sum(i.size for i in ins) == SIZE and ins[-1].address+ins[-1].size == ENTRY+SIZE,
         "incomplete local-body decode")
    asm = (exports/"009488e0.asm").read_text(encoding="utf-8-sig")
    native = [(int(m[1], 16), m[2]) for m in
              re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", asm, re.M)]
    need(len(native) == len(ins), "native instruction count differs")
    branches, calls = {}, {}
    for i, (address, line) in zip(ins, native):
        need(i.address == address, "native instruction address mismatch")
        need(normalized(i.mnemonic+" "+i.op_str) == normalized(line),
             "native PE operand mismatch at "+hx(i.address))
        if i.mnemonic.startswith("j"):
            need(len(i.operands) == 1 and i.operands[0].type == capstone.x86.X86_OP_IMM,
                 "indirect branch")
            branches[hx(i.address)] = hx(i.operands[0].imm)
        if i.mnemonic == "call":
            need(len(i.operands) == 1 and i.operands[0].type == capstone.x86.X86_OP_IMM,
                 "indirect call")
            calls[hx(i.address)] = hx(i.operands[0].imm)
    need(not calls, "unexpected callee")
    addresses = {i.address for i in ins}
    edges = []
    for i in ins:
        after = i.address+i.size
        if i.mnemonic.startswith("j"):
            target = i.operands[0].imm
            need(target in addresses, "branch target outside local instructions")
            edges.append([hx(i.address), hx(target)])
            if i.mnemonic != "jmp":
                need(after in addresses, "branch fallthrough outside body")
                edges.append([hx(i.address), hx(after)])
        elif i.mnemonic != "ret":
            need(after in addresses, "fallthrough outside body")
            edges.append([hx(i.address), hx(after)])
    need([hx(i.address) for i in ins if i.mnemonic == "ret"] ==
         ["0094893c", "00948946", "00948950", "0094895a"], "return sites changed")
    reads, writes = [], []
    for i in ins:
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                row = {"va": hx(i.address), "bytes": op.size,
                       "operand": i.op_str}
                if i.mnemonic != "lea" and op.access & capstone.CS_AC_READ:
                    reads.append(row)
                if op.access & capstone.CS_AC_WRITE:
                    writes.append(row)
    return {"schema_version": 1, "unit": "R27-B", "entry_va": hx(ENTRY),
            "old_native_name": "_strlen", "annotation_action": "preserve existing name and comment",
            "address_kind": "virtual unless file_offset is explicit",
            "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": CHECKPOINT,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "file_offset": hx(offset), "body_bytes": SIZE, "body_sha256": sha(body),
            "instruction_count": len(ins), "end_exclusive_va": hx(ENTRY+SIZE),
            "instruction_starts": [hx(i.address) for i in ins],
            "return_sites": ["0094893c", "00948946", "00948950", "0094895a"],
            "return_stack_immediate": 0, "branches": branches, "calls": calls,
            "cfg_edges": edges, "explicit_reads": reads, "explicit_writes": writes,
            "native_instructions_match": True,
            "python_optimized_integrity": "explicit ValueError gates; no assert"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/strlen-runtime-27-sites.json"))
    args = parser.parse_args()
    result = extract(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")
    print("wrote", args.output)

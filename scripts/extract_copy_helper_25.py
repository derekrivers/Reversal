#!/usr/bin/env python3
"""Verify complete R25-C PE/native instructions and emit compact static sites."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "9f7e0de5968e38bac77fe8438678596f82ab31abee5e820c7ccb36b2f1ce531c"
PREFLIGHT = "34ca2e277634b5a4bdbde668ffcc7d3b91a65a4c1689844f54c454b644834899"
CHECKPOINT = "77fb2072a25ff030ab3c0e58c5cd289730a9a8c5345ceaaf56e948e727c1dd0b"
ENTRY, SIZE = 0x948851, 138


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
         (0x62ec00, 0x62ece0, 0x62ed70, 0x6d0980, ENTRY) for ext in (".asm", ".c")},
         "native export inventory mismatch")
    for name, meta in manifest["files"].items():
        raw = (exports/name).read_bytes()
        need(len(raw) == meta["bytes"] and sha(raw) == meta["sha256"],
             "native export mismatch: "+name)
    sites = {int(s["address"], 16): s for s in old["sites"]}
    need(len(sites) == 5 and sites[ENTRY] ==
         {"address": hx(ENTRY), "function_name": "FUN_00948851", "instruction_exists": True},
         "exact-old native name mismatch")
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
    asm = (exports/"00948851.asm").read_text(encoding="utf-8-sig")
    native = [(int(m[1], 16), m[2]) for m in
              re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", asm, re.M)]
    need(len(native) == len(ins), "native instruction count differs")
    branches, calls = {}, {}
    for i, (address, line) in zip(ins, native):
        need(i.address == address, "native instruction address mismatch")
        if i.address not in (0x9488cc, 0x9488d3):
            need(normalized(i.mnemonic+" "+i.op_str) == normalized(line),
                 "native PE operand mismatch at "+hx(i.address))
        else:
            need((i.address == 0x9488cc and i.mnemonic == "rep stosd" and
                  line == "STOSD.REP ES:EDI") or
                 (i.address == 0x9488d3 and i.mnemonic == "rep stosb" and
                  line == "STOSB.REP ES:EDI"), "repeat-store operand mismatch")
        if i.mnemonic.startswith("j"):
            need(len(i.operands) == 1 and i.operands[0].type == capstone.x86.X86_OP_IMM,
                 "indirect branch")
            branches[hx(i.address)] = hx(i.operands[0].imm)
        if i.mnemonic == "call":
            need(len(i.operands) == 1 and i.operands[0].type == capstone.x86.X86_OP_IMM,
                 "indirect call")
            calls[hx(i.address)] = hx(i.operands[0].imm)
    need(calls == {"0094886b": "009466d0"}, "callee boundary changed")
    need(ins[-1].address == 0x9488da and ins[-1].mnemonic == "ret" and
         not ins[-1].op_str, "cdecl return changed")
    critical = {0x948854: ("cmp", "dword ptr [0xde441c], 0"),
                0x948886: ("test", "byte ptr [esi + 0xde4521], 4"),
                0x94888d: ("mov", "byte ptr [edi], al"),
                0x9488b0: ("and", "byte ptr [edi - 1], 0"),
                0x9488b6: ("and", "byte ptr [edi - 2], 0"),
                0x9488c9: ("shr", "ecx, 2"),
                0x9488d0: ("and", "ecx, 3")}
    by_address = {i.address: i for i in ins}
    for address, (mnemonic, operand) in critical.items():
        i = by_address[address]
        need(i.mnemonic == mnemonic and i.op_str == operand,
             "critical PE operand mismatch at "+hx(address))
    need(by_address[0x94888d].operands[0].size == 1 and
         by_address[0x9488b0].operands[0].size == 1 and
         by_address[0x9488b6].operands[0].size == 1,
         "copy/truncation write width changed")
    return {"schema_version": 1, "unit": "R25-C", "entry_va": hx(ENTRY),
            "old_native_name": "FUN_00948851", "address_kind": "virtual unless file_offset is explicit",
            "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": CHECKPOINT,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "file_offset": hx(offset), "body_bytes": SIZE, "body_sha256": sha(body),
            "instruction_count": len(ins), "end_exclusive_va": hx(ENTRY+SIZE),
            "return_site": "009488da", "return_stack_immediate": 0,
            "branches": branches, "calls": calls,
            "critical_sites": {hx(a): {"mnemonic": m, "operand": op}
                               for a, (m, op) in critical.items()},
            "native_instructions_match": True,
            "mode_zero": "delegated _strncpy at 009466d0; static boundary only",
            "nonzero_mode": "call-free locale lead-byte loop, truncation and zero padding",
            "python_optimized_integrity": "explicit ValueError gates; no assert"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/copy-helper-25-sites.json"))
    args = parser.parse_args()
    result = extract(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")
    print("wrote", args.output)

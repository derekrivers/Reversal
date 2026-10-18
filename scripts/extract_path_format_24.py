#!/usr/bin/env python3
"""Check R24-C PE/native local bodies and emit compact static sites only."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN_SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "c3770d9a3b8b99d80454413ea5ec85114aa0f3baa9ec0c661567c30d7bf40e70"
PREFLIGHT_SHA = "1df62ffab8859fa6d1b86e486a26f10f82c82827eb08356caae3ce916694a193"
CHECKPOINT_SHA = "9cb03ce3740e5529a2f6155aa20b1a61ea4ba321c6d3520e1c91525782703f52"
SPECS = {0x944C9F: (82, "FUN_00944c9f"), 0x944CFF: (327, "FUN_00944cff")}
EXPECTED_CALLS = {
    0x944CC8: 0x947C67, 0x944CE5: 0x947B52,
    0x944D0E: 0x9488E0, 0x944D2A: 0x948851, 0x944DA5: 0x948851,
    0x944DE4: 0x948851, 0x944E0B: 0x948851, 0x944E2B: 0x948851,
}
EXPECTED_BRANCHES = {
    0x944CD5: 0x944CDF, 0x944CDD: 0x944CEC,
    0x944D17: 0x944D3A, 0x944D1D: 0x944D3A, 0x944D24: 0x944D36,
    0x944D38: 0x944D44, 0x944D3F: 0x944D44, 0x944D55: 0x944DBC,
    0x944D63: 0x944D68, 0x944D66: 0x944D82, 0x944D6B: 0x944D7C,
    0x944D70: 0x944D7C, 0x944D75: 0x944D82, 0x944D7A: 0x944D82,
    0x944D86: 0x944D57, 0x944D90: 0x944DBC, 0x944D96: 0x944DB7,
    0x944D9C: 0x944DA0, 0x944DBA: 0x944DC6, 0x944DC1: 0x944DC6,
    0x944DCB: 0x944E19, 0x944DCF: 0x944E19, 0x944DD5: 0x944DF6,
    0x944DDB: 0x944DDF, 0x944DFB: 0x944E41, 0x944E02: 0x944E06,
    0x944E17: 0x944E41, 0x944E1E: 0x944E37, 0x944E24: 0x944E28,
    0x944E3C: 0x944E41,
}
OUTPUT_TERMINATORS = {
    0x944D32: "drive[2]", 0x944D41: "drive[0]",
    0x944DB0: "directory[min(delta,255)]", 0x944DC3: "directory[0]",
    0x944DEF: "basename[min(dot-basename,255)]",
    0x944E13: "extension[min(end-dot,255)]",
    0x944E33: "basename[min(end-basename,255)]",
    0x944E3E: "extension[0]", 0x944CDA: "formatter_cursor[0]",
}
OUTPUT_COPIES = {0x944D2A: "drive:2", 0x944DA5: "directory:<=255",
                 0x944DE4: "basename_before_last_dot:<=255",
                 0x944E0B: "extension_including_dot:<=255",
                 0x944E2B: "basename_without_extension:<=255"}
EXPECTED_SITE_OPERANDS = {
    0x944CA5: "MOV EAX,dword ptr [EBP + 0x8]",
    0x944CB2: "MOV dword ptr [EBP + -0x14],0x42",
    0x944CC0: "MOV dword ptr [EBP + -0x1c],0x7fffffff",
    0x944CD0: "DEC dword ptr [EBP + -0x1c]",
    0x944D13: "CMP EAX,0x1",
    0x944D19: "CMP byte ptr [EBX + 0x1],0x3a",
    0x944D26: "PUSH 0x2",
    0x944D4D: "MOV ESI,0xff",
    0x944D5C: "TEST byte ptr [EDX + 0xde4521],0x4",
    0x944D68: "CMP CL,0x2f",
    0x944D6D: "CMP CL,0x5c",
    0x944D72: "CMP CL,0x2e",
    0x944D9A: "CMP EDI,ESI",
    0x944DD9: "CMP EDI,ESI",
    0x944E00: "CMP EAX,ESI",
    0x944E22: "CMP EAX,ESI",
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(n):
    return f"{n:08x}"


def norm(s):
    s = s.lower().strip()
    s = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0], 16)), s)
    s = re.sub(r"\s+", "", s).replace("+-", "-").replace("+0]", "]")
    s = re.sub(r"\*1(?=[+\]])", "", s)
    s = re.sub(r"^(mov(?:eax|ecx|esi),)dwordptr(\[)", r"\1\2", s)
    for old, new in (("jnz", "jne"), ("jz", "je"), ("jnc", "jae"), ("jc", "jb")):
        if s.startswith(old):
            s = new+s[len(old):]
    return s


def run(binary, exports, preflight):
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    pe_data = binary.read_bytes()
    need(len(pe_data) == 7192576 and sha(pe_data) == SPECIMEN_SHA,
         "specimen size/SHA-256 mismatch")
    manifest_raw = (exports / "manifest.json").read_bytes()
    preflight_raw = preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST_SHA, "export manifest SHA-256 mismatch")
    need(sha(preflight_raw) == PREFLIGHT_SHA, "annotation preflight SHA-256 mismatch")
    manifest, prior = json.loads(manifest_raw), json.loads(preflight_raw)
    need(manifest["specimen_sha256"] == prior["sha256"] == SPECIMEN_SHA,
         "specimen metadata mismatch")
    need(manifest["checkpoint_archive_sha256"] == CHECKPOINT_SHA and
         manifest["preflight_sha256"] == PREFLIGHT_SHA, "native checkpoint mismatch")
    need(set(manifest["files"]) == {hx(va)+ext for va in
         (0x54CC30, 0x62C680, *SPECS) for ext in (".asm", ".c")},
         "export inventory mismatch")
    for name, meta in manifest["files"].items():
        raw = (exports / name).read_bytes()
        need(len(raw) == meta["bytes"] and sha(raw) == meta["sha256"],
             "native export size/SHA-256 mismatch: "+name)
    prior_sites = {int(site["address"], 16): site for site in prior["sites"]}
    need(len(prior_sites) == 4, "preflight site inventory mismatch")
    for va, (length, old_name) in SPECS.items():
        need(prior_sites[va] == {"address": hx(va), "function_name": old_name,
             "function_comment_blank": True, "instruction_exists": True,
             "body_addresses": length}, "exact-old preflight mismatch at "+hx(va))

    pe = struct.unpack_from("<I", pe_data, 0x3C)[0]
    need(pe_data[:2] == b"MZ" and pe_data[pe:pe+4] == b"PE\0\0", "invalid PE")
    need(struct.unpack_from("<H", pe_data, pe+4)[0] == 0x14C and
         struct.unpack_from("<H", pe_data, pe+24)[0] == 0x10B, "expected PE32 x86")
    section_count = struct.unpack_from("<H", pe_data, pe+6)[0]
    opt_size = struct.unpack_from("<H", pe_data, pe+20)[0]
    optional = pe+24
    base = struct.unpack_from("<I", pe_data, optional+28)[0]
    sections = [struct.unpack_from("<8sIIII", pe_data, optional+opt_size+40*n)
                for n in range(section_count)]

    def offset(va, size):
        for _, virtual_size, rva, raw_size, raw_off in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= min(virtual_size, raw_size):
                return raw_off+delta
        raise ValueError("VA not raw-backed: "+hx(va))

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    bodies, branches, calls, null_writes, critical_sites = [], {}, {}, {}, {}
    for va, (length, old_name) in SPECS.items():
        file_offset = offset(va, length)
        body = pe_data[file_offset:file_offset+length]
        decoded = list(md.disasm(body, va))
        need(decoded and sum(i.size for i in decoded) == length and
             decoded[0].address == va and decoded[-1].address+decoded[-1].size == va+length,
             "incomplete original body decode at "+hx(va))
        export = (exports / (hx(va)+".asm")).read_text(encoding="utf-8-sig")
        native = [(int(m[1], 16), m[2]) for m in
                  re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", export, re.M)]
        need(len(native) == len(decoded), "native instruction count mismatch: "+hx(va))
        for ins, (address, asm) in zip(decoded, native):
            need(ins.address == address and norm(ins.mnemonic+" "+ins.op_str) == norm(asm),
                 "native mnemonic/operand mismatch at "+hx(ins.address))
            if address in EXPECTED_SITE_OPERANDS:
                need(norm(ins.mnemonic+" "+ins.op_str) == norm(EXPECTED_SITE_OPERANDS[address]),
                     "critical operand mismatch at "+hx(address))
                critical_sites[address] = EXPECTED_SITE_OPERANDS[address]
            if ins.mnemonic.startswith("j"):
                need(len(ins.operands) == 1 and ins.operands[0].type == capstone.x86.X86_OP_IMM,
                     "indirect branch at "+hx(address))
                branches[address] = ins.operands[0].imm
            if ins.mnemonic == "call":
                need(len(ins.operands) == 1 and ins.operands[0].type == capstone.x86.X86_OP_IMM,
                     "indirect call at "+hx(address))
                calls[address] = ins.operands[0].imm
            if address in OUTPUT_TERMINATORS:
                need(ins.mnemonic == "and" and ins.operands[0].type == capstone.x86.X86_OP_MEM and
                     ins.operands[0].size == 1 and ins.operands[1].type == capstone.x86.X86_OP_IMM and
                     ins.operands[1].imm == 0, "output terminator operand mismatch at "+hx(address))
                null_writes[address] = OUTPUT_TERMINATORS[address]
        need(decoded[-1].mnemonic == "ret" and decoded[-1].op_str == "",
             "return ABI mismatch at "+hx(va))
        bodies.append({"entry_va": hx(va), "old_native_name": old_name,
                       "file_offset": hx(file_offset), "body_bytes": length,
                       "instruction_count": len(decoded), "body_sha256": sha(body),
                       "native_asm_sha256": manifest["files"][hx(va)+".asm"]["sha256"],
                       "end_exclusive_va": hx(va+length), "return_site": hx(decoded[-1].address),
                       "ret_immediate_bytes": 0, "all_native_instructions_match": True})
    need(branches == EXPECTED_BRANCHES, "branch target set mismatch")
    need(calls == EXPECTED_CALLS, "direct call target set mismatch")
    need(null_writes == OUTPUT_TERMINATORS, "output byte-zero site set mismatch")
    need(critical_sites == EXPECTED_SITE_OPERANDS, "critical operand site set mismatch")
    need(0x944CFF == 0x944C9F+96, "unexpected body separation")
    return {"schema_version": 1, "unit": "R24-C",
            "evidence_class": "complete local static PE/native mapping; no execution oracle",
            "specimen_sha256": SPECIMEN_SHA, "export_manifest_sha256": MANIFEST_SHA,
            "preflight_sha256": PREFLIGHT_SHA, "checkpoint_archive_sha256": CHECKPOINT_SHA,
            "decoder": "Capstone 5.0.7 x86-32", "address_kind": "virtual unless file_offset is explicit",
            "python_optimized_integrity": "explicit ValueError gates; no assert", "bodies": bodies,
            "branches": [{"site_va": hx(k), "target_va": hx(v)} for k,v in sorted(branches.items())],
            "calls": [{"site_va": hx(k), "target_va": hx(v),
                       **({"copy_role": OUTPUT_COPIES[k]} if k in OUTPUT_COPIES else {})}
                      for k,v in sorted(calls.items())],
            "output_byte_zero_sites": [{"site_va": hx(k), "role": v}
                                       for k,v in sorted(null_writes.items())],
            "scan_table_read": {"site_va": "00944d5c", "base_va": "00de4521",
                                "tested_bit": 4, "index": "zero-extended source byte"},
            "copy_limit_bytes": 255,
            "limits": ["No original-instruction execution oracle or TypeScript unit",
                       "Copy, strlen, formatter and finalizer callees remain transitive boundaries",
                       "No buffer-capacity, aliasing, malformed lead-byte or caller-path guarantee"]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("evidence/path-format-24-sites.json"))
    a = p.parse_args()
    result = run(a.binary, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")
    print("wrote", a.output)

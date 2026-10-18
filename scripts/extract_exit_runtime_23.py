#!/usr/bin/env python3
"""Verify R23-B complete PE bodies against the read-only checkpoint-22 export.

Output is compact address/site metadata, with no executable bytes or bulk native text.
All integrity gates are explicit and work under Python -O.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN_SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "b8d302c629ba6fbb98cb45315ee5df6f238b5b9a8e02a1c8220db3e2f384844d"
PREFLIGHT_SHA = "c7128da6c29d92931c1e096fc17112f28b73a4cd0276f7869e80a6800aee9e3a"
CHECKPOINT_SHA = "ea4c9888f34fe4282434e41a38e842cabec61ded30d064d0417a166e18f7fcc2"
SPECS = {0x945956: (153, "FUN_00945956"), 0x9459EF: (26, "FUN_009459ef")}
EXPECTED_IMPORTS = {
    0x967164: "KERNEL32.dll!ExitProcess",
    0x967168: "KERNEL32.dll!TerminateProcess",
    0x96716C: "KERNEL32.dll!GetCurrentProcess",
}
EXPECTED_BRANCHES = {
    0x945960: 0x945973, 0x945989: 0x9459C7, 0x945992: 0x9459B6,
    0x9459A0: 0x9459B5, 0x9459A6: 0x9459AA, 0x9459B3: 0x9459A2,
    0x9459DB: 0x9459ED, 0x9459F8: 0x945A07, 0x9459FE: 0x945A02,
    0x945A05: 0x9459F4,
}
EXPECTED_CALLS = {
    0x945966: ("import", 0x96716C), 0x94596D: ("import", 0x967168),
    0x9459A8: ("register", "eax"), 0x9459C0: ("local", 0x9459EF),
    0x9459D1: ("local", 0x9459EF), 0x9459E7: ("import", 0x967164),
    0x945A00: ("register", "eax"),
}
EXPECTED_WRITES = {
    0x94597D: (0xDE2FD0, 4), 0x945983: (0xDE2FCC, 1),
    0x9459E1: (0xDE2FD4, 4),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(number):
    return f"{number:08x}"


def norm(text):
    text = text.lower().strip()
    text = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0], 16)), text)
    text = re.sub(r"\s+", "", text).replace("+-", "-").replace("+0]", "]")
    # Ghidra omits the redundant DWORD marker on memory moves into EAX/ECX.
    text = re.sub(r"^(mov(?:eax|ecx|esi),)dwordptr(\[)", r"\1\2", text)
    # Ghidra uses JNZ/JZ; Capstone uses JNE/JE for the identical encodings.
    for old, new in (("jnz", "jne"), ("jz", "je"), ("jnc", "jae"), ("jc", "jb")):
        if text.startswith(old):
            text = new + text[len(old):]
    return text


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
    need(set(manifest["files"]) == {hx(va) + ext for va in (0x601070, 0x62C400, *SPECS)
                                     for ext in (".asm", ".c")}, "export inventory mismatch")
    for name, meta in manifest["files"].items():
        raw = (exports / name).read_bytes()
        need(len(raw) == meta["bytes"] and sha(raw) == meta["sha256"],
             "native export size/SHA-256 mismatch: " + name)
    prior_sites = {int(site["address"], 16): site for site in prior["sites"]}
    need(len(prior_sites) == 4, "preflight site inventory mismatch")
    for va, (length, old_name) in SPECS.items():
        need(prior_sites[va] == {"address": hx(va), "function_name": old_name,
                                "function_comment_blank": True,
                                "instruction_exists": True, "body_addresses": length},
             "exact-old preflight mismatch at " + hx(va))

    pe = struct.unpack_from("<I", pe_data, 0x3C)[0]
    need(pe_data[:2] == b"MZ" and pe_data[pe:pe+4] == b"PE\0\0", "invalid PE")
    need(struct.unpack_from("<H", pe_data, pe+4)[0] == 0x14C and
         struct.unpack_from("<H", pe_data, pe+24)[0] == 0x10B, "expected PE32 x86")
    count = struct.unpack_from("<H", pe_data, pe+6)[0]
    opt_size = struct.unpack_from("<H", pe_data, pe+20)[0]
    optional = pe + 24
    base = struct.unpack_from("<I", pe_data, optional+28)[0]
    sections = [struct.unpack_from("<8sIIII", pe_data, optional+opt_size+40*n)
                for n in range(count)]

    def offset(va, size):
        for _, virtual_size, rva, raw_size, raw_off in sections:
            delta = va - base - rva
            if 0 <= delta and delta + size <= min(virtual_size, raw_size):
                return raw_off + delta
        raise ValueError("VA not raw-backed: " + hx(va))

    def read_va(va, size):
        off = offset(va, size)
        return pe_data[off:off+size]

    def u32_va(va):
        return struct.unpack("<I", read_va(va, 4))[0]

    def c_string(va):
        data = pe_data[offset(va, 1):offset(va, 1)+256]
        end = data.find(b"\0")
        need(end >= 0, "unterminated PE import string")
        return data[:end].decode("ascii")

    # Parse import descriptors and IAT slots from the original PE data directory.
    import_rva = struct.unpack_from("<I", pe_data, optional+104)[0]
    need(import_rva != 0, "missing import directory")
    imports = {}
    for desc in range(256):
        rva = import_rva + 20*desc
        original, _, _, dll_name, first_thunk = struct.unpack("<IIIII", read_va(base+rva, 20))
        if not any((original, dll_name, first_thunk)):
            break
        dll = c_string(base+dll_name)
        thunk_rva = original or first_thunk
        for n in range(4096):
            thunk = u32_va(base+thunk_rva+4*n)
            if thunk == 0:
                break
            name = "#" + str(thunk & 0xFFFF) if thunk & 0x80000000 else c_string(base+thunk+2)
            imports[base+first_thunk+4*n] = dll + "!" + name
        else:
            raise ValueError("unterminated import thunk array")
    else:
        raise ValueError("unterminated import descriptor array")
    need({slot: imports.get(slot) for slot in EXPECTED_IMPORTS} == EXPECTED_IMPORTS,
         "import IAT identity mismatch")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    result_bodies = []
    seen_branches, seen_calls, seen_writes = {}, {}, {}
    for va, (length, old_name) in SPECS.items():
        body = read_va(va, length)
        decoded = list(md.disasm(body, va))
        need(decoded and sum(i.size for i in decoded) == length and
             decoded[0].address == va and decoded[-1].address+decoded[-1].size == va+length,
             "incomplete original body decode at " + hx(va))
        export = (exports / (hx(va)+".asm")).read_text(encoding="utf-8-sig")
        native = [(int(m[1], 16), m[2]) for m in
                  re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", export, re.M)]
        need(len(native) == len(decoded), "native instruction count mismatch: " + hx(va))
        for ins, (address, asm) in zip(decoded, native):
            need(ins.address == address and norm(ins.mnemonic+" "+ins.op_str) == norm(asm),
                 "native mnemonic/operand mismatch at " + hx(ins.address))
            if ins.mnemonic.startswith("j"):
                need(len(ins.operands) == 1 and ins.operands[0].type == capstone.x86.X86_OP_IMM,
                     "nonlocal/indirect branch at " + hx(address))
                seen_branches[address] = ins.operands[0].imm
            if ins.mnemonic == "call":
                operand = ins.operands[0]
                if operand.type == capstone.x86.X86_OP_IMM:
                    seen_calls[address] = ("local", operand.imm)
                elif operand.type == capstone.x86.X86_OP_REG:
                    seen_calls[address] = ("register", ins.reg_name(operand.reg))
                elif operand.type == capstone.x86.X86_OP_MEM:
                    need(operand.mem.base == 0 and operand.mem.index == 0,
                         "unexpected import call addressing at " + hx(address))
                    seen_calls[address] = ("import", operand.mem.disp)
                else:
                    raise ValueError("unexpected call addressing at " + hx(address))
            if len(ins.operands) >= 2 and ins.mnemonic == "mov" and ins.operands[0].type == capstone.x86.X86_OP_MEM:
                mem = ins.operands[0].mem
                if mem.base == 0 and mem.index == 0:
                    seen_writes[address] = (mem.disp, ins.operands[0].size)
        need(decoded[-1].mnemonic == "ret" and decoded[-1].op_str == "", "return mismatch")
        result_bodies.append({
            "entry_va": hx(va), "old_native_name": old_name,
            "file_offset": hx(offset(va, length)), "body_bytes": length,
            "instruction_count": len(decoded), "body_sha256": sha(body),
            "native_asm_sha256": manifest["files"][hx(va)+".asm"]["sha256"],
            "range_end_exclusive_va": hx(va+length), "all_native_instructions_match": True,
            "return_site": hx(decoded[-1].address), "ret_immediate_bytes": 0,
        })
    need(seen_branches == EXPECTED_BRANCHES, "branch target set mismatch")
    need(seen_calls == EXPECTED_CALLS, "direct/indirect call set mismatch")
    need(seen_writes == EXPECTED_WRITES, "direct global write set mismatch")
    need(0x9459EF == 0x945956+153 and 0x945A09 == 0x9459EF+26,
         "body adjacency mismatch")
    # Explicitly pin the status reads and exit-mode argument tests. Their precise
    # operands are already checked above; these site identities protect summary.
    for first, last in ((0x9870BC, 0x9870C4), (0x9870C8, 0x9870D0)):
        offset(first, last-first)
    return {
        "schema_version": 1, "unit": "R23-B", "evidence_class": "complete local static PE/native mapping; no execution oracle",
        "specimen_sha256": SPECIMEN_SHA, "export_manifest_sha256": MANIFEST_SHA,
        "preflight_sha256": PREFLIGHT_SHA, "checkpoint_archive_sha256": CHECKPOINT_SHA,
        "decoder": "Capstone 5.0.7 x86-32", "address_kind": "virtual unless file_offset is explicit",
        "python_optimized_integrity": "explicit ValueError gates; no assert", "bodies": result_bodies,
        "branches": [{"site_va": hx(site), "target_va": hx(target)} for site, target in sorted(seen_branches.items())],
        "calls": [{"site_va": hx(site), "kind": kind,
                   "target": hx(target) if isinstance(target, int) else target,
                   **({"import_identity": imports[target]} if kind == "import" else {})}
                  for site, (kind, target) in sorted(seen_calls.items())],
        "direct_nonframe_writes": [{"site_va": hx(site), "address_va": hx(address), "width_bytes": width}
                                   for site, (address, width) in sorted(seen_writes.items())],
        "callback_table_ranges": [
            {"start_va": "009870bc", "end_exclusive_va": "009870c4", "slots": 2},
            {"start_va": "009870c8", "end_exclusive_va": "009870d0", "slots": 2}],
        "limits": ["No original-instruction execution oracle or TypeScript unit",
                   "Imported API and callback return/nonreturn and side effects are boundaries",
                   "No guaranteed process termination under all environments"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/exit-runtime-23-sites.json"))
    args = parser.parse_args()
    result = run(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")
    print("wrote", args.output)

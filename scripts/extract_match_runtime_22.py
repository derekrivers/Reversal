#!/usr/bin/env python3
"""Verify R22-D complete local PE bodies against pinned read-only Ghidra exports.

Retains compact site metadata only, not executable bytes or bulk native exports.
Every integrity check is explicit and active under python -O.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN_SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "81e524e19f5a48da5feb994b1c49aeb7a54483983eb21cf6645595b19950f401"
PREFLIGHT_SHA = "239bc3cbef548589d959c9cc123726b5f910d0f48873c4b627aaef94640eb27d"
CHECKPOINT_SHA = "bf4e1739d0c1ab1780fca5f95ec9bf0f9447d7cbe28520366a79aa36b6cc5971"
SPECS = {0x5A8F60: (1, 1), 0x90D130: (6, 2), 0x945640: (39, 15), 0x945934: (17, 6)}
OLD_NAMES = {0x5A8F60: "FUN_005a8f60", 0x90D130: "FUN_0090d130",
             0x945640: "__ftol", 0x945934: "FUN_00945934"}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(number):
    return f"{number:08x}"


def normalized(text):
    text = text.lower().strip()
    text = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m.group(), 16)), text)
    text = re.sub(r"\s+", "", text).replace("+-", "-").replace("+0]", "]")
    return text


def run(binary, exports, preflight):
    require(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    pe_data = binary.read_bytes()
    require(sha(pe_data) == SPECIMEN_SHA, "specimen SHA-256 mismatch")
    manifest_raw = (exports / "manifest.json").read_bytes()
    preflight_raw = preflight.read_bytes()
    require(sha(manifest_raw) == MANIFEST_SHA, "export manifest SHA-256 mismatch")
    require(sha(preflight_raw) == PREFLIGHT_SHA, "annotation preflight SHA-256 mismatch")
    manifest, prior = json.loads(manifest_raw), json.loads(preflight_raw)
    require(manifest["specimen_sha256"] == prior["sha256"] == SPECIMEN_SHA,
            "input specimen metadata mismatch")
    require(manifest["preflight_sha256"] == PREFLIGHT_SHA and
            manifest["checkpoint_archive_sha256"] == CHECKPOINT_SHA,
            "native checkpoint/preflight mismatch")
    expected_files = {hx(va) + "." + ext for va in SPECS for ext in ("asm", "c")}
    require(set(manifest["files"]) == expected_files, "native file inventory mismatch")
    for name, metadata in manifest["files"].items():
        raw = (exports / name).read_bytes()
        require(len(raw) == metadata["bytes"] and sha(raw) == metadata["sha256"],
                "native export size/hash mismatch: " + name)
    require(len(prior["sites"]) == len(SPECS), "preflight site count mismatch")
    sites = {int(s["address"], 16): s for s in prior["sites"]}
    require(set(sites) == set(SPECS), "preflight address set mismatch")

    pe = struct.unpack_from("<I", pe_data, 0x3c)[0]
    require(pe_data[:2] == b"MZ" and pe_data[pe:pe + 4] == b"PE\0\0", "invalid PE")
    require(struct.unpack_from("<H", pe_data, pe + 4)[0] == 0x14c and
            struct.unpack_from("<H", pe_data, pe + 24)[0] == 0x10b, "expected PE32 x86")
    base = struct.unpack_from("<I", pe_data, pe + 24 + 28)[0]
    section_count = struct.unpack_from("<H", pe_data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", pe_data, pe + 20)[0]
    sections = [struct.unpack_from("<8sIIII", pe_data, pe + 24 + optional_size + 40*n)
                for n in range(section_count)]

    def read(va, length):
        for _, virtual_size, rva, raw_size, raw_offset in sections:
            delta = va - base - rva
            if 0 <= delta and delta + length <= min(virtual_size, raw_size):
                return raw_offset + delta, pe_data[raw_offset + delta:raw_offset + delta + length]
        raise ValueError("VA range not raw-backed: " + hx(va))

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    bodies = []
    for va, (length, expected_instructions) in SPECS.items():
        old = sites[va]
        require(old["instruction_exists"] and old["function_name"] == OLD_NAMES[va] and
                old["body_addresses"] == length, "exact-old preflight mismatch: " + hx(va))
        require(old["function_comment_blank"] == (va != 0x945640),
                "old-comment status mismatch: " + hx(va))
        offset, raw = read(va, length)
        decoded = list(md.disasm(raw, va))
        # Capstone exposes WAIT;FNSTCW separately; Ghidra prints the paired
        # WAIT-prefixed form as one FSTCW instruction starting at the WAIT byte.
        if va == 0x945640:
            require(decoded[3].address == 0x945646 and decoded[3].mnemonic == "wait" and
                    decoded[4].address == 0x945647 and decoded[4].mnemonic == "fnstcw",
                    "unexpected x87 WAIT/FNSTCW encoding")
            class WaitFstcw:
                address = decoded[3].address
                size = decoded[3].size + decoded[4].size
                mnemonic = "fstcw"
                op_str = decoded[4].op_str
            instructions = decoded[:3] + [WaitFstcw()] + decoded[5:]
        else:
            instructions = decoded
        require(len(instructions) == expected_instructions and
                sum(i.size for i in instructions) == length and
                instructions[-1].address + instructions[-1].size == va + length,
                "incomplete/changed body decode: " + hx(va))
        export = (exports / (hx(va) + ".asm")).read_text(encoding="utf-8-sig")
        native = [(int(m.group(1), 16), m.group(2)) for m in
                  re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", export, re.M)]
        require(len(native) == len(instructions), "native instruction count mismatch: " + hx(va))
        for instruction, (address, asm) in zip(instructions, native):
            require(instruction.address == address and
                    normalized(instruction.mnemonic + " " + instruction.op_str) == normalized(asm),
                    "native mnemonic/operand mismatch at " + hx(instruction.address))
        require(all(i.mnemonic != "jmp" and not i.mnemonic.startswith("j") for i in instructions),
                "unexpected branch: " + hx(va))
        require(instructions[-1].mnemonic == "ret" and instructions[-1].op_str == "" and
                all(i.mnemonic != "ret" for i in instructions[:-1]),
                "unexpected return: " + hx(va))
        calls = [i for i in instructions if i.mnemonic == "call"]
        expected_calls = {0x5A8F60: [], 0x90D130: [], 0x945640: [],
                          0x945934: [(0x94593c, 0x945956)]}[va]
        require([(i.address, i.operands[0].imm) for i in calls] == expected_calls and
                all(i.operands[0].type == capstone.x86.X86_OP_IMM for i in calls),
                "unexpected callee: " + hx(va))
        # Selected sites preserve the local contract without retaining full original assembly.
        selected = [i for i in instructions if i.mnemonic in
                    ("call", "fstcw", "wait", "fldcw", "fistp", "or", "ret")]
        if va == 0x90D130:
            require(instructions[0].mnemonic == "mov" and
                    instructions[0].operands[1].type == capstone.x86.X86_OP_IMM,
                    "version pointer instruction mismatch")
            pointer = instructions[0].operands[1].imm
            require(pointer == 0xAD4394, "version pointer VA mismatch")
        bodies.append({
            "entry_va": hx(va), "old_native_name": OLD_NAMES[va],
            "body_bytes": length, "instruction_count": len(instructions),
            "file_offset": f"{offset:08x}", "body_sha256": sha(raw),
            "range_end_exclusive_va": hx(va + length),
            "native_asm_sha256": manifest["files"][hx(va) + ".asm"]["sha256"],
            "all_native_instructions_match": True,
            "branch_sites": [], "direct_call_sites": [
                {"site": hx(i.address), "target": hx(i.operands[0].imm)} for i in calls],
            "return_site": hx(instructions[-1].address), "ret_immediate_bytes": 0,
            "selected_sites": [{"address": hx(i.address), "mnemonic": i.mnemonic,
                                "operand": i.op_str} for i in selected],
        })
    # The MOV immediate in 0090d130 is a pointer, not a read of the string bytes.
    _, string_region = read(pointer, 32)
    nul = string_region.find(b"\0")
    require(nul >= 0, "unterminated version string in inspected range")
    version = string_region[:nul].decode("ascii")
    require(version == "3.9.68", "version pointer content mismatch")
    return {
        "schema_version": 1, "unit": "R22-D", "evidence_class": "complete local static PE/native mapping; no execution oracle",
        "specimen_sha256": SPECIMEN_SHA, "export_manifest_sha256": MANIFEST_SHA,
        "preflight_sha256": PREFLIGHT_SHA, "checkpoint_archive_sha256": CHECKPOINT_SHA,
        "decoder": "Capstone 5.0.7 x86-32", "address_kind": "virtual unless file_offset is explicit",
        "python_optimized_integrity": "explicit ValueError gates; no assert",
        "bodies": bodies,
        "pointer_target": {"address_va": hx(pointer), "string_length_bytes": len(version),
                           "string_sha256": sha(string_region[:nul]), "semantic": "ASCII 3.9.68; not read by 0090d130"},
        "limits": ["No transitive 00945956 effects or imported API behavior",
                   "No x87 execution/exception/numeric precision validation",
                   "No connected selection, match, UI or game equivalence"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/match-runtime-22-sites.json"))
    args = parser.parse_args()
    result = run(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("wrote", args.output)

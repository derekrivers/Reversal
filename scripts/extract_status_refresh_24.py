#!/usr/bin/env python3
"""Check the complete 0062c680 PE body against checkpoint-23 native export."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "c3770d9a3b8b99d80454413ea5ec85114aa0f3baa9ec0c661567c30d7bf40e70"
PREFLIGHT = "1df62ffab8859fa6d1b86e486a26f10f82c82827eb08356caae3ce916694a193"
ARCHIVE = "9cb03ce3740e5529a2f6155aa20b1a61ea4ba321c6d3520e1c91525782703f52"
START, LENGTH = 0x0062C680, 1909


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(value):
    return f"{value:08x}"


def normalized(value):
    value = value.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    # Ghidra omits redundant widths when the register fixes the memory size.
    # Operand widths are separately retained from the original decode.
    for width in ("dword ptr", "qword ptr", "byte ptr", "word ptr"):
        value = value.replace(width, "")
    value = re.sub(r"0x[0-9a-f]+", lambda m: str((int(m[0], 16) + 0x80000000) % 0x100000000 - 0x80000000), value)
    value = re.sub(r"\s+", "", value).replace("*1", "").replace("+-", "-").replace("+0]", "]")
    value = re.sub(r"st\(([0-7])\)", r"st\1", value)
    for old, new in (("jnz", "jne"), ("jz", "je"), ("jnc", "jae"), ("jc", "jb"), ("setnz", "setne"), ("setz", "sete")):
        if value.startswith(old):
            value = new + value[len(old):]
    return value


def extract(binary_path, exports, preflight):
    binary = binary_path.read_bytes()
    need(len(binary) == 7192576 and sha(binary) == SPECIMEN, "specimen size/SHA-256 mismatch")
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    manifest_raw, preflight_raw = (exports / "manifest.json").read_bytes(), preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST and sha(preflight_raw) == PREFLIGHT, "native manifest/preflight SHA-256 mismatch")
    manifest, native = json.loads(manifest_raw), json.loads(preflight_raw)
    need(manifest["specimen_sha256"] == native["sha256"] == SPECIMEN, "native specimen metadata mismatch")
    need(manifest["preflight_sha256"] == PREFLIGHT and manifest["checkpoint_archive_sha256"] == ARCHIVE,
         "native checkpoint metadata mismatch")
    need({"0062c680.asm", "0062c680.c"}.issubset(manifest["files"]), "native export file set missing body")
    for name in ("0062c680.asm", "0062c680.c"):
        meta = manifest["files"][name]
        payload = (exports / name).read_bytes()
        need(len(payload) == meta["bytes"] and sha(payload) == meta["sha256"], "native export mismatch: " + name)
    need({"address": hx(START), "function_name": "cm0102_refresh_player_status_row_candidate", "function_comment_blank": False,
          "instruction_exists": True, "body_addresses": LENGTH} in native["sites"], "exact-old native preflight mismatch")

    need(binary[:2] == b"MZ", "MZ header missing")
    pe = struct.unpack_from("<I", binary, 0x3C)[0]
    need(binary[pe:pe+4] == b"PE\0\0" and struct.unpack_from("<H", binary, pe+4)[0] == 0x14C, "expected x86 PE")
    optional = pe + 24
    need(struct.unpack_from("<H", binary, optional)[0] == 0x10B, "expected PE32")
    base = struct.unpack_from("<I", binary, optional+28)[0]
    nsec, optlen = struct.unpack_from("<H", binary, pe+6)[0], struct.unpack_from("<H", binary, pe+20)[0]
    sections = [struct.unpack_from("<IIII", binary, optional+optlen+40*n+8)[1:] for n in range(nsec)]

    def offset(va, size):
        for rva, raw_size, raw_ptr in sections:
            delta = va - base - rva
            if 0 <= delta and delta+size <= raw_size:
                return raw_ptr+delta
        raise ValueError("VA range not backed by PE raw section")

    file_offset = offset(START, LENGTH)
    body = binary[file_offset:file_offset+LENGTH]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    instructions = list(md.disasm(body, START))
    need(sum(i.size for i in instructions) == LENGTH and instructions[-1].address+instructions[-1].size == START+LENGTH,
         "incomplete original-body decode")
    asm = (exports / "0062c680.asm").read_text(encoding="utf-8-sig")
    rows = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", asm, re.M)]
    need(len(rows) == len(instructions), "native/original instruction count mismatch")
    for ins, (address, native_text) in zip(instructions, rows):
        need(ins.address == address and normalized(ins.mnemonic+" "+ins.op_str) == normalized(native_text),
             "native/original operand mismatch at " + hx(ins.address) + ": " + ins.mnemonic + " " + ins.op_str + " versus " + native_text)
        # Check native explicit memory widths as well as canonicalized operands.
        native_widths = [4 if width == "float" else 8 if width == "double" else
                         {"byte": 1, "word": 2, "dword": 4, "qword": 8}[width]
                         for width in re.findall(r"\b(byte|word|dword|qword|float|double) ptr\b", native_text.lower())]
        decoded_widths = [op.size for op in ins.operands if op.type == CS_OP_MEM]
        need(native_widths == decoded_widths[:len(native_widths)],
             "native/original operand width mismatch at " + hx(ins.address))

    starts = {i.address for i in instructions}
    def successors(ins):
        if ins.mnemonic == "ret":
            return []
        fall = ins.address+ins.size
        if ins.mnemonic.startswith("j"):
            need(ins.operands[0].type == CS_OP_IMM, "indirect branch")
            return [ins.operands[0].imm] + ([] if ins.mnemonic == "jmp" else [fall])
        return [fall]
    edges = {i.address: successors(i) for i in instructions}
    need(all(t in starts for targets in edges.values() for t in targets), "local CFG escapes body")
    seen, pending = set(), [START]
    while pending:
        site = pending.pop()
        if site in seen:
            continue
        seen.add(site)
        pending.extend(edges[site])
    need(seen == starts, "unreachable native instruction in complete body")

    branches = [[hx(i.address), i.mnemonic, [hx(t) for t in edges[i.address]]] for i in instructions if i.mnemonic.startswith("j")]
    calls = defaultdict(list)
    reads, writes = [], []
    for ins in instructions:
        if ins.mnemonic == "call":
            need(ins.operands[0].type == CS_OP_IMM, "unexpected indirect call")
            calls[hx(ins.operands[0].imm)].append(hx(ins.address))
        for op in ins.operands:
            if op.type != CS_OP_MEM or ins.mnemonic == "lea":
                continue
            descriptor = [hx(ins.address), ins.mnemonic, op.size, ins.op_str]
            if op.access & capstone.CS_AC_READ:
                reads.append(descriptor)
            if op.access & capstone.CS_AC_WRITE:
                writes.append(descriptor)
    returns = [[hx(i.address), int(i.op_str or "0", 0)] for i in instructions if i.mnemonic == "ret"]
    need([x[0] for x in returns] == ["0062cdf2"], "return sites changed")
    need(len(instructions) == 562 and len(branches) == 69 and sum(map(len, calls.values())) == 27,
         "body site census changed")
    need(set(calls) == {"00417c10", "0054a110", "0054cc30", "0054cdb0", "0062e700",
                        "00669bd0", "0076d780", "0076e040", "0090cfc0", "00945640", "0094627a"},
         "direct call targets changed")
    need([x[0] for x in writes if "[esp" not in x[3]] ==
         ["0062c68e", "0062c6c2", "0062c6ed", "0062c71a", "0062c7d8", "0062c98d",
          "0062c99a", "0062ca76", "0062cdd3", "0062cdd7", "0062cde8"],
         "direct nonframe write sites changed")
    return {"work_unit": "R24-A", "specimen_sha256": SPECIMEN,
            "checkpoint_archive_sha256": ARCHIVE, "export_manifest_sha256": MANIFEST,
            "annotation_preflight_sha256": PREFLIGHT, "entry_va": hx(START),
            "file_offset": f"0x{file_offset:x}", "body_bytes": LENGTH, "body_sha256": sha(body),
            "instruction_count": len(instructions), "all_original_and_native_instructions_match": True,
            "branches": branches, "direct_calls": [{"target": a, "sites": sites} for a, sites in sorted(calls.items())],
            "memory_reads": reads, "memory_writes": writes, "returns": returns,
            "native_export_hashes": {ext: manifest["files"]["0062c680."+ext]["sha256"] for ext in ("asm", "c")},
            "scope": "complete local body; transitive callee effects unresolved",
            "integrity_under_python_optimized_mode": "explicit ValueError gates"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = extract(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")

#!/usr/bin/env python3
"""Check the complete 0062c400 PE body against checkpoint-22 native export."""
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
MANIFEST = "b8d302c629ba6fbb98cb45315ee5df6f238b5b9a8e02a1c8220db3e2f384844d"
PREFLIGHT = "c7128da6c29d92931c1e096fc17112f28b73a4cd0276f7869e80a6800aee9e3a"
ARCHIVE = "ea4c9888f34fe4282434e41a38e842cabec61ded30d064d0417a166e18f7fcc2"
START, LENGTH = 0x0062C400, 271


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(value):
    return f"{value:08x}"


def normalized(value):
    value = value.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    # Ghidra omits redundant DWORD widths where the register fixes them.
    value = value.replace("dword ptr", "")
    value = re.sub(r"0x[0-9a-f]+", lambda m: str((int(m[0], 16) + 0x80000000) % 0x100000000 - 0x80000000), value)
    value = re.sub(r"\s+", "", value).replace("*1", "").replace("+-", "-").replace("+0]", "]")
    for old, new in (("jnz", "jne"), ("jz", "je"), ("setnz", "setne"), ("setz", "sete")):
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
    need({"0062c400.asm", "0062c400.c"}.issubset(manifest["files"]), "native export file set missing body")
    for name in ("0062c400.asm", "0062c400.c"):
        meta = manifest["files"][name]
        payload = (exports / name).read_bytes()
        need(len(payload) == meta["bytes"] and sha(payload) == meta["sha256"], "native export mismatch: " + name)
    need({"address": hx(START), "function_name": "FUN_" + hx(START), "function_comment_blank": True,
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
    asm = (exports / "0062c400.asm").read_text(encoding="utf-8-sig")
    rows = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", asm, re.M)]
    need(len(rows) == len(instructions), "native/original instruction count mismatch")
    for ins, (address, native_text) in zip(instructions, rows):
        need(ins.address == address and normalized(ins.mnemonic+" "+ins.op_str) == normalized(native_text),
             "native/original operand mismatch at " + hx(ins.address))

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
    need([x[0] for x in returns] == ["0062c47b", "0062c4f8", "0062c50c"], "return sites changed")
    need(set(calls) == {"0054cc30", "005e8290", "0062c680", "0090d130", "00944c9f", "00944cff"}, "call targets changed")
    need([x[0] for x in writes if "[esp" not in x[3]] == ["0062c46b"], "direct nonframe write sites changed")
    return {"work_unit": "R23-A", "specimen_sha256": SPECIMEN,
            "checkpoint_archive_sha256": ARCHIVE, "export_manifest_sha256": MANIFEST,
            "annotation_preflight_sha256": PREFLIGHT, "entry_va": hx(START),
            "file_offset": f"0x{file_offset:x}", "body_bytes": LENGTH, "body_sha256": sha(body),
            "instruction_count": len(instructions), "all_original_and_native_instructions_match": True,
            "branches": branches, "direct_calls": [{"target": a, "sites": sites} for a, sites in sorted(calls.items())],
            "memory_reads": reads, "memory_writes": writes, "returns": returns,
            "native_export_hashes": {ext: manifest["files"]["0062c400."+ext]["sha256"] for ext in ("asm", "c")},
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

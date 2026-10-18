#!/usr/bin/env python3
"""Check the complete 00601070 body against the pinned PE and restored Ghidra export.

Only site metadata and hashes are published. All gates remain active under -O.
"""
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
START, LENGTH = 0x00601070, 399


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(value):
    return f"{value:08x}"


def normalized(text):
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    text = re.sub(r"0x[0-9a-f]+", lambda m: str((int(m[0], 16) + 0x80000000) % 0x100000000 - 0x80000000), text)
    text = re.sub(r"\s+", "", text).replace("*1", "").replace("+-", "-").replace("+0]", "]")
    for old, new in (("jnz", "jne"), ("jz", "je")):
        if text.startswith(old):
            text = new + text[len(old):]
    return text


def extract(binary_path, exports, preflight):
    raw = binary_path.read_bytes()
    need(len(raw) == 7192576 and sha(raw) == SPECIMEN, "specimen size/SHA-256 mismatch")
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    manifest_raw, preflight_raw = (exports / "manifest.json").read_bytes(), preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST, "native manifest SHA-256 mismatch")
    need(sha(preflight_raw) == PREFLIGHT, "preflight SHA-256 mismatch")
    manifest, old = json.loads(manifest_raw), json.loads(preflight_raw)
    need(manifest["specimen_sha256"] == old["sha256"] == SPECIMEN, "metadata specimen mismatch")
    need(manifest["preflight_sha256"] == PREFLIGHT and manifest["checkpoint_archive_sha256"] == ARCHIVE,
         "checkpoint/preflight metadata mismatch")
    need(set(manifest["files"]) == {hx(v) + "." + ext for v in (0x00601070, 0x0062c400, 0x00945956, 0x009459ef) for ext in ("asm", "c")},
         "unexpected export file set")
    for name, info in manifest["files"].items():
        payload = (exports / name).read_bytes()
        need(len(payload) == info["bytes"] and sha(payload) == info["sha256"], "native export changed: " + name)
    row = [s for s in old["sites"] if s["address"] == hx(START)]
    need(len(row) == 1 and row[0] == {"address": hx(START), "function_name": "FUN_" + hx(START),
         "function_comment_blank": True, "instruction_exists": True, "body_addresses": LENGTH},
         "exact-old preflight mismatch")

    need(raw[:2] == b"MZ", "MZ header missing")
    pe = struct.unpack_from("<I", raw, 0x3c)[0]
    need(raw[pe:pe + 4] == b"PE\0\0" and struct.unpack_from("<H", raw, pe + 4)[0] == 0x14c,
         "expected x86 PE")
    optional = pe + 24
    need(struct.unpack_from("<H", raw, optional)[0] == 0x10b, "expected PE32")
    image_base = struct.unpack_from("<I", raw, optional + 28)[0]
    count, opt_size = struct.unpack_from("<H", raw, pe + 6)[0], struct.unpack_from("<H", raw, pe + 20)[0]
    sections = [struct.unpack_from("<IIII", raw, optional + opt_size + 40 * n + 8)[1:] for n in range(count)]

    def offset(va, size):
        for rva, raw_size, raw_ptr in sections:
            delta = va - image_base - rva
            if 0 <= delta and delta + size <= raw_size:
                return raw_ptr + delta
        raise ValueError("VA range not PE raw-section-backed: " + hx(va))

    body = raw[offset(START, LENGTH):offset(START, LENGTH) + LENGTH]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    insns = list(md.disasm(body, START))
    need(sum(i.size for i in insns) == LENGTH and insns[0].address == START and
         insns[-1].address + insns[-1].size == START + LENGTH, "incomplete body decode")
    native_text = (exports / (hx(START) + ".asm")).read_text(encoding="utf-8-sig")
    native = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", native_text, re.M)]
    need(len(native) == len(insns), "native instruction count mismatch")
    for ins, (address, asm) in zip(insns, native):
        need(ins.address == address and normalized(ins.mnemonic + " " + ins.op_str) == normalized(asm),
             "native operand mismatch at " + hx(ins.address))
    starts = {i.address for i in insns}

    def edges(ins):
        if ins.mnemonic == "ret":
            return []
        fall = ins.address + ins.size
        if ins.mnemonic.startswith("j"):
            need(ins.operands[0].type == CS_OP_IMM, "indirect branch")
            return [ins.operands[0].imm] + ([] if ins.mnemonic == "jmp" else [fall])
        return [fall]

    need(all(e in starts for i in insns for e in edges(i)), "branch/fallthrough escapes body")
    by_address = {i.address: i for i in insns}
    seen, pending = set(), [START]
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        seen.add(address)
        pending.extend(edges(by_address[address]))
    need(seen == starts, "unreachable native instruction")
    calls = defaultdict(list)
    reads, writes, branches = [], [], []
    for i in insns:
        if i.mnemonic == "call":
            need(i.operands[0].type == CS_OP_IMM, "indirect call")
            calls[hx(i.operands[0].imm)].append(hx(i.address))
        if i.mnemonic.startswith("j"):
            branches.append([hx(i.address), i.mnemonic, [hx(v) for v in edges(i)]])
        for op in i.operands:
            if op.type != CS_OP_MEM or i.mnemonic == "lea":
                continue
            site = [hx(i.address), i.mnemonic, op.size, i.op_str]
            if op.access & capstone.CS_AC_READ:
                reads.append(site)
            if op.access & capstone.CS_AC_WRITE:
                writes.append(site)
    returns = [[hx(i.address), int(i.op_str or "0", 0)] for i in insns if i.mnemonic == "ret"]
    need(returns == [["00601163", 8], ["006011fc", 8]], "RET site/width changed")
    need(set(calls) == {"005e8290", "0090d130", "00944c9f", "00944cff"}, "callee set changed")
    need(not [w for w in writes if not ("esp" in w[3].lower() or w[0] == "006011ec")], "unexpected nonframe store")
    return {"work_unit": "R23-C", "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": ARCHIVE,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "entry_va": hx(START), "file_offset": f"0x{offset(START, LENGTH):x}", "body_bytes": LENGTH,
            "body_sha256": sha(body), "instruction_count": len(insns), "all_pe_instructions_match_native_operands": True,
            "branches": branches, "direct_calls": [{"target": k, "sites": v} for k, v in sorted(calls.items())],
            "memory_reads": reads, "memory_writes": writes, "returns": returns,
            "native_export_hashes": {ext: manifest["files"][hx(START) + "." + ext]["sha256"] for ext in ("asm", "c")},
            "scope": "complete local static body; callee effects unresolved",
            "integrity_under_python_optimized_mode": "explicit ValueError gates"}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = extract(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")

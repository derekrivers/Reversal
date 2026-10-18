#!/usr/bin/env python3
"""Verify R22-A complete local bodies against the pinned PE and native export.

Only compact sites and digests are written. Integrity checks remain active with -O.
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
MANIFEST = "a73c3300131cc5162d3f0122dd04d622fe6581505cea12c499ad4794ce79e239"
PREFLIGHT = "16760db81594c51f88b877aa98a8703ccbcc928a9fae7cad935e32ced6c8d5fe"
BODIES = {0x0062c3d0: 36, 0x0062c590: 198}


def need(test, why):
    if not test:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(value):
    return f"{value:08x}"


def normalized(text):
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    text = re.sub(r"0x[0-9a-f]+", lambda m: str((int(m[0], 16)+0x80000000) % 0x100000000-0x80000000), text)
    text = re.sub(r"\s+", "", text).replace("*1", "").replace("+-", "-").replace("+0]", "]")
    for a, b in (("jnz", "jne"), ("jz", "je")):
        if text.startswith(a):
            text = b + text[len(a):]
    return text


def extract(binary_path, exports, preflight):
    binary = binary_path.read_bytes()
    need(sha(binary) == SPECIMEN, "specimen SHA-256 mismatch")
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    manifest_raw = (exports / "manifest.json").read_bytes()
    preflight_raw = preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST, "native manifest SHA-256 mismatch")
    need(sha(preflight_raw) == PREFLIGHT, "preflight SHA-256 mismatch")
    manifest = json.loads(manifest_raw)
    native = json.loads(preflight_raw)
    need(manifest["specimen_sha256"] == native["sha256"] == SPECIMEN, "metadata specimen mismatch")
    need(manifest["preflight_sha256"] == PREFLIGHT, "manifest preflight mismatch")
    need(set(manifest["files"]) == {hx(a)+"."+ext for a in BODIES for ext in ("asm", "c")}, "export file set mismatch")
    for name, item in manifest["files"].items():
        raw = (exports/name).read_bytes()
        need(len(raw) == item["bytes"] and sha(raw) == item["sha256"], "native export mismatch: "+name)
    pe = struct.unpack_from("<I", binary, 0x3c)[0]
    need(binary[:2] == b"MZ" and binary[pe:pe+4] == b"PE\0\0", "invalid PE signature")
    need(struct.unpack_from("<H", binary, pe+4)[0] == 0x14c, "not x86")
    optional = pe+24
    need(struct.unpack_from("<H", binary, optional)[0] == 0x10b, "not PE32")
    image_base = struct.unpack_from("<I", binary, optional+28)[0]
    nsec = struct.unpack_from("<H", binary, pe+6)[0]
    section_start = optional+struct.unpack_from("<H", binary, pe+20)[0]
    sections = [struct.unpack_from("<IIII", binary, section_start+40*n+8)[1:] for n in range(nsec)]
    def offset(va, size):
        for rva, raw_size, raw_ptr in sections:
            delta = va-image_base-rva
            if delta >= 0 and delta+size <= raw_size:
                return raw_ptr+delta
        raise ValueError("VA range not backed by PE raw section")
    def raw(va, size):
        o = offset(va, size)
        return binary[o:o+size]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    output = []
    for start, size in BODIES.items():
        matched = [row for row in native["sites"] if row["address"] == hx(start)]
        need(len(matched) == 1 and matched[0]["function_name"] == "FUN_"+hx(start) and matched[0]["instruction_exists"], "old annotation mismatch")
        need(matched[0]["function_comment_blank"] and matched[0]["body_addresses"] == size, "preflight body/comment mismatch")
        body = raw(start, size)
        decoded = list(md.disasm(body, start))
        need(sum(i.size for i in decoded) == size, "incomplete PE decode")
        native_rows = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", (exports/(hx(start)+".asm")).read_text(encoding="utf-8-sig"), re.M)]
        need(len(decoded) == len(native_rows), "native instruction count mismatch")
        for ins, (address, asm) in zip(decoded, native_rows):
            need(ins.address == address and normalized(ins.mnemonic+" "+ins.op_str) == normalized(asm), "native operand mismatch at "+hx(ins.address))
        starts = {i.address for i in decoded}
        def nexts(ins):
            if ins.mnemonic == "ret":
                return []
            fall = ins.address+ins.size
            if ins.mnemonic.startswith("j"):
                need(ins.operands[0].type == CS_OP_IMM, "indirect local branch")
                return [ins.operands[0].imm] + ([] if ins.mnemonic == "jmp" else [fall])
            return [fall]
        branches = [[hx(i.address), i.mnemonic, [hx(v) for v in nexts(i)]] for i in decoded if i.mnemonic.startswith("j")]
        need(all(v in starts for i in decoded for v in nexts(i)), "CFG escapes local body")
        by_address = {i.address:i for i in decoded}
        seen, pending = set(), [start]
        while pending:
            address = pending.pop()
            if address in seen:
                continue
            seen.add(address)
            pending.extend(nexts(by_address[address]))
        need(seen == starts, "unreachable PE instruction in native body")
        calls = defaultdict(list)
        reads, stores = [], []
        for i in decoded:
            if i.mnemonic == "call":
                need(i.operands[0].type == CS_OP_IMM, "unexpected indirect call")
                calls[hx(i.operands[0].imm)].append(hx(i.address))
            for op in i.operands:
                if op.type != CS_OP_MEM or i.mnemonic == "lea":
                    continue
                access = op.access
                # Capstone 5 labels x87 stack input/output differently from the data-memory effect.
                if i.mnemonic in ("fst", "fstp"):
                    access = capstone.CS_AC_WRITE
                item = [hx(i.address), i.mnemonic, op.size, i.op_str]
                if access & capstone.CS_AC_READ:
                    reads.append(item)
                if access & capstone.CS_AC_WRITE:
                    stores.append(item)
        output.append({"entry_va":hx(start), "file_offset":f"0x{offset(start,size):x}", "body_bytes":size,
                       "body_sha256":sha(body), "instruction_count":len(decoded),
                       "all_pe_instructions_match_native_operands":True,
                       "branches":branches, "direct_calls":[{"target":a,"sites":v} for a,v in sorted(calls.items())],
                       "memory_reads":reads, "memory_writes":stores,
                       "returns":[[hx(i.address), int(i.op_str or "0", 0)] for i in decoded if i.mnemonic == "ret"],
                       "x87_sites":[[hx(i.address),i.mnemonic] for i in decoded if i.mnemonic.startswith("f")],
                       "native_export_hashes":{ext:manifest["files"][hx(start)+"."+ext]["sha256"] for ext in ("asm","c")}})
    need([len(f["direct_calls"]) for f in output] == [0, 2], "unexpected call targets")
    need([tuple((f['instruction_count'],len(f['branches']),len(f['direct_calls']),len(f['memory_writes']),len(f['returns']))) for f in output]
         == [(12,1,0,0,2),(70,9,2,1,3)], "body summary count changed")
    need([row['target'] for row in output[1]['direct_calls']] == ['0062c400','00945640'], "callee set changed")
    need([f["returns"] for f in output] == [[['0062c3e0',4],['0062c3f1',4]], [['0062c5a1',8],['0062c5c4',8],['0062c653',8]]], "unexpected RET sites")
    constants = []
    for address, kind in ((0x0096bac8,"float32"),(0x00968968,"float64")):
        width = {"dword":4,"float32":4,"float64":8}[kind]
        b = raw(address,width)
        constants.append({"va":hx(address),"file_offset":f"0x{offset(address,width):x}","width":width,
                          "kind":kind,"value":struct.unpack({"dword":"<I","float32":"<f","float64":"<d"}[kind],b)[0],"sha256":sha(b)})
    return {"work_unit":"R22-A", "specimen_sha256":SPECIMEN, "export_manifest_sha256":MANIFEST,
            "annotation_preflight_sha256":PREFLIGHT, "checkpoint_archive_sha256":manifest["checkpoint_archive_sha256"],
            "decoder":"Capstone 5.0.7 x86-32", "scope":"complete local static bodies; no transitive effects",
            "integrity_under_python_optimized_mode":"explicit ValueError gates", "functions":output,
            "runtime_global":"00ae2364 is read as a DWORD; BSS has no raw-file value", "x87_constants":constants}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = extract(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")

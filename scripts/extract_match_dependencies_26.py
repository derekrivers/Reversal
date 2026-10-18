#!/usr/bin/env python3
"""Verify two complete local bodies against the pinned PE and native export."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "e86692ed3575e204e9e22c5c6d15bba0f5a299d1bc30ce64111b25f0e66cad75"
PREFLIGHT = "b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd"
ARCHIVE = "670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a"
BODIES = {0x62e700: 284, 0x62be00: 342}
CALLS = {0x62e700: {0x944cff, 0x90d130, 0x944c9f, 0x5e8290, 0x58e340, 0x600a50, 0x630ee0},
         0x62be00: {0x944cf1, 0x68d020, 0x68d1b0, 0x68d0d0}}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(value):
    return f"{value:08x}"


def normalized(value):
    value = value.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    value = value.replace("dword ptr", "")
    value = re.sub(r"0x[0-9a-f]+", lambda m: str((int(m[0], 16)+0x80000000)%0x100000000-0x80000000), value)
    value = re.sub(r"\s+", "", value).replace("*1", "").replace("+-", "-").replace("+0]", "]")
    for old, new in (("jnz", "jne"), ("jz", "je")):
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
    need(manifest["checkpoint_archive_sha256"] == ARCHIVE and manifest["preflight_sha256"] == PREFLIGHT,
         "native checkpoint metadata mismatch")
    need(binary[:2] == b"MZ", "MZ header missing")
    pe = struct.unpack_from("<I", binary, 0x3c)[0]
    need(binary[pe:pe+4] == b"PE\0\0" and struct.unpack_from("<H", binary, pe+4)[0] == 0x14c,
         "expected x86 PE")
    optional = pe+24
    need(struct.unpack_from("<H", binary, optional)[0] == 0x10b, "expected PE32")
    base = struct.unpack_from("<I", binary, optional+28)[0]
    nsec, optlen = struct.unpack_from("<H", binary, pe+6)[0], struct.unpack_from("<H", binary, pe+20)[0]
    sections = [struct.unpack_from("<IIII", binary, optional+optlen+40*n+8)[1:] for n in range(nsec)]

    def offset(va, size):
        for rva, raw_size, raw_ptr in sections:
            delta = va-base-rva
            if 0 <= delta and delta+size <= raw_size:
                return raw_ptr+delta
        raise ValueError("VA range not backed by PE raw section")

    result = {}
    for start, length in BODIES.items():
        name = hx(start)
        for ext in ("asm", "c"):
            filename = name+"."+ext
            need(filename in manifest["files"], "native export missing: "+filename)
            payload = (exports / filename).read_bytes()
            meta = manifest["files"][filename]
            need(len(payload) == meta["bytes"] and sha(payload) == meta["sha256"], "native export mismatch: "+filename)
        site = next((s for s in native["sites"] if s["address"] == name), None)
        need(site is not None and site["instruction_exists"], "native preflight site missing")
        need(site["body_addresses"] == length, "native preflight body size changed")
        need(site["function_name"] == ("FUN_"+name),
             "native exact-old name changed")
        file_offset = offset(start, length)
        body = binary[file_offset:file_offset+length]
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        insns = list(md.disasm(body, start))
        need(sum(i.size for i in insns) == length and insns[-1].address+insns[-1].size == start+length,
             "incomplete original-body decode: "+name)
        rows = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", (exports/(name+".asm")).read_text(encoding="utf-8-sig"), re.M)]
        need(len(rows) == len(insns), "native/original instruction count mismatch: "+name)
        for ins, (address, native_text) in zip(insns, rows):
            need(ins.address == address and normalized(ins.mnemonic+" "+ins.op_str) == normalized(native_text),
                 "native/original operand mismatch at "+hx(ins.address))
        starts = {i.address for i in insns}
        edges, calls, reads, writes = {}, [], [], []
        for ins in insns:
            fall = ins.address+ins.size
            if ins.mnemonic == "ret":
                edges[ins.address] = []
            elif ins.mnemonic.startswith("j"):
                need(ins.operands[0].type == CS_OP_IMM, "indirect branch")
                edges[ins.address] = [ins.operands[0].imm]+([] if ins.mnemonic == "jmp" else [fall])
            else:
                edges[ins.address] = [fall]
            if ins.mnemonic == "call":
                need(ins.operands[0].type == CS_OP_IMM, "indirect call")
                calls.append([hx(ins.address), hx(ins.operands[0].imm)])
            for op in ins.operands:
                if op.type != CS_OP_MEM or ins.mnemonic == "lea":
                    continue
                row = [hx(ins.address), ins.mnemonic, op.size, ins.op_str]
                if op.access & capstone.CS_AC_READ:
                    reads.append(row)
                if op.access & capstone.CS_AC_WRITE:
                    writes.append(row)
        need(all(t in starts or (ins.mnemonic == "call" and t == ins.address+ins.size)
                 for ins in insns for t in edges[ins.address]), "local CFG escapes body: "+name)
        need({int(target,16) for _,target in calls} == CALLS[start], "call target set changed: "+name)
        seen, pending = set(), [start]
        while pending:
            site = pending.pop()
            if site in seen:
                continue
            seen.add(site)
            pending.extend(edges[site])
        need(seen == starts, "unreachable original instruction in local body: "+name)
        result[name] = {"entry_va": name, "file_offset": f"0x{file_offset:x}", "body_bytes": length,
                        "body_sha256": sha(body), "instruction_count": len(insns), "all_original_and_native_instructions_match": True,
                        "branches": [[hx(i.address),i.mnemonic,[hx(t) for t in edges[i.address]]] for i in insns if i.mnemonic.startswith("j")],
                        "calls": calls, "memory_reads": reads, "memory_writes": writes,
                        "returns": [[hx(i.address), int(i.op_str or "0",0)] for i in insns if i.mnemonic == "ret"],
                        "native_export_hashes": {ext: manifest["files"][name+"."+ext]["sha256"] for ext in ("asm","c")}}
    return {"work_unit": "R26-A", "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": ARCHIVE,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "scope": "two complete local bodies; all transitive callees and exception handler remain outside this map",
            "integrity_under_python_optimized_mode": "explicit ValueError gates", "bodies": result}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = extract(args.binary, args.exports, args.preflight)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")

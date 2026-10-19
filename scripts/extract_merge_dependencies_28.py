#!/usr/bin/env python3
"""Verify R28-B PE/native bodies and emit complete local control-flow evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "058514c602952b66abeade64ba9a28bbab3873c16503af4ca0f834fb2a6d2ddc"
PREFLIGHT = "9f9e52088fc32356aebecb6fc39ba78fea96e14f359383afb01362287409fbb2"
ROWS = [(0x68d020, 17), (0x68d0d0, 221)]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked(path, expected):
    data = path.read_bytes()
    if sha(data) != expected:
        raise ValueError(f"SHA-256 mismatch: {path}")
    return data


def norm(text):
    text = text.lower()
    text = re.sub(r"\bjnz\b", "jne", text)
    text = re.sub(r"\bjz\b", "je", text)
    text = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0], 16)), text)
    text = text.replace("dword ptr fs:", "fs:")
    text = re.sub(r"\s+", "", text).replace("+0]", "]")
    return text


def extract(exe, exports, preflight):
    if capstone.__version__ != "5.0.7":
        raise ValueError("Capstone 5.0.7 required")
    data = checked(exe, PINNED)
    manifest = json.loads(checked(exports / "manifest.json", MANIFEST))
    prior = json.loads(checked(preflight, PREFLIGHT))
    if (manifest["specimen_sha256"] != PINNED or
            manifest["preflight_sha256"] != PREFLIGHT or prior["sha256"] != PINNED):
        raise ValueError("provenance mismatch")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[:2] != b"MZ" or data[pe:pe+4] != b"PE\0\0":
        raise ValueError("not PE")
    opt = pe + 24
    if struct.unpack_from("<H", data, pe+4)[0] != 0x14c or struct.unpack_from("<H", data, opt)[0] != 0x10b:
        raise ValueError("not x86 PE32")
    base = struct.unpack_from("<I", data, opt+28)[0]
    sections = [struct.unpack_from("<8sIIII", data, opt + struct.unpack_from("<H", data, pe+20)[0] + 40*i)
                for i in range(struct.unpack_from("<H", data, pe+6)[0])]

    def offset(va):
        for _, virtual_size, rva, raw_size, raw_offset in sections:
            delta = va-base-rva
            if 0 <= delta < raw_size and delta < max(raw_size, virtual_size):
                return raw_offset+delta
        raise ValueError(f"unbacked virtual address {va:08x}")

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    old = {site["address"]: site for site in prior["sites"]}
    functions = []
    for entry, size in ROWS:
        key = f"{entry:08x}"
        before = old[key]
        if (before["function_name"] != "FUN_"+key or before["body_addresses"] != size or
                before["instruction_exists"] is not True):
            raise ValueError("native exact-old preflight mismatch " + key)
        hashes = {}
        for ext in ("asm", "c"):
            name = f"{key}.{ext}"
            raw = (exports/name).read_bytes()
            reference = manifest["files"][name]
            if len(raw) != reference["bytes"] or sha(raw) != reference["sha256"]:
                raise ValueError("native export mismatch " + name)
            hashes[ext] = sha(raw)
        if "FUN_"+key+"(" not in (exports/f"{key}.c").read_text():
            raise ValueError("native pseudocode identity mismatch " + key)
        pos = offset(entry)
        if offset(entry+size-1) != pos+size-1:
            raise ValueError("body crosses PE backing")
        body = data[pos:pos+size]
        ins = list(cs.disasm(body, entry))
        own = {i.address: norm(i.mnemonic+" "+i.op_str) for i in ins}
        native = {}
        for line in (exports/f"{key}.asm").read_text().splitlines():
            address, expression = line.split(None, 1)
            va = int(address, 16)
            if va in native:
                raise ValueError("duplicate native instruction")
            native[va] = norm(expression)
        if not ins or sum(i.size for i in ins) != size or own != native:
            raise ValueError(f"complete PE/native instruction or operand mismatch {key}: {own!r} != {native!r}")
        starts = set(own)
        edges = []
        calls = []
        for i in ins:
            targets = []
            if i.group(capstone.CS_GRP_CALL):
                if len(i.operands) != 1 or i.operands[0].type != capstone.x86.X86_OP_IMM:
                    raise ValueError("indirect call requires separate analysis")
                calls.append([f"{i.address:08x}", f"{i.operands[0].imm:08x}"])
            if i.group(capstone.CS_GRP_JUMP):
                if len(i.operands) != 1 or i.operands[0].type != capstone.x86.X86_OP_IMM:
                    raise ValueError("indirect jump requires separate analysis")
                targets.append(i.operands[0].imm)
            if i.mnemonic != "ret" and i.mnemonic != "jmp":
                targets.append(i.address+i.size)
            if any(t not in starts for t in targets):
                raise ValueError("local edge leaves body")
            edges.extend([[f"{i.address:08x}", f"{t:08x}"] for t in targets])
        reached = {entry}
        while True:
            more = {int(b, 16) for a,b in edges if int(a,16) in reached}-reached
            if not more:
                break
            reached |= more
        if reached != starts:
            raise ValueError("unreachable native instruction starts")
        functions.append({"entry_va": key, "file_offset": f"0x{pos:x}", "body_bytes": size,
                          "body_sha256": sha(body), "native_export_sha256": hashes,
                          "instruction_count": len(ins), "matched_native_instructions": len(ins),
                          "reachable_instruction_starts": len(reached), "edges": edges,
                          "return_sites": [f"{i.address:08x}" for i in ins if i.mnemonic == "ret"],
                          "calls": calls,
                          "memory_operands": [[f"{i.address:08x}", i.mnemonic, i.op_str]
                                              for i in ins if "[" in i.op_str]})
    return {"work_unit": "R28-B", "specimen_sha256": PINNED,
            "checkpoint_archive_sha256": manifest["checkpoint_archive_sha256"],
            "export_manifest_sha256": MANIFEST, "preflight_sha256": PREFLIGHT,
            "method": "Capstone 5.0.7 complete PE/native instruction, operand, byte and local CFG comparison",
            "functions": functions}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.exe, args.exports, args.preflight), indent=2)+"\n", encoding="utf-8", newline="\n")

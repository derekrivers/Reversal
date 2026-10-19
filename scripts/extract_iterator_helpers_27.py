#!/usr/bin/env python3
"""Pin both R27-A bodies to PE/native bytes and emit compact instruction evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "bbd00280029a738f4f4dfa6462c7d34a4379887626749d9f20eef20873655f14"
PREFLIGHT = "fb1be5075c72e92045f4d802f649665801d8ebc85b049a25e0f652e282f6015d"
ROWS = [(0x68d1b0, 19, 6), (0x68d1d0, 19, 10)]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path, expected):
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError(f"SHA-256 mismatch: {path}")
    return raw


def norm(s):
    s = s.lower()
    s = re.sub(r"\bjz\b", "je", s)
    s = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0], 16)), s)
    return re.sub(r"\s+", "", s).replace("+0]", "]")


def extract(exe, exports, preflight):
    if capstone.__version__ != "5.0.7":
        raise ValueError("Capstone 5.0.7 required")
    data = checked(exe, PINNED)
    m = json.loads(checked(exports / "manifest.json", MANIFEST))
    p = json.loads(checked(preflight, PREFLIGHT))
    if m["specimen_sha256"] != PINNED or m["preflight_sha256"] != PREFLIGHT or p["sha256"] != PINNED:
        raise ValueError("provenance mismatch")
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    if data[:2] != b"MZ" or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("not PE")
    opt = e_lfanew + 24
    if struct.unpack_from("<H", data, e_lfanew + 4)[0] != 0x14c or struct.unpack_from("<H", data, opt)[0] != 0x10b:
        raise ValueError("not PE32 x86")
    base = struct.unpack_from("<I", data, opt + 28)[0]
    count = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sections = [struct.unpack_from("<8sIIII", data, opt + opt_size + 40*i) for i in range(count)]

    def offset(va):
        for _, virtual_size, rva, raw_size, raw_offset in sections:
            d = va - base - rva
            if 0 <= d < raw_size and d < max(raw_size, virtual_size):
                return raw_offset + d
        raise ValueError(f"unbacked VA {va:08x}")

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    old = {r["address"]: r for r in p["sites"]}
    out = []
    for entry, size, link in ROWS:
        key = f"{entry:08x}"
        hashes = {}
        for extension in ("asm", "c"):
            name = f"{key}.{extension}"
            row = m["files"][name]
            raw = (exports / name).read_bytes()
            if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
                raise ValueError("native export mismatch " + name)
            hashes[extension] = sha(raw)
        before = old[key]
        if before["function_name"] != "FUN_" + key or before["body_addresses"] != size or not before["instruction_exists"]:
            raise ValueError("native preflight mismatch " + key)
        if "FUN_" + key + "(" not in (exports / f"{key}.c").read_text():
            raise ValueError("pseudocode name mismatch")
        pos = offset(entry)
        if offset(entry + size - 1) != pos + size - 1:
            raise ValueError("body crosses noncontiguous PE backing")
        body = data[pos:pos + size]
        ins = list(cs.disasm(body, entry))
        native = {}
        for line in (exports / f"{key}.asm").read_text().splitlines():
            address, instruction = line.split(None, 1)
            va = int(address, 16)
            if va in native:
                raise ValueError("duplicate native instruction")
            native[va] = norm(instruction)
        own = {i.address: norm(i.mnemonic + " " + i.op_str) for i in ins}
        if len(ins) != 9 or sum(i.size for i in ins) != size or own != native:
            raise ValueError(f"complete original/native instruction mismatch {key}: {own!r} != {native!r}")
        starts = set(own)
        edges = []
        for i in ins:
            targets = []
            if i.group(capstone.CS_GRP_JUMP):
                if i.operands[0].type != capstone.x86.X86_OP_IMM:
                    raise ValueError("indirect branch")
                targets.append(i.operands[0].imm)
            if i.mnemonic != "ret" and i.mnemonic != "jmp":
                targets.append(i.address + i.size)
            if any(t not in starts for t in targets):
                raise ValueError("edge leaves body")
            edges.extend([[f"{i.address:08x}", f"{t:08x}"] for t in targets])
        reached = {entry}
        while True:
            more = {int(b, 16) for a, b in edges if int(a, 16) in reached} - reached
            if not more:
                break
            reached |= more
        if reached != starts:
            raise ValueError("unreachable native start")
        out.append({"entry_va": key, "file_offset": f"0x{pos:x}", "body_bytes": size,
                    "body_sha256": sha(body), "native_export_sha256": hashes,
                    "instruction_count": len(ins), "matched_native_instructions": len(ins),
                    "reachable_instruction_starts": len(reached), "edges": edges,
                    "return_sites": [f"{i.address:08x}" for i in ins if i.mnemonic == "ret"],
                    "link_offset": link,
                    "memory_operands": [[f"{i.address:08x}", i.mnemonic, i.op_str]
                                        for i in ins if "[" in i.op_str]})
    return {"work_unit": "R27-A", "specimen_sha256": PINNED,
            "checkpoint_archive_sha256": m["checkpoint_archive_sha256"],
            "export_manifest_sha256": MANIFEST, "preflight_sha256": PREFLIGHT,
            "method": "Capstone 5.0.7 exact complete PE/native instruction, operand, byte, CFG and preflight comparison",
            "functions": out}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.exe, args.exports, args.preflight), indent=2) + "\n", encoding="utf-8", newline="\n")

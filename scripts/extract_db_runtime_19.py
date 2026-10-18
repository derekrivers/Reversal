#!/usr/bin/env python3
"""Verify R19 descriptor and allocation wrappers; emit compact static evidence.

Requires capstone==5.0.7. Arguments: EXE EXPORTS_19 PREFLIGHT_19 OUTPUT.json.
Never emits original bytes or bulk listings. Native inputs are read-only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "3c5da196118b891f3dcd84f8126355d3c36888c3c7b72ca1f6d89772d8a22935"
PREFLIGHT = "a8b6f47a04ac2dcc2d6fb13537a55b223db5630d50e857ceb014f40f7069cf78"
# Native membership is checked against every decoded instruction and byte,
# rather than assuming the min/max extent establishes a contiguous body.
ROWS = [
    (0x94fded, 61, "FUN_0094fded", None,
     [0x94fdf1, 0x94fdfe, 0x94fe08, 0x94fe12, 0x94fe15, 0x94fe1c]),
    (0x944e46, 18, "_malloc",
     "Library Function - Single Match\n _malloc\n\nLibrary: Visual Studio 2003 Release",
     [0x944e46, 0x944e4c, 0x944e50]),
    (0x944e58, 44, "__nh_malloc",
     "Library Function - Single Match\n __nh_malloc\n\nLibrary: Visual Studio 2003 Release",
     [0x944e58, 0x944e63, 0x944e6d, 0x944e77, 0x944e7f, 0x944e81]),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalize(text):
    text = text.lower()
    for old, new in [("jz", "je"), ("jnz", "jne"), ("jc", "jb"), ("jnc", "jae")]:
        text = re.sub(r"\b" + old + r"\b", new, text)
    # Ghidra prints sign-extended imm8 constants as negative hex; Capstone
    # may print the equivalent unsigned DWORD (e.g. -0x20 / 0xffffffe0).
    text = re.sub(r"-0x[0-9a-f]+|\b0x[0-9a-f]+\b",
                  lambda m: str(int(m[0], 16) & 0xffffffff), text)
    text = re.sub(r"\s+", "", text).replace("+-", "-")
    return re.sub(r"\*1(?=[+\-\]])", "", text).replace("+0]", "]")


def extract(specimen, exports, preflight):
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires capstone==5.0.7")
    data = specimen.read_bytes()
    manifest_raw = (exports / "manifest.json").read_bytes()
    preflight_raw = preflight.read_bytes()
    for raw, expected, label in [(data, PINNED, "specimen"),
            (manifest_raw, MANIFEST, "manifest"), (preflight_raw, PREFLIGHT, "preflight")]:
        if digest(raw) != expected:
            raise ValueError(label + " hash mismatch")
    manifest, old = json.loads(manifest_raw), json.loads(preflight_raw)
    if (manifest["specimen_sha256"] != PINNED or old["sha256"] != PINNED
            or manifest["preflight_sha256"] != PREFLIGHT):
        raise ValueError("native provenance mismatch")
    old_names = {r["address"]: r for r in old["sites"]}
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    opt = pe + 24
    if (data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0"
            or struct.unpack_from("<H", data, pe + 4)[0] != 0x14c
            or struct.unpack_from("<H", data, opt)[0] != 0x10b):
        raise ValueError("not x86 PE32")
    base = struct.unpack_from("<I", data, opt + 28)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    sections = [struct.unpack_from("<8sIIII", data, opt + opt_size + 40 * i)
                for i in range(count)]

    def offset(va):
        for _, _, rva, raw_size, raw_offset in sections:
            delta = va - base - rva
            if 0 <= delta < raw_size:
                return raw_offset + delta
        raise ValueError(f"VA {va:08x} is not file-backed")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    functions = []
    for start, size, name, comment, picks in ROWS:
        entry = f"{start:08x}"
        native_hashes = {}
        for suffix in ["asm", "c"]:
            filename = entry + "." + suffix
            raw = (exports / filename).read_bytes()
            row = manifest["files"][filename]
            if digest(raw) != row["sha256"] or len(raw) != row["bytes"]:
                raise ValueError("native export mismatch: " + filename)
            native_hashes[suffix] = digest(raw)
        pos = offset(start)
        if offset(start + size - 1) != pos + size - 1:
            raise ValueError("noncontiguous file backing")
        body = data[pos:pos + size]
        ins = list(md.disasm(body, start))
        own = {i.address: normalize(i.mnemonic + " " + i.op_str) for i in ins}
        native = {}
        for line in (exports / (entry + ".asm")).read_text().splitlines():
            address, instruction = line.split(None, 1)
            va = int(address, 16)
            if va in native:
                raise ValueError("duplicate native instruction")
            native[va] = normalize(instruction)
        if (sum(i.size for i in ins) != size or ins[0].address != start
                or ins[-1].address + ins[-1].size != start + size or own != native):
            mismatch = {f"{va:08x}": [own.get(va), native.get(va)]
                        for va in set(own) | set(native) if own.get(va) != native.get(va)}
            raise ValueError("complete original/native comparison failed: " + entry + " " + str(mismatch))
        old_row = old_names[entry]
        if (not old_row["instruction_exists"] or old_row["function_name"] != name
                or old_row.get("function_comment") != comment
                or name + "(" not in (exports / (entry + ".c")).read_text()):
            raise ValueError("unexpected old native annotation")
        graph, jumps, calls = {}, [], []
        for i in ins:
            successors = []
            if i.group(capstone.CS_GRP_JUMP):
                operand = i.operands[0]
                if operand.type != capstone.x86.X86_OP_IMM or operand.imm not in own:
                    raise ValueError("unresolved or nonlocal branch")
                successors.append(operand.imm)
                jumps.append({"site_va": f"{i.address:08x}", "target_va": f"{operand.imm:08x}"})
            if i.mnemonic not in ("ret", "jmp"):
                successors.append(i.address + i.size)
            if any(target not in own for target in successors):
                raise ValueError("fallthrough outside owned instructions")
            graph[i.address] = successors
            if i.mnemonic == "call":
                operand = i.operands[0]
                if operand.type != capstone.x86.X86_OP_IMM:
                    raise ValueError("unresolved call")
                calls.append({"site_va": f"{i.address:08x}", "target_va": f"{operand.imm:08x}"})
        reached, pending = set(), [start]
        while pending:
            va = pending.pop()
            if va not in reached:
                reached.add(va)
                pending.extend(graph[va])
        if reached != set(own):
            raise ValueError("structurally unreachable instruction")
        selected = {f"{i.address:08x}": (i.mnemonic + " " + i.op_str).strip()
                    for i in ins if i.address in picks}
        if len(selected) != len(picks):
            raise ValueError("selected site is not an instruction")
        functions.append({"entry_va": entry, "native_name": name,
            "entry_file_offset": f"{pos:08x}", "end_exclusive_va": f"{start + size:08x}",
            "body_bytes": size, "instruction_count": len(ins),
            "matched_native_instructions": len(ins),
            "owned_instruction_bytes_sha256": digest(body), "native_file_sha256": native_hashes,
            "native_instruction_membership": "Exactly matches complete contiguous PE decode; no omitted native starts or decoded bytes",
            "structurally_reached_instruction_count": len(reached), "branches": jumps, "calls": calls,
            "return_sites_va": [f"{i.address:08x}" for i in ins if i.mnemonic == "ret"],
            "selected_instructions": selected})
    return {"specimen_sha256": PINNED, "native_manifest_sha256": MANIFEST,
        "private_preflight_sha256": PREFLIGHT, "address_space": "VA unless explicitly file offset",
        "method": "Capstone 5.0.7 full original-PE decode/native instruction membership and operand comparison; complete branch/fallthrough graph; static only",
        "functions": functions}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ["specimen", "exports", "preflight", "output"]:
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen, args.exports, args.preflight), indent=2)
                          + "\n", encoding="utf-8", newline="\n")

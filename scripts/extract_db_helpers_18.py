#!/usr/bin/env python3
"""Verify three R18 database-path helper bodies; retain compact static evidence.

Requires capstone==5.0.7. Usage: EXE EXPORTS_18 PREFLIGHT_18 OUTPUT.json.
Original bytes, error-table rows and bulk native listings are never emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "fc4f2070cb0efa89c9473ebe507d0e2d3f01e1f5f66338177be5f34848ee7151"
PREFLIGHT = "8749c47798c3758dc7509d0b3b71b7147f169ee0390066f01ef023baf670bcbb"
ROWS = [
    (0x94b2a0, 103, [0x94b2a6, 0x94b2b1, 0x94b2be, 0x94b2ca,
                       0x94b2d5, 0x94b2dc, 0x94b2f0, 0x94b2fc]),
    (0x94c552, 154, [0x94c557, 0x94c577, 0x94c58a, 0x94c596,
                       0x94c59a, 0x94c59c, 0x94c5c7, 0x94c5d4]),
    (0x94ec37, 68, [0x94ec37, 0x94ec4e, 0x94ec53, 0x94ec57,
                     0x94ec60, 0x94ec64, 0x94ec6a, 0x94ec74]),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalize(text):
    text = text.lower()
    # Native MOV [absolute],EAX omits the redundant width; the register
    # establishes DWORD width just as Capstone's explicit spelling does.
    text = re.sub(r"\bmov\s+(\[[^\]]+\]),\s*(eax)\b", r"mov dword ptr \1,\2", text)
    for old, new in [("jz", "je"), ("jnz", "jne"), ("jc", "jb"), ("jnc", "jae")]:
        text = re.sub(r"\b" + old + r"\b", new, text)
    text = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0], 16)), text)
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

    def read(va, size):
        pos = offset(va)
        if offset(va + size - 1) != pos + size - 1:
            raise ValueError("noncontiguous input read")
        return data[pos:pos + size]

    def cstr(va):
        pos = offset(va)
        return data[pos:data.index(0, pos)].decode("ascii")

    imports = {}
    directory = base + struct.unpack_from("<I", data, opt + 104)[0]
    while True:
        original, _, _, library, first = struct.unpack("<IIIII", read(directory, 20))
        if not any((original, library, first)):
            break
        library_name = cstr(base + library)
        index = 0
        while True:
            value = struct.unpack("<I", read(base + (original or first) + 4 * index, 4))[0]
            if value == 0:
                break
            name = "ordinal:" + str(value & 0xffff) if value & 0x80000000 else cstr(base + value + 2)
            imports[base + first + 4 * index] = library_name + "!" + name
            index += 1
        directory += 20
    expected_imports = {0x9670a0: "KERNEL32.dll!SetFilePointer", 0x9670e8: "KERNEL32.dll!GetLastError"}
    if any(imports.get(va) != name for va, name in expected_imports.items()):
        raise ValueError("unexpected import binding")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    functions = []
    for start, size, picks in ROWS:
        entry = f"{start:08x}"
        native_hashes = {}
        for suffix in ["asm", "c"]:
            name = entry + "." + suffix
            raw = (exports / name).read_bytes()
            row = manifest["files"][name]
            if digest(raw) != row["sha256"] or len(raw) != row["bytes"]:
                raise ValueError("native export mismatch: " + name)
            native_hashes[suffix] = digest(raw)
        # Decode the entire independently bounded PE body, not just addresses
        # reported as instructions by Ghidra. All three bodies are contiguous.
        body = read(start, size)
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
            raise ValueError("complete original/native instruction comparison failed: "
                             + entry + " " + str(mismatch))
        old_row = old_names[entry]
        if (not old_row["instruction_exists"] or old_row["function_name"] != "FUN_" + entry
                or old_row.get("function_comment") not in (None, "")
                or "FUN_" + entry + "(" not in (exports / (entry + ".c")).read_text()):
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
                if operand.type == capstone.x86.X86_OP_IMM:
                    calls.append({"site_va": f"{i.address:08x}", "target_va": f"{operand.imm:08x}"})
                elif (operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == 0
                        and operand.mem.index == 0 and operand.mem.disp in expected_imports):
                    calls.append({"site_va": f"{i.address:08x}", "iat_slot_va": f"{operand.mem.disp:08x}",
                                  "import": imports[operand.mem.disp]})
                else:
                    raise ValueError("unresolved call")
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
        functions.append({"entry_va": entry, "entry_file_offset": f"{offset(start):08x}",
            "end_exclusive_va": f"{start + size:08x}", "body_bytes": size,
            "instruction_count": len(ins), "matched_native_instructions": len(ins),
            "owned_instruction_bytes_sha256": digest(body), "native_file_sha256": native_hashes,
            "structurally_reached_instruction_count": len(reached), "branches": jumps, "calls": calls,
            "return_sites_va": [f"{i.address:08x}" for i in ins if i.mnemonic == "ret"],
            "selected_instructions": selected})
    return {"specimen_sha256": PINNED, "native_manifest_sha256": MANIFEST,
        "private_preflight_sha256": PREFLIGHT, "address_space": "VA unless explicitly file offset",
        "method": "Capstone 5.0.7 full contiguous original-PE decode/native comparison, complete branch/fallthrough graph and import bindings; static only",
        "error_table": {"start_va": "00ad8dc0", "end_exclusive_va": "00ad8f28",
                        "row_count": 45, "row_bytes": 8,
                        "private_original_table_sha256": digest(read(0xad8dc0, 0x168)),
                        "contents": "Not redistributed; DWORD key followed by DWORD mapped value; first exact key wins"},
        "functions": functions}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ["specimen", "exports", "preflight", "output"]:
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen, args.exports, args.preflight), indent=2)
                          + "\n", encoding="utf-8", newline="\n")

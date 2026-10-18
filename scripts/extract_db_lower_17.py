#!/usr/bin/env python3
"""Verify R17 lower-copy/read/refill bodies against the pinned PE and native exports.

Requires capstone==5.0.7. Only compact static sites, hashes and table targets are
published, never instruction bytes or bulk decompilation. Usage: EXE EXPORTS PREFLIGHT OUTPUT
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

PINNED = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "096c06e07891855555057cdcc9f33307c6cdee79e7c632be5f593f76d894a2b8"
PREFLIGHT = "0d084f0348af44eeb24a73d8cec0fc866525099b14180bd87bd9c6246beda10f"
ROWS = [
    (0x94ab50, 664, 0x94ae84, [0x94ab55, 0x94ab58, 0x94ab5b, 0x94ab62,
        0x94ab66, 0x94ab6a, 0x94ab83, 0x94ab93, 0x94ab96, 0x94ac8f,
        0x94ace8, 0x94acec, 0x94ad03, 0x94ad04, 0x94ad06, 0x94ad23,
        0x94ad26, 0x94ad28, 0x94ad2b, 0x94ae27]),
    (0x94b3e0, 502, 0x94b5d5, [0x94b3ec, 0x94b3fa, 0x94b3fd, 0x94b400,
        0x94b416, 0x94b426, 0x94b42e, 0x94b433, 0x94b43f, 0x94b442,
        0x94b450, 0x94b477, 0x94b47b, 0x94b485, 0x94b490, 0x94b4ad,
        0x94b4b8, 0x94b4c0, 0x94b4c4, 0x94b4c9, 0x94b4cd, 0x94b4cf,
        0x94b4ec, 0x94b4f4, 0x94b503, 0x94b50d, 0x94b512, 0x94b53b,
        0x94b545, 0x94b549, 0x94b551, 0x94b565, 0x94b56b, 0x94b58a,
        0x94b5aa, 0x94b5ae, 0x94b5b2, 0x94b5bd, 0x94b5c4]),
    (0x94b307, 217, 0x94b3df, [0x94b30c, 0x94b30f, 0x94b317, 0x94b31f,
        0x94b323, 0x94b32d, 0x94b32f, 0x94b341, 0x94b344, 0x94b357,
        0x94b35a, 0x94b35e, 0x94b366, 0x94b36f, 0x94b388, 0x94b394,
        0x94b399, 0x94b39f, 0x94b3ab, 0x94b3b0, 0x94b3b5, 0x94b3bf,
        0x94b3c2, 0x94b3c6, 0x94b3ca, 0x94b3cc, 0x94b3ce, 0x94b3d1,
        0x94b3d4, 0x94b3d7]),
]
# Valid index domains follow from the mask/alignment/count branches. Tables
# may use an instruction's address as index zero, or negative indices.
TABLES = [
    (0x94abb0, [1, 2, 3]), (0x94ac2c, list(range(8))),
    (0x94ac98, list(range(4))),
    (0x94aca8, [-4, -3, -2, -1]),
    (0x94ad38, [1, 2, 3]), (0x94ade0, list(range(-7, 1))),
    (0x94ae30, list(range(4))),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalize(text):
    text = text.lower().replace("movsd.rep es:edi,esi", "rep movsd dword ptr es:[edi],dword ptr [esi]")
    for old, new in [("jz", "je"), ("jnz", "jne"), ("jc", "jb"), ("jnc", "jae")]:
        text = re.sub(r"\b" + old + r"\b", new, text)
    text = re.sub(r"\b0x[0-9a-f]+\b", lambda m: str(int(m[0], 16)), text)
    compact = re.sub(r"\s+", "", text).replace("+-", "-")
    compact = re.sub(r"\*1(?=[+\-\]])", "", compact)
    # Ghidra prints a redundant zero displacement for LEA index-only operands.
    return compact.replace("+0]", "]")


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
    if manifest["specimen_sha256"] != PINNED or old["sha256"] != PINNED:
        raise ValueError("native specimen mismatch")
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

    # Resolve imported names from original import descriptors/thunks, rather
    # than assigning OS identities from the decompiler's inferred calls.
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
    if imports.get(0x9670e4) != "KERNEL32.dll!ReadFile" or imports.get(0x9670e8) != "KERNEL32.dll!GetLastError":
        raise ValueError("unexpected import binding")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    functions = []
    for start, size, last, picks in ROWS:
        entry = f"{start:08x}"
        native_hashes = {}
        for suffix in ["asm", "c"]:
            name = entry + "." + suffix
            raw = (exports / name).read_bytes()
            row = manifest["files"][name]
            if digest(raw) != row["sha256"] or len(raw) != row["bytes"]:
                raise ValueError("native export mismatch: " + name)
            native_hashes[suffix] = digest(raw)
        # Decode each native-owned instruction independently, permitting holes
        # occupied by inline tables/alignment. Every owned byte is compared.
        ins, native = [], {}
        for line in (exports / (entry + ".asm")).read_text().splitlines():
            address, instruction = line.split(None, 1)
            va = int(address, 16)
            native[va] = normalize(instruction)
            ins.append(next(md.disasm(read(va, 15), va, count=1)))
        own = {i.address: normalize(i.mnemonic + " " + i.op_str) for i in ins}
        if own != native:
            mismatch = {f"{va:08x}": [own.get(va), native.get(va)]
                        for va in set(own) | set(native) if own.get(va) != native.get(va)}
            raise ValueError("native instruction mismatch: " + str(mismatch))
        if sum(i.size for i in ins) != size or ins[0].address != start or ins[-1].address != last:
            raise ValueError("body ownership mismatch")
        ranges = []
        for i in ins:
            if ranges and ranges[-1][1] == i.address:
                ranges[-1][1] += i.size
            else:
                if ranges and ranges[-1][1] > i.address:
                    raise ValueError("overlapping or unsorted instructions")
                ranges.append([i.address, i.address + i.size])
        body = b"".join(read(a, b-a) for a,b in ranges)
        if not old_names[entry]["instruction_exists"] or old_names[entry]["function_name"] != "FUN_" + entry:
            raise ValueError("unexpected old annotation")
        if "FUN_" + entry + "(" not in (exports / (entry + ".c")).read_text():
            raise ValueError("decompiler header disagreement")
        direct_jumps, indirect_jumps = [], []
        for i in ins:
            if i.group(capstone.CS_GRP_JUMP):
                operand = i.operands[0]
                if operand.type == capstone.x86.X86_OP_IMM:
                    if operand.imm not in own:
                        raise ValueError("nonlocal direct jump")
                    direct_jumps.append(i)
                else:
                    if start != 0x94ab50 or operand.type != capstone.x86.X86_OP_MEM or operand.mem.disp not in dict(TABLES):
                        raise ValueError("unresolved indirect jump")
                    indirect_jumps.append(i)
        tables = []
        table_targets = {}
        for table, indices in TABLES if start == 0x94ab50 else []:
            targets = [struct.unpack("<I", read(table + 4 * index, 4))[0] for index in indices]
            if any(target not in own for target in targets):
                raise ValueError("nonlocal table target")
            table_targets[table] = targets
            tables.append({"base_va": f"{table:08x}", "indices": indices,
                           "targets_va": [f"{target:08x}" for target in targets],
                           "table_values_sha256": digest(b"".join(read(table + 4 * i, 4) for i in indices))})
        graph = {}
        for i in ins:
            successors = []
            if i.group(capstone.CS_GRP_JUMP):
                operand = i.operands[0]
                successors.extend([operand.imm] if operand.type == capstone.x86.X86_OP_IMM
                                  else table_targets[operand.mem.disp])
            if i.mnemonic not in ("ret", "jmp"):
                successors.append(i.address + i.size)
            if any(target not in own for target in successors):
                raise ValueError("fallthrough outside owned instructions")
            graph[i.address] = successors
        reached, pending = set(), [start]
        while pending:
            va = pending.pop()
            if va not in reached:
                reached.add(va)
                pending.extend(graph[va])
        if reached != set(own):
            raise ValueError("owned instructions not structurally reachable")
        calls = []
        for n, i in enumerate(ins):
            if i.mnemonic != "call":
                continue
            operand = i.operands[0]
            target = operand.imm if operand.type == capstone.x86.X86_OP_IMM else operand.mem.disp
            calls.append({"site_va": f"{i.address:08x}",
                          "target_va" if operand.type == capstone.x86.X86_OP_IMM else "iat_slot_va": f"{target:08x}",
                          **({"import": imports[target]} if target in imports else {}),
                          "nearby_argument_pushes": [j.op_str for j in ins[max(0,n-7):n] if j.mnemonic == "push"]})
        selected = {f"{i.address:08x}": (i.mnemonic + " " + i.op_str).strip()
                    for i in ins if i.address in picks}
        if len(selected) != len(picks):
            raise ValueError("selected site not an instruction")
        functions.append({"entry_va": entry, "entry_file_offset": f"{offset(start):08x}",
            "body_bytes": size, "instruction_count": len(ins), "matched_native_instructions": len(ins),
            "owned_ranges": [{"start_va": f"{a:08x}", "end_exclusive_va": f"{b:08x}"} for a,b in ranges],
            "owned_instruction_bytes_sha256": digest(body), "native_file_sha256": native_hashes,
            "verified_direct_jump_count": len(direct_jumps), "verified_indirect_jump_count": len(indirect_jumps),
            "structurally_reached_instruction_count": len(reached),
            "jump_tables": tables, "calls": calls,
            "return_sites_va": [f"{i.address:08x}" for i in ins if i.mnemonic == "ret"],
            "selected_instructions": selected})
    return {"specimen_sha256": PINNED, "native_manifest_sha256": MANIFEST,
        "private_preflight_sha256": PREFLIGHT, "address_space": "VA unless explicitly file offset",
        "method": "Capstone 5.0.7 per-owned-instruction decode/native comparison; direct branches, inline jump table targets and original import bindings verified; static only",
        "functions": functions}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ["specimen", "exports", "preflight", "output"]:
        parser.add_argument(arg, type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(extract(args.specimen, args.exports, args.preflight), indent=2)
                          + "\n", encoding="utf-8", newline="\n")

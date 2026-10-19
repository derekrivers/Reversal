#!/usr/bin/env python3
"""Verify R29-C PE/native local bodies and emit compact, non-binary evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone

SPECIMEN = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST = "ced03a8f3d9da3cc61fcb9d63e0be55cb1cc39776615c038e0320836a526c0da"
PREFLIGHT = "cee6d3c36808bd69afb14796fa22314a8900909e3b59e08544e5bdfe58063a0c"
CHECKPOINT = "ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a"
BODIES = {0x68d080: (77, "FUN_0068d080"), 0x68d280: (96, "FUN_0068d280"),
          0x68d2e0: (13, "FUN_0068d2e0"), 0x68d2f0: (128, "FUN_0068d2f0")}
CALLS = {0x68d080: {0x68d09a: 0x68d010, 0x68d0a0: 0x944c94},
         0x68d280: {0x68d2c9: 0x68d010, 0x68d2cf: 0x944c94},
         0x68d2e0: {},
         0x68d2f0: {0x68d30a: 0x68d010, 0x68d310: 0x944c94,
                    0x68d361: 0x68d0d0}}
SELECTED = {0x68d094,0x68d096,0x68d0a8,0x68d0aa,0x68d0ad,0x68d2b6,
            0x68d2b9,0x68d2c3,0x68d2e0,0x68d2e5,0x68d2e7,
            0x68d33e,0x68d344,0x68d350,0x68d352,0x68d357,0x68d361,0x68d366}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(n):
    return f"{n:08x}"


def normalized(s):
    s = s.lower().strip().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    s = s.replace("dword ptr fs:", "fs:")
    for width in ("d", "b"):
        if s == f"movs{width}.rep es:edi,esi":
            ptr = "dword" if width == "d" else "byte"
            s = f"rep movs{width} {ptr} ptr es:[edi], {ptr} ptr [esi]"
    s = re.sub(r"0x[0-9a-f]+", lambda m: str((int(m[0], 16) + 0x80000000) % 0x100000000 - 0x80000000), s)
    s = re.sub(r"\s+", "", s).replace("*0x1", "").replace("*1", "").replace("+-", "-").replace("+0]", "]")
    for a, b in (("jz", "je"), ("jnz", "jne"), ("jc", "jb"), ("jnc", "jae")):
        if s.startswith(a):
            s = b + s[len(a):]
    return s


def pe_offset(pe, va, size):
    header = struct.unpack_from("<I", pe, 0x3c)[0]
    need(pe[:2] == b"MZ" and pe[header:header + 4] == b"PE\0\0", "invalid PE")
    need(struct.unpack_from("<H", pe, header + 4)[0] == 0x14c and
         struct.unpack_from("<H", pe, header + 24)[0] == 0x10b, "requires PE32 x86")
    count, opt_size = struct.unpack_from("<H", pe, header + 6)[0], struct.unpack_from("<H", pe, header + 20)[0]
    base = struct.unpack_from("<I", pe, header + 24 + 28)[0]
    sections = [struct.unpack_from("<8sIIII", pe, header + 24 + opt_size + 40*i) for i in range(count)]
    matches = [off + va - base - rva for _, virtual, rva, raw, off in sections
               if 0 <= va - base - rva and va - base - rva + size <= min(virtual, raw)]
    need(len(matches) == 1, "range is not uniquely raw-backed")
    return matches[0]


def extract(binary, exports, preflight):
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    pe = binary.read_bytes()
    need(len(pe) == 7192576 and sha(pe) == SPECIMEN, "pinned specimen mismatch")
    manifest_raw, old_raw = (exports / "manifest.json").read_bytes(), preflight.read_bytes()
    need(sha(manifest_raw) == MANIFEST and sha(old_raw) == PREFLIGHT, "manifest/preflight SHA-256 mismatch")
    manifest, old = json.loads(manifest_raw), json.loads(old_raw)
    need(manifest["specimen_sha256"] == old["sha256"] == SPECIMEN and
         manifest["checkpoint_archive_sha256"] == CHECKPOINT and
         manifest["preflight_sha256"] == PREFLIGHT, "native provenance mismatch")
    need(set(manifest["files"]) == {hx(a) + ext for a in
         (0x68d080, 0x68d280, 0x68d2e0, 0x68d2f0, 0x6c38c0, 0x6c38f0, 0x6ce110)
         for ext in (".asm", ".c")}, "native export inventory mismatch")
    for name, meta in manifest["files"].items():
        raw = (exports / name).read_bytes()
        need(len(raw) == meta["bytes"] and sha(raw) == meta["sha256"], "native export mismatch: " + name)
    old_sites = {int(s["address"], 16): s for s in old["sites"]}
    need(len(old_sites) == 7, "preflight site inventory mismatch")
    result = {}
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    for entry, (size, expected_name) in BODIES.items():
        name = hx(entry)
        site = old_sites[entry]
        need(site["function_name"] == expected_name and site["instruction_exists"] is True and
             site["body_addresses"] == size, "exact-old native name/body mismatch: " + name)
        off = pe_offset(pe, entry, size)
        body = pe[off:off + size]
        ins = list(md.disasm(body, entry))
        need(ins and sum(i.size for i in ins) == size and ins[-1].address + ins[-1].size == entry + size,
             "incomplete body decode: " + name)
        native = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$",
                  (exports / (name + ".asm")).read_text(encoding="utf-8-sig"), re.M)]
        need(len(native) == len(ins), "native instruction count mismatch: " + name)
        starts = {i.address for i in ins}
        for i, (address, line) in zip(ins, native):
            need(i.address == address and normalized(i.mnemonic + " " + i.op_str) == normalized(line),
                 "PE/native opcode or operand mismatch at " + hx(i.address) + ": " + i.mnemonic + " " + i.op_str + " / " + line)
        edges, branches, calls, reads, writes = {}, [], [], [], []
        for i in ins:
            fall = i.address + i.size
            if i.mnemonic == "ret":
                targets = []
            elif i.mnemonic.startswith("j"):
                need(len(i.operands) == 1 and i.operands[0].type == capstone.x86.X86_OP_IMM,
                     "indirect branch at " + hx(i.address))
                targets = [i.operands[0].imm] + ([] if i.mnemonic == "jmp" else [fall])
                branches.append([hx(i.address), i.mnemonic, [hx(a) for a in targets]])
            else:
                targets = [fall]
            need(all(a in starts for a in targets), "CFG escapes body at " + hx(i.address))
            edges[i.address] = targets
            if i.mnemonic == "call":
                need(len(i.operands) == 1 and i.operands[0].type == capstone.x86.X86_OP_IMM,
                     "unexpected indirect call at " + hx(i.address))
                calls.append([hx(i.address), hx(i.operands[0].imm)])
            for op in i.operands:
                if op.type != capstone.x86.X86_OP_MEM or i.mnemonic == "lea":
                    continue
                row = [hx(i.address), op.size, i.mnemonic, i.op_str]
                if op.access & capstone.CS_AC_READ:
                    reads.append(row)
                if op.access & capstone.CS_AC_WRITE:
                    writes.append(row)
        reached, pending = set(), [entry]
        while pending:
            a = pending.pop()
            if a not in reached:
                reached.add(a)
                pending.extend(edges[a])
        need(reached == starts, "unreachable local instruction: " + name)
        need({int(a, 16): int(b, 16) for a, b in calls} == CALLS[entry],
             "direct call set changed: " + name)
        result[name] = {
            "entry_va": name, "file_offset": hx(off), "body_bytes": size, "body_sha256": sha(body),
            "old_native_name": expected_name, "old_library_comment_sha256":
                sha(site["function_comment"].encode()) if "function_comment" in site else None,
            "instruction_count": len(ins), "all_native_operands_match": True,
            "all_instructions_reachable": True,
            "instruction_starts_sha256": sha(("\n".join(hx(i.address) for i in ins) + "\n").encode()),
            "local_edge_count": sum(len(v) for v in edges.values()), "branches": branches,
            "direct_calls": calls,
            "selected_instructions": {hx(i.address): i.mnemonic + " " + i.op_str for i in ins
                                      if i.address in SELECTED},
            "returns": [[hx(i.address), int(i.op_str or "0", 0)] for i in ins if i.mnemonic == "ret"],
            "explicit_memory_reads": reads, "explicit_memory_writes": writes,
            "implicit_string_memory": [[hx(i.address), i.mnemonic, i.op_str] for i in ins
                                       if i.mnemonic.startswith("rep movs")],
            "native_export_hashes": {ext: manifest["files"][name + "." + ext]["sha256"]
                                     for ext in ("asm", "c")},
            "scope": "complete local body"
        }
    return {"schema_version": 1, "unit": "R29-C", "address_kind": "virtual unless file_offset is explicit",
            "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": CHECKPOINT,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "scope": "complete local PE/native bodies; release and allocator calls are separate boundaries",
            "python_optimized_integrity": "explicit ValueError gates, no assert", "bodies": result}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = extract(a.binary, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("verified R29-C PE/native bodies:", [(k, v["instruction_count"]) for k, v in result["bodies"].items()])

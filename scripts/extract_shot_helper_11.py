#!/usr/bin/env python3
"""Extract compact static R11-A evidence; never emit executable bytes or bulk code.

Requires Capstone 5.0.7 and the private pinned specimen. Optional read-only
Ghidra assembly exports corroborate owned instruction addresses and direct calls.
This is not an emulator and does not certify dynamic paths or helper effects.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
BASELINE = "2c6bb83f13c92a3f9d2309e71e5e77aac7715383"
OWNED_START, OWNED_END = 0x7103e0, 0x7109eb
LOOPS = [
    (0x7105dc, 0x7105fd, 0x71061b, 0x710637, 0x71064e, "owner continuation"),
    (0x7106e4, 0x710705, 0x710723, 0x71073f, 0x710756, "entry float gate"),
    (0x710778, 0x710799, 0x7107b7, 0x7107d3, 0x7107ea, "R(20)==0 and slot10d==0"),
    (0x710837, 0x710858, 0x710876, 0x710892, 0x7108a9, "state5 distance and slot10d gate"),
    (0x7108f1, 0x710912, 0x710930, 0x71094c, 0x710963, "nonowner slot2b!=0"),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hx(n):
    return f"{n:08x}"


def run(args):
    data = args.binary.read_bytes()
    if digest(data) != SHA:
        raise ValueError("specimen SHA-256 mismatch")
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires Capstone 5.0.7 for reproducible decoding")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("expected PE image")
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optsize = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x10b:
        raise ValueError("expected PE32")
    imagebase = struct.unpack_from("<I", data, optional + 28)[0]
    sections = []
    for n in range(count):
        pos = optional + optsize + 40 * n
        _, rva, rawsize, rawoffset = struct.unpack_from("<IIII", data, pos + 8)
        sections.append((rva, rawsize, rawoffset))

    def offset(va, size):
        for rva, rawsize, rawoffset in sections:
            delta = va - imagebase - rva
            if 0 <= delta and delta + size <= rawsize:
                return rawoffset + delta
        raise ValueError(f"VA range not backed by one raw section: {va:x}+{size:x}")

    def read(va, size):
        off = offset(va, size)
        return data[off:off + size]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    def decode(start, end):
        rows = list(md.disasm(read(start, end - start), start))
        cursor = start
        for row in rows:
            if row.address != cursor:
                raise ValueError("non-contiguous decode")
            cursor += row.size
        if cursor != end:
            raise ValueError(f"incomplete decode {start:x}..{end:x}")
        return rows

    rows = decode(OWNED_START, OWNED_END)
    at = {i.address: i for i in rows}

    def direct_calls(instructions):
        return [(i.address, i.operands[0].imm) for i in instructions
                if i.mnemonic == "call" and i.operands[0].type == CS_OP_IMM]

    calls = direct_calls(rows)
    result = dict(
        investigation=11, work_unit="R11-A", baseline_commit=BASELINE,
        specimen_sha256=SHA, address_kind="virtual addresses; raw offsets explicitly labelled",
        evidence_class="static assembly mapping; no new original-instruction oracle",
        owned_range=dict(start=hx(OWNED_START), end_exclusive=hx(OWNED_END), bytes=OWNED_END-OWNED_START,
                         file_offset=f"0x{offset(OWNED_START, OWNED_END-OWNED_START):x}",
                         sha256=digest(read(OWNED_START, OWNED_END-OWNED_START)),
                         instruction_count=len(rows), direct_call_count=len(calls)),
        direct_calls=[dict(site=hx(site), target=hx(target)) for site, target in calls],
        rng_sites=[hx(site) for site, target in calls if target == 0x90cfc0],
        abi=dict(entry="ECX=slot; no explicit stack arguments", return_cleanup=0,
                 preserves=["EBX", "ESI", "EDI"], return_value="no meaningful result established",
                 return_sites=[hx(i.address) for i in rows if i.mnemonic == "ret"]),
        loop_sites=[dict(entry=hx(a), predicate_call=hx(b), rng900=hx(c),
                         candidate_boundary=hx(d), backedge=hx(e), path=f)
                    for a,b,c,d,e,f in LOOPS],
        limitations=["Names and field meanings remain provisional",
                     "No caller reachability or transitive side-effect certification",
                     "Large callees are immediate ABI boundaries only; their bodies are unassigned",
                     "No behavioral port, connected attempt oracle or complete outcome claim"],
    )
    for _, pred, rng, callee, backedge, _ in LOOPS:
        assert (pred, 0x6bce20) in calls
        assert (rng, 0x90cfc0) in calls
        assert (callee, 0x714d40) in calls
        assert at[backedge].mnemonic == "jl"

    # Source-level assertions protect the width/operand facts authored below.
    writes = [
        (0x71065f, "byte", "match+1a7", "0"),
        (0x710758, "word", "slot+198", "67"),
        (0x7107ef, "word", "slot+35", "add -15 (word wrap)"),
        (0x7107f6, "word", "slot+198", "67"),
        (0x710801, "byte", "slot+2b", "1 if previously zero"),
        (0x71081e, "float32", "slot+4d", "x87 slot4d + 5 + R(5)"),
        (0x7108ae, "word", "slot+198", "67"),
        (0x7108bb, "byte", "slot+2b", "1 if previously zero"),
        (0x7108d8, "float32", "slot+4d", "x87 slot4d + 5 + R(5)"),
        (0x710965, "word", "slot+198", "67"),
    ]
    for site, width, target, _ in writes:
        i = at[site]
        assert i.mnemonic in ("mov", "add", "fstp")
        assert i.operands[0].size == {"byte":1, "word":2, "float32":4}[width]
        assert i.operands[0].mem.disp == int(target.split("+")[1], 16)
    result["direct_external_writes"] = [dict(site=hx(a), width=b, target=c, value=d) for a,b,c,d in writes]
    # Check that the write list is exhaustive for explicit non-frame destinations.
    external = []
    for i in rows:
        if i.mnemonic in ("mov", "add", "fstp") and i.operands[0].type == capstone.CS_OP_MEM:
            if i.reg_name(i.operands[0].mem.base) != "esp":
                external.append(i.address)
    assert external == [w[0] for w in writes], external

    result["constants"] = [dict(va="0096d818", kind="float64", value=struct.unpack("<d",read(0x96d818,8))[0]),
                           dict(va="0096d754", kind="float32", value=struct.unpack("<f",read(0x96d754,4))[0]),
                           dict(va="00968e18", kind="float64", value=struct.unpack("<d",read(0x968e18,8))[0])]
    caller_ranges = [(0x702180,0x7021b5),(0x703e19,0x703eca),(0x6beacd,0x6beb12),(0x6beda9,0x6bedb5)]
    result["dependency_selected_ranges"] = []
    for start,end in caller_ranges:
        selected = decode(start,end)
        result["dependency_selected_ranges"].append(dict(start=hx(start), end_exclusive=hx(end),
            sha256=digest(read(start,end-start)), instruction_count=len(selected),
            direct_calls=[dict(site=hx(a),target=hx(b)) for a,b in direct_calls(selected)]))

    if args.exports:
        export = (args.exports / "007103e0.asm").read_bytes()
        text = export.decode("utf-8-sig").replace("\r\n", "\n")
        addresses = [int(m.group(1),16) for m in re.finditer(r"^([0-9a-fA-F]{8})\s",text,re.M)]
        export_calls = [(int(m.group(1),16),int(m.group(2),16)) for m in
                        re.finditer(r"^([0-9a-fA-F]{8})\s+CALL 0x([0-9a-fA-F]+)$",text,re.M)]
        assert addresses == [i.address for i in rows], "native address mismatch"
        assert export_calls == calls, "native call mismatch"
        result["native_owned_corroboration"] = dict(export_sha256=digest(export),
            all_instruction_addresses_match=True, all_direct_call_sites_targets_match=True)
        boundaries = []
        for entry, size, cleanup, callsite, arg in [
            (0x7109f0,13162,4,0x710654,"pushed dword0"),
            (0x713fc0,3226,4,0x7109d1,"1"),
            (0x714d40,4583,0,0x7109df,"no explicit stack argument"),
        ]:
            src = (args.exports / f"{entry:08x}.asm").read_bytes()
            returns = [(int(m.group(1),16),int(m.group(2) or "0",16)) for m in
                       re.finditer(r"^([0-9a-fA-F]{8})\s+RET(?: 0x([0-9a-fA-F]+))?$",src.decode("utf-8-sig").replace("\r\n", "\n"),re.M)]
            assert returns and all(n == cleanup for _,n in returns)
            for site, n in returns:
                instructions = decode(site, site + (3 if n else 1))
                assert len(instructions) == 1 and instructions[0].mnemonic == "ret"
                assert (instructions[0].operands[0].imm if n else 0) == cleanup
            assert (callsite,entry) in calls
            boundaries.append(dict(entry=hx(entry), declared_bytes=size,
                code_range_sha256=digest(read(entry,size)), export_sha256=digest(src),
                representative_owned_call=hx(callsite), explicit_argument=arg, ecx="slot pointer",
                return_cleanup=cleanup, return_sites=[hx(a) for a,_ in returns],
                scope="immediate entry/call/return boundary only; no body contract"))
        result["large_callee_boundaries"] = boundaries
        manifest_path = args.exports / "EXPORT-MANIFEST.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            byname = {item["name"]:item for item in manifest}
            for name in ["007103e0.asm", "007109f0.asm", "00713fc0.asm", "00714d40.asm"]:
                src = (args.exports / name).read_bytes()
                assert byname[name]["sha256"] == digest(src)
                assert byname[name]["bytes"] == len(src)
            result["native_manifest_check"] = dict(sha256=digest(manifest_path.read_bytes()),
                relevant_export_count=4, all_relevant_digests_and_sizes_match=True)
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, help="private read-only exports-11 directory")
    parser.add_argument("--output", type=Path)
    run(parser.parse_args())

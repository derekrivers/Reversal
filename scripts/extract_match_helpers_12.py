#!/usr/bin/env python3
"""Extract bounded R12-A static evidence without publishing code or game data.

Requires Capstone 5.0.7, the pinned private PE32 executable and read-only R12
Ghidra exports. This is a decoder/corroboration check, not an execution oracle.
"""

# Integrity assertions must remain active before reading or writing evidence.
if not __debug__:
    raise SystemExit("Integrity checks require assertions; rerun without Python optimization (-O/-OO).")
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
BASELINE = "a5972e1659afa4b2937490cdc57ebd8f4a5887d3"
RANGES = [(0x6f09b0, 0x6f09ed), (0x6cb960, 0x6cb9a3), (0x6bce20, 0x6bce7f)]
CALLER = (0x7103e0, 0x7109eb)
LOOPS = [0x7105dc, 0x7106e4, 0x710778, 0x710837, 0x7108f1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hx(value):
    return f"{value:08x}"


def run(args):
    data = args.binary.read_bytes()
    if digest(data) != SHA:
        raise ValueError("specimen SHA-256 mismatch")
    if capstone.__version__ != "5.0.7":
        raise ValueError("requires Capstone 5.0.7")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("expected PE image")
    count, optsize = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    if struct.unpack_from("<H", data, optional)[0] != 0x10b:
        raise ValueError("expected PE32")
    base = struct.unpack_from("<I", data, optional + 28)[0]
    sections = []
    for n in range(count):
        pos = optional + optsize + 40 * n
        _, rva, size, offset = struct.unpack_from("<IIII", data, pos + 8)
        sections.append((rva, size, offset))

    def file_offset(va, size):
        for rva, raw_size, offset in sections:
            delta = va - base - rva
            if 0 <= delta and delta + size <= raw_size:
                return offset + delta
        raise ValueError("range is not backed by one raw PE section")

    def read(va, size):
        offset = file_offset(va, size)
        return data[offset:offset + size]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    def decode(start, end):
        rows = list(md.disasm(read(start, end - start), start))
        cursor = start
        for row in rows:
            assert row.address == cursor, "non-contiguous decode"
            cursor += row.size
        assert cursor == end, "incomplete decode"
        return rows

    def calls(rows):
        return [(i.address, i.operands[0].imm) for i in rows
                if i.mnemonic == "call" and i.operands[0].type == CS_OP_IMM]

    def metadata(start, end, rows):
        return dict(start=hx(start), end_exclusive=hx(end), bytes=end - start,
                    raw_file_offset=f"0x{file_offset(start, end - start):x}",
                    code_sha256=digest(read(start, end - start)), instruction_count=len(rows))

    result = dict(work_unit="R12-A", baseline_commit=BASELINE, specimen_sha256=SHA,
                  address_kind="virtual addresses; raw file offsets explicitly labelled",
                  evidence_class="static original-instruction mapping; no execution oracle",
                  decoder="Capstone 5.0.7 x86-32", functions=[])
    all_owned = {}
    for start, end in RANGES:
        rows = decode(start, end)
        all_owned.update({i.address: i for i in rows})
        item = metadata(start, end, rows)
        item["direct_calls"] = [dict(site=hx(a), target=hx(b)) for a, b in calls(rows)]
        item["returns"] = [dict(site=hx(i.address), cleanup_bytes=i.operands[0].imm)
                           for i in rows if i.mnemonic == "ret"]
        expected_returns = {
            0x6f09b0: [("006f09ea", 8)],
            0x6cb960: [("006cb982", 12), ("006cb99b", 12), ("006cb9a0", 12)],
            0x6bce20: [("006bce76", 12), ("006bce7c", 12)],
        }
        assert [(r["site"], r["cleanup_bytes"]) for r in item["returns"]] == expected_returns[start]
        # Explicit stores to memory are absent. PUSH/POP/CALL/RET have stack effects.
        stores = [i.address for i in rows for operand in i.operands
                  if operand.type == CS_OP_MEM and operand.access & capstone.CS_AC_WRITE]
        assert stores == [], stores
        item["explicit_memory_store_sites"] = []
        asm = (args.exports / f"{hx(start)}.asm").read_bytes()
        text = asm.decode("utf-8-sig")
        addresses = [int(m.group(1), 16) for m in re.finditer(r"^([0-9a-fA-F]{8})\s", text, re.M)]
        exported_calls = [(int(m.group(1), 16), int(m.group(2), 16)) for m in
                          re.finditer(r"^([0-9a-fA-F]{8})\s+CALL 0x([0-9a-fA-F]+)", text, re.M)]
        assert addresses == [i.address for i in rows], "export instruction addresses differ"
        assert exported_calls == calls(rows), "export direct calls differ"
        refs = (args.exports / f"{hx(start)}.refs").read_bytes()
        pseudocode = (args.exports / f"{hx(start)}.c").read_bytes()
        exported_name = re.search(r"\b(FUN_[0-9a-f]{8})\(", pseudocode.decode("utf-8-sig")).group(1)
        assert exported_name == f"FUN_{hx(start)}"
        ref_sites = [int(m.group(1), 16) for m in re.finditer(
            r"^([0-9a-fA-F]{8}) UNCONDITIONAL_CALL\s*$", refs.decode("utf-8-sig"), re.M)]
        for site in ref_sites:
            instructions = decode(site, site + 5)
            assert calls(instructions) == [(site, start)], "incoming reference not an original direct call"
        item["native_corroboration"] = dict(asm_sha256=digest(asm), refs_sha256=digest(refs),
            pseudocode_sha256=digest(pseudocode), checkpoint_11_exported_name=exported_name,
            reference_count=len(ref_sites), all_reference_targets_verified=True,
            instruction_addresses_and_direct_calls_agree=True)
        result["functions"].append(item)

    # Protect selected width/sign/cleanup facts; no code bytes or bulk listing emitted.
    expected = {
        0x6f09b0: ("movsx", "eax, byte ptr [ecx + 0x103]"),
        0x6f09b7: ("movsx", "edx, byte ptr [esp + 8]"),
        0x6f09c4: ("movsx", "eax, al"),
        0x6f09ca: ("movsx", "eax, byte ptr [ecx + 0x102]"),
        0x6f09d1: ("movsx", "ecx, byte ptr [esp + 8]"),
        0x6f09dd: ("movsx", "edx, al"),
        0x6f09e2: ("fld", "dword ptr [esi*4 + 0xa15e44]"),
        0x6cb960: ("mov", "al, byte ptr [esp + 4]"),
        0x6cb966: ("mov", "al, byte ptr [esp + 8]"),
        0x6cb96e: ("jl", "0x6cb99e"),
        0x6cb97e: ("jg", "0x6cb99e"),
        0x6cb991: ("test", "al, al"),
        0x6cb993: ("jl", "0x6cb99e"),
        0x6cb99e: ("xor", "al, al"),
        0x6bce23: ("mov", "ecx, dword ptr [esp + 8]"),
        0x6bce31: ("mov", "dl, byte ptr [esp + 0xc]"),
        0x6bce3f: ("mov", "al, byte ptr [esp + 0x10]"),
        0x6bce47: ("cmp", "byte ptr [ecx + 0x2b], 2"),
        0x6bce4b: ("jge", "0x6bce79"),
        0x6bce4d: ("cmp", "ecx, dword ptr [esi + 0xf582]"),
        0x6bce55: ("cmp", "ecx, dword ptr [esi + 0xf57a]"),
        0x6bce5d: ("call", "0x6f4600"),
        0x6bce66: ("mov", "al, byte ptr [esi + 0x8eb2]"),
        0x6bce70: ("mov", "eax, 1"),
        0x6bce79: ("xor", "eax, eax"),
    }
    for site, expected_instruction in expected.items():
        row = all_owned[site]
        assert (row.mnemonic, row.op_str) == expected_instruction, hx(site)
    result["checked_contract_sites"] = [hx(a) for a in expected]
    assert [(a, b) for item in result["functions"] for a, b in
            [(int(c["site"], 16), int(c["target"], 16)) for c in item["direct_calls"]]] == [(0x6bce5d, 0x6f4600)]

    caller_rows = decode(*CALLER)
    at = {i.address: i for i in caller_rows}
    owned_calls = [(a, b) for a, b in calls(caller_rows) if b in [s for s, _ in RANGES]]
    expected_calls = [(0x7104b9, 0x6cb960), (0x710560, 0x6f09b0),
                      (0x7105fd, 0x6bce20), (0x710705, 0x6bce20),
                      (0x710799, 0x6bce20), (0x710858, 0x6bce20),
                      (0x710912, 0x6bce20), (0x7109bb, 0x6cb960)]
    assert owned_calls == expected_calls
    # Three register arrangements establish equivalent low-byte/pointer arguments.
    setup_variants = [
        [("mov", "dl, byte ptr [esi + 0x103]"), ("movsx", "ecx, al"),
         ("mov", "al, byte ptr [esi + 0x102]"), ("push", "edx"),
         ("lea", "edi, [esi + ecx*4 + 0x1ae]"), ("push", "eax"),
         ("mov", "ecx, dword ptr [edi]"), ("push", "ecx"),
         ("mov", "ecx, dword ptr [esi + 0x19e]")],
        [("mov", "cl, byte ptr [esi + 0x103]"), ("mov", "dl, byte ptr [esi + 0x102]"),
         ("movsx", "eax, al"), ("push", "ecx"), ("mov", "ecx, dword ptr [esi + 0x19e]"),
         ("lea", "edi, [esi + eax*4 + 0x1ae]"), ("push", "edx"),
         ("mov", "eax, dword ptr [edi]"), ("push", "eax")],
        [("mov", "cl, byte ptr [esi + 0x102]"), ("movsx", "edx, al"),
         ("mov", "al, byte ptr [esi + 0x103]"), ("lea", "edi, [esi + edx*4 + 0x1ae]"),
         ("push", "eax"), ("push", "ecx"), ("mov", "ecx, dword ptr [esi + 0x19e]"),
         ("mov", "edx, dword ptr [edi]"), ("push", "edx")],
    ]
    setups = []
    for start, variant in zip(LOOPS, [0, 0, 1, 2, 1]):
        end = start + 0x21
        rows = decode(start, end)
        sequence = [(i.mnemonic, i.op_str) for i in rows]
        assert sequence == setup_variants[variant]
        setups.append(metadata(start, end, rows))
    assert (at[0x71055a].mnemonic, at[0x71055a].op_str) == ("push", "0")
    assert (at[0x71055c].mnemonic, at[0x71055c].op_str) == ("push", "4")
    assert (at[0x710565].mnemonic, at[0x710565].op_str) == ("fstp", "dword ptr [esp + 0x10]")
    for start, callsite in [(0x7104a3, 0x7104b9), (0x7109a5, 0x7109bb)]:
        expected_setup = [("mov", "cl, byte ptr [edi + 0x8ea8]"),
            ("mov", "dl, byte ptr [edi + 0x8ea7]"), ("test", "al, al"),
            ("push", "ecx"), ("push", "edx"), ("sete", "al"),
            ("push", "eax"), ("mov", "ecx, edi")]
        assert [(i.mnemonic, i.op_str) for i in decode(start, callsite)] == expected_setup
    result["caller_boundary"] = metadata(*CALLER, caller_rows)
    result["caller_boundary"]["owned_calls"] = [dict(site=hx(a), target=hx(b)) for a, b in owned_calls]
    result["caller_boundary"]["five_equivalent_candidate_setups"] = setups
    # Read-only dependency boundary, not a full-body behavioral claim.
    result["unresolved_dependency"] = dict(entry="006f4600", owned_call_site="006bce5d",
        entry_register="ECX=candidate", explicit_stack_arguments=0,
        consumed_result="AL nonzero", full_body_and_transitive_effects="unassigned")
    result["limitations"] = ["No execution oracle or new reconstruction",
        "No full grid data, helper code bytes, decompilation or private paths emitted",
        "No safe coordinate bounds or live match reachability established",
        "006f4600 transitive reads/writes/RNG and ABI preservation remain unverified"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args())

#!/usr/bin/env python3
"""Verify compact R13-A static evidence from private PE and Ghidra exports.

Requires Capstone 5.0.7. Emits metadata/sites only, never original code bytes.
This is an instruction decoder check, not an execution oracle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "fa2728212d3189f2a0ec9f4db14b2355b0da8457bc9bff091d5c2b442b38a489"
RANGES = [(0x6f4600, 0x6f4642), (0x5b57c0, 0x5b57cf), (0x6f46b0, 0x6f491c)]


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
    manifest_data = (args.exports / "EXPORT-MANIFEST.json").read_bytes()
    if digest(manifest_data) != MANIFEST_SHA:
        raise ValueError("export manifest SHA-256 mismatch")
    manifest = json.loads(manifest_data)
    exported = {f["name"]: f for f in manifest["files"]}
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0"
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optsize = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x10b
    base = struct.unpack_from("<I", data, optional + 28)[0]
    sections = []
    for n in range(count):
        _, rva, size, offset = struct.unpack_from("<IIII", data, optional + optsize + 40*n + 8)
        sections.append((rva, size, offset))

    def file_offset(va, size):
        for rva, raw_size, offset in sections:
            delta = va - base - rva
            if 0 <= delta and delta + size <= raw_size:
                return offset + delta
        raise ValueError("range not backed by one raw PE section")

    def read(va, size):
        offset = file_offset(va, size)
        return data[offset:offset + size]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    def decode(start, end):
        rows = list(md.disasm(read(start, end-start), start))
        cursor = start
        for row in rows:
            assert row.address == cursor, "noncontiguous decode"
            cursor += row.size
        assert cursor == end, "incomplete decode"
        return rows

    def calls(rows):
        return [(i.address, i.operands[0].imm) for i in rows
                if i.mnemonic == "call" and i.operands[0].type == CS_OP_IMM]

    def metadata(start, end, rows):
        return dict(start=hx(start), end_exclusive=hx(end), bytes=end-start,
                    raw_file_offset=f"0x{file_offset(start, end-start):x}",
                    code_sha256=digest(read(start, end-start)), instruction_count=len(rows))

    result = dict(work_unit="R13-A", baseline_commit="87ea0f39d5dcb62fe6969ad6570c3dca8b152673",
                  specimen_sha256=SHA, export_manifest_sha256=MANIFEST_SHA,
                  address_kind="virtual addresses; raw file offsets explicitly labelled",
                  evidence_class="static original-instruction mapping; no execution oracle",
                  decoder="Capstone 5.0.7 x86-32", functions=[])
    owned = {}
    for start, end in RANGES:
        rows = decode(start, end)
        owned.update({i.address: i for i in rows})
        item = metadata(start, end, rows)
        item["direct_calls"] = [dict(site=hx(a), target=hx(b)) for a, b in calls(rows)]
        item["returns"] = [dict(site=hx(i.address), cleanup_bytes=i.operands[0].imm if i.operands else 0)
                           for i in rows if i.mnemonic == "ret"]
        item["explicit_memory_store_sites"] = [hx(i.address) for i in rows
            if any(op.type == CS_OP_MEM and op.access & capstone.CS_AC_WRITE for op in i.operands)]
        item["branches"] = [dict(site=hx(i.address), kind=i.mnemonic, target=hx(i.operands[0].imm))
                            for i in rows if i.mnemonic.startswith("j")]
        for branch in item["branches"]:
            assert int(branch["target"], 16) in {i.address for i in rows}
        corroboration = {}
        texts = {}
        for suffix in ("asm", "c", "refs"):
            name = f"{hx(start)}.{suffix}"
            raw = (args.exports / name).read_bytes()
            assert len(raw) == exported[name]["bytes"] and digest(raw) == exported[name]["sha256"]
            corroboration[f"{suffix}_sha256"] = digest(raw)
            texts[suffix] = raw.decode("utf-8-sig")
        addresses = [int(m.group(1), 16) for m in re.finditer(r"^([0-9a-fA-F]{8})\s", texts["asm"], re.M)]
        assert addresses == [i.address for i in rows]
        exported_calls = [(int(m.group(1), 16), int(m.group(2), 16)) for m in
            re.finditer(r"^([0-9a-fA-F]{8})\s+CALL 0x([0-9a-fA-F]+)", texts["asm"], re.M)]
        assert exported_calls == calls(rows)
        assert f"FUN_{hx(start)}(" in texts["c"]
        refs = [int(m.group(1), 16) for m in re.finditer(
            r"^([0-9a-fA-F]{8}) UNCONDITIONAL_CALL\s*$", texts["refs"], re.M)]
        for site in refs:
            assert calls(decode(site, site+5)) == [(site, start)]
        corroboration.update(checkpoint_12_exported_name=f"FUN_{hx(start)}",
            reference_count=len(refs), all_reference_targets_verified=True,
            instruction_addresses_and_direct_calls_agree=True)
        item["native_corroboration"] = corroboration
        item["incoming_direct_call_sites"] = [hx(a) for a in refs]
        result["functions"].append(item)

    # Selected exact operands protect byte sign extension, ABI and non-equivalent paths.
    expected = {
        0x5b57c0: ("movsx", "eax, byte ptr [esp + 4]"),
        0x5b57c5: ("mov", "al, byte ptr [eax + ecx + 0x5b4]"),
        0x6f4603: ("mov", "al, byte ptr [esi + 0x19]"),
        0x6f4607: ("movsx", "eax, byte ptr [esi + 0x27]"),
        0x6f460b: ("lea", "ecx, [eax + eax*4]"),
        0x6f460e: ("shl", "ecx, 5"),
        0x6f4611: ("sub", "ecx, eax"),
        0x6f4613: ("lea", "ecx, [eax + ecx*4]"),
        0x6f4616: ("lea", "edx, [ecx + ecx*4]"),
        0x6f461f: ("lea", "eax, [eax + edx*2]"),
        0x6f4619: ("mov", "ecx, dword ptr [esi + 0x19e]"),
        0x6f4622: ("lea", "ecx, [eax + ecx + 0x91e2]"),
        0x6f462e: ("test", "al, 2"),
        0x6f4632: ("mov", "al, byte ptr [esi + 0x108]"),
        0x6f463a: ("mov", "al, byte ptr [esi + 0x10a]"),
        0x6f46b6: ("mov", "dl, byte ptr [esp + 4]"),
        0x6f46c3: ("mov", "bl, byte ptr [esp + 0x210]"),
        0x6f46dd: ("cmp", "al, 0xff"),
        0x6f46e3: ("jle", "0x6f4819"),
        0x6f4729: ("movsx", "esi, byte ptr [ecx + 0x27]"),
        0x6f472d: ("mov", "dl, byte ptr [esi + eax + 0x58]"),
        0x6f4733: ("jne", "0x6f47a4"),
        0x6f47a7: ("movsx", "edx, dl"),
        0x6f47ad: ("movsx", "ebx, byte ptr [esp + 0xf]"),
        0x6f47b6: ("mov", "edx, dword ptr [eax + edx*4 - 4]"),
        0x6f47ba: ("mov", "dword ptr [eax + ebx*4], edx"),
        0x6f47cb: ("mov", "byte ptr [edx], bl"),
        0x6f47e6: ("mov", "byte ptr [eax + 0x28], bl"),
        0x6f47f5: ("mov", "byte ptr [ecx + 0x28], dl"),
        0x6f47f8: ("inc", "byte ptr [eax]"),
        0x6f4811: ("mov", "dword ptr [edi + eax*4], ecx"),
        0x6f4844: ("mov", "byte ptr [ecx + 0x28], bl"),
        0x6f4847: ("inc", "byte ptr [eax]"),
        0x6f484d: ("cmp", "byte ptr [eax + esi + 0x58], 0xb"),
        0x6f4852: ("jle", "0x6f48c8"),
        0x6f48d4: ("mov", "dword ptr [esi + eax*4], ecx"),
        0x6f48de: ("mov", "byte ptr [ecx + 0x102], dl"),
        0x6f48e4: ("mov", "byte ptr [ecx + 0x103], al"),
        0x6f48f0: ("cmp", "ecx, dword ptr [eax + 0xf582]"),
        0x6f48f8: ("mov", "byte ptr [eax + 0x8ea7], dl"),
        0x6f490a: ("mov", "byte ptr [edx + 0x8ea8], al"),
    }
    for site, instruction in expected.items():
        row = owned[site]
        assert (row.mnemonic, row.op_str) == instruction, (hx(site), row.mnemonic, row.op_str)
    result["checked_contract_sites"] = [hx(a) for a in expected]
    assert [f["returns"] for f in result["functions"]] == [
        [dict(site="006f4639", cleanup_bytes=0), dict(site="006f4641", cleanup_bytes=0)],
        [dict(site="005b57cc", cleanup_bytes=4)],
        [dict(site="006f47a1", cleanup_bytes=8), dict(site="006f4919", cleanup_bytes=8)]]
    assert result["functions"][0]["explicit_memory_store_sites"] == []
    assert result["functions"][1]["explicit_memory_store_sites"] == []

    # Dependency context only: verify caller argument consumption and tiny wrappers.
    contexts = [(0x6bce20, 0x6bce7f), (0x6bcc90, 0x6bcc9e),
                (0x714037, 0x714051), (0x714e65, 0x714e7f),
                (0x945934, 0x945945), (0x90d130, 0x90d136), (0x5a8f60, 0x5a8f61)]
    result["dependency_context_ranges"] = [metadata(a, b, decode(a, b)) for a, b in contexts]
    at = {i.address: i for a, b in contexts for i in decode(a, b)}
    for site, instruction in {
        0x6bce5d: ("call", "0x6f4600"), 0x6bce62: ("test", "al, al"),
        0x6bcc9b: ("movsx", "edx, al"),
        0x94593c: ("call", "0x945956"), 0x945944: ("ret", ""),
        0x90d130: ("mov", "eax, 0xad4394"), 0x5a8f60: ("ret", ""),
    }.items():
        assert (at[site].mnemonic, at[site].op_str) == instruction
    result["limitations"] = ["No execution oracle or numerical equivalence claim",
        "No code bytes, bulk disassembly/pseudocode or private paths emitted",
        "Incoming references are exported direct calls, not a completeness proof",
        "Diagnostics and termination transitive effects remain open; 00945934 wrapper contains RET",
        "No live coordinate/count/side invariants or caller reachability established"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args())

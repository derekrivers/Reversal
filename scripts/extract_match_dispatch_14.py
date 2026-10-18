#!/usr/bin/env python3
"""Check R14-A static sites against the private PE and read-only native export.

Requires Capstone 5.0.7. Emits addresses, widths and digests; no original bytes
or bulk instruction listing. This decoder check is not an execution oracle.
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
MANIFEST_SHA = "233ec2078dc3eacf0d1b83a3d093028caf57c634329bacce4af4ea2efb5c7f86"
PREFLIGHT_SHA = "728f0dbb5ccd7860c03a35203f30b7bb377048879c2b95601b1744fd78e7fc3d"
START, END = 0x713fc0, 0x714c5a


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
    raw_manifest = (args.exports / "EXPORT-MANIFEST.json").read_bytes()
    if digest(raw_manifest) != MANIFEST_SHA:
        raise ValueError("export manifest SHA-256 mismatch")
    manifest = json.loads(raw_manifest)
    assert manifest["specimen_sha256"] == SHA
    raw_preflight = args.preflight.read_bytes()
    if digest(raw_preflight) != PREFLIGHT_SHA:
        raise ValueError("annotation preflight SHA-256 mismatch")
    preflight = json.loads(raw_preflight)
    assert preflight["sha256"] == SHA
    old = [s for s in preflight["sites"] if s["address"] == hx(START)]
    assert len(old) == 1 and old[0]["instruction_exists"]
    assert old[0]["function_name"] == "FUN_00713fc0"
    exported = {f["name"]: f for f in manifest["files"]}
    texts, native = {}, {}
    for suffix in ("asm", "c", "refs"):
        name = f"{hx(START)}.{suffix}"
        raw = (args.exports / name).read_bytes()
        assert len(raw) == exported[name]["bytes"]
        assert digest(raw) == exported[name]["sha256"]
        texts[suffix] = raw.decode("utf-8-sig")
        native[f"{suffix}_sha256"] = digest(raw)
    assert "FUN_00713fc0(" in texts["c"]
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe+4] == b"PE\0\0"
    assert struct.unpack_from("<H", data, pe+4)[0] == 0x14c
    count = struct.unpack_from("<H", data, pe+6)[0]
    optsize = struct.unpack_from("<H", data, pe+20)[0]
    optional = pe+24
    assert struct.unpack_from("<H", data, optional)[0] == 0x10b
    base = struct.unpack_from("<I", data, optional+28)[0]
    sections = []
    for n in range(count):
        _, rva, size, offset = struct.unpack_from("<IIII", data, optional+optsize+40*n+8)
        sections.append((rva, size, offset))

    def offset(va, length):
        for rva, size, raw in sections:
            delta = va-base-rva
            if 0 <= delta and delta+length <= size:
                return raw+delta
        raise ValueError("range not backed by one raw PE section")

    def read(va, length):
        at = offset(va, length)
        return data[at:at+length]

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    def decode(start, end):
        rows = list(md.disasm(read(start, end-start), start))
        cursor = start
        for row in rows:
            assert row.address == cursor
            cursor += row.size
        assert cursor == end
        return rows

    def calls(rows):
        return [(i.address, i.operands[0].imm) for i in rows
                if i.mnemonic == "call" and i.operands[0].type == CS_OP_IMM]

    rows = decode(START, END)
    at = {i.address: i for i in rows}
    assert [int(m.group(1), 16) for m in re.finditer(
        r"^([0-9a-fA-F]{8})\s", texts["asm"], re.M)] == list(at)
    assert [(int(m.group(1), 16), int(m.group(2), 16)) for m in re.finditer(
        r"^([0-9a-fA-F]{8})\s+CALL 0x([0-9a-fA-F]+)", texts["asm"], re.M)] == calls(rows)
    refs = [int(m.group(1), 16) for m in re.finditer(
        r"^([0-9a-fA-F]{8}) UNCONDITIONAL_CALL\s*$", texts["refs"], re.M)]
    for site in refs:
        assert calls(decode(site, site+5)) == [(site, START)]
    # Selected widths/operands protect distinctions the decompiler obscures.
    expected = {
        0x713fc0: ("sub", "esp, 0x224"),
        0x713ffb: ("test", "al, 4"),
        0x71407a: ("movsx", "ecx, bl"),
        0x714080: ("add", "eax, ecx"),
        0x714082: ("je", "0x7140a3"),
        0x714176: ("fcomp", "qword ptr [0x968950]"),
        0x71417e: ("test", "ah, 0x41"),
        0x7141a1: ("movsx", "ecx, word ptr [esi + 0x35]"),
        0x7141da: ("fstp", "dword ptr [esp + 0x2c]"),
        0x7141f4: ("test", "ah, 1"),
        0x714286: ("movsx", "eax, byte ptr [edx + 0x1a]"),
        0x714355: ("test", "ah, 1"),
        0x7143cb: ("mov", "byte ptr [esp + 0x20], al"),
        0x7143fa: ("and", "edx, 4"),
        0x714649: ("push", "esi"),
        0x71464a: ("mov", "byte ptr [esp + 0x13], 0"),
        0x7146af: ("test", "dword ptr [ecx + 0x9766], 0x1000"),
        0x7146c7: ("movsx", "eax, byte ptr [esp + 0xf]"),
        0x7146e0: ("jg", "0x714743"),
        0x714733: ("movsx", "edi, al"),
        0x714741: ("jge", "0x714764"),
        0x714754: ("and", "edx, 0xb"),
        0x71475b: ("cdq", ""),
        0x71475c: ("sub", "eax, edx"),
        0x71475e: ("sar", "eax, 1"),
        0x714782: ("test", "al, al"),
        0x7147ca: ("mov", "dword ptr [esp + 0x10], eax"),
        0x7147df: ("cmp", "cl, 0xfb"),
        0x7147e8: ("cmp", "cl, 0xff"),
        0x71485f: ("fnstsw", "ax"),
        0x714861: ("test", "ah, 0x41"),
        0x714888: ("cmp", "al, 2"),
        0x71488c: ("cmp", "al, 8"),
        0x714894: ("cmp", "al, 6"),
        0x714898: ("test", "al, al"),
        0x71493e: ("movsx", "eax, al"),
        0x71495d: ("jle", "0x71497d"),
        0x7149a5: ("cmp", "bx, 1"),
        0x714a5c: ("test", "bl, 6"),
        0x714b18: ("fld", "dword ptr [esi + 0xe1]"),
        0x714b1e: ("fadd", "dword ptr [0x968a78]"),
        0x714ba4: ("test", "byte ptr [esp + 0x10], 6"),
    }
    for site, pair in expected.items():
        assert (at[site].mnemonic, at[site].op_str) == pair, (hx(site), at[site].mnemonic, at[site].op_str)
    stores = [i for i in rows if any(op.type == CS_OP_MEM and op.access & capstone.CS_AC_WRITE
                                      for op in i.operands)]
    state_stores = [i for i in stores if any(op.type == CS_OP_MEM and op.access & capstone.CS_AC_WRITE
                         and i.reg_name(op.mem.base) != "esp" for op in i.operands)]
    expected_stores = {
        0x71400a: (2, "slot+198", "ffff"), 0x714043: (2, "slot+198", "68"),
        0x7140eb: (2, "slot+198", "100"), 0x714225: (2, "slot+35", "+7 wrapping"),
        0x714234: (2, "slot+198", "6a"), 0x7142ce: (2, "slot+198", "6a"),
        0x71437e: (2, "slot+35", "+7 wrapping"), 0x71438d: (2, "slot+198", "6a"),
        0x7147f1: (2, "slot+198", "105"), 0x71491e: (4, "00b67a34", "0"),
        0x714963: (2, "slot+198", "6b"), 0x7149bf: (2, "slot+198", "76"),
        0x714a29: (2, "slot+35", "+7 wrapping"), 0x714a38: (2, "slot+198", "6a"),
        0x714a8f: (2, "slot+35", "+7 wrapping"), 0x714a9e: (2, "slot+198", "69"),
        0x714ace: (2, "slot+198", "76"), 0x714afe: (2, "slot+198", "76"),
        0x714b71: (2, "slot+35", "+7 wrapping"), 0x714b80: (2, "slot+198", "6a"),
        0x714bd9: (2, "slot+35", "+7 wrapping"), 0x714be8: (2, "slot+198", "69"),
        0x714c14: (2, "slot+198", "68"), 0x714c40: (2, "slot+198", "68"),
    }
    assert [i.address for i in state_stores] == list(expected_stores)
    for i in state_stores:
        assert i.operands[0].size == expected_stores[i.address][0]
        if i.mnemonic == "mov":
            assert i.operands[1].imm == int(expected_stores[i.address][2], 16)
        else:
            assert i.mnemonic == "add" and i.operands[1].imm == 7
    branches = [dict(site=hx(i.address), kind=i.mnemonic, target=hx(i.operands[0].imm))
                for i in rows if i.mnemonic.startswith("j")]
    for branch in branches:
        assert int(branch["target"], 16) in at
    # All local paths are acyclic, although layout contains backward jumps.
    visiting, maximum = set(), {}

    def max_rng(site):
        if site in maximum:
            return maximum[site]
        assert site not in visiting, "local control flow cycle"
        visiting.add(site)
        i = at[site]
        successors = [] if i.mnemonic == "ret" else [site+i.size]
        if i.mnemonic.startswith("j"):
            successors = [i.operands[0].imm] + ([] if i.mnemonic == "jmp" else successors)
        own = int(i.mnemonic == "call" and i.operands[0].imm == 0x90cfc0)
        maximum[site] = own + max((max_rng(s) for s in successors), default=0)
        visiting.remove(site)
        return maximum[site]

    upper = max_rng(START)
    returns = [dict(site=hx(i.address), cleanup_bytes=i.operands[0].imm)
               for i in rows if i.mnemonic == "ret"]
    assert len(returns) == 16 and all(r["cleanup_bytes"] == 4 for r in returns)
    rng = {
        0x714075: ("20", "match f57a==slot and either sentinel byte is ff"),
        0x7141de: ("20 if tactical mask40h set else 50", "special region/distance route"),
        0x71428b: ("s8(byte(dword(slot+6d)+1a))", "other route and flags EAX bit21"),
        0x714294: ("5", "immediately after 0071428b"),
        0x71433f: ("20 if tactical mask40h set else 50", "other route after failed/bypassed bit21 path"),
        0x7146d3: ("0,16,18 or20", "team mask1000h with nonzero match+6+side, or flags EAX bit23"),
        0x714736: ("3", "direction/region and slot+109 gate; after optional failed 007146d3"),
        0x714849: ("21", "valid partner and slot+10a nonzero; helper false and saved lookup bit2 clear"),
        0x714945: ("5*s8(AL from 006c4130)", "fallback helper AL>=0"),
        0x714953: ("3", "immediately after 00714945"),
        0x714b30: ("EAX from 00945640 on x87(float32(slot+e1)+10.0f)", "fallback coordinates differ"),
    }
    assert [a for a, b in calls(rows) if b == 0x90cfc0] == list(rng)
    # Start at known instruction boundaries, not arbitrary bytes before a call.
    contexts = [(0x7109cd, 0x7109d6), (0x6ba4df, 0x6ba4ef), (0x5b5270, 0x5b5286)]
    context_results = []
    for start, end in contexts:
        decoded = decode(start, end)
        context_results.append(dict(start=hx(start), end_exclusive=hx(end),
             code_sha256=digest(read(start, end-start)), direct_calls=[dict(site=hx(a), target=hx(b))
             for a, b in calls(decoded)]))
    leaf = {i.address: i for i in decode(0x5b5270, 0x5b5286)}
    for site, pair in {
        0x5b5270: ("movsx", "edx, byte ptr [esp + 4]"),
        0x5b5275: ("mov", "eax, dword ptr [ecx + edx*8 + 0x188b]"),
        0x5b527c: ("mov", "edx, dword ptr [ecx + edx*8 + 0x188f]"),
        0x5b5283: ("ret", "4"),
    }.items():
        assert (leaf[site].mnemonic, leaf[site].op_str) == pair
    # Call cleanup is inferred from local stack balance, not from decompiler
    # prototypes. Propagate it through every CFG edge, requiring consistent joins
    # and the original entry ESP before each RET4. This is a static ABI check.
    cleanup = {0x5b57c0: 4, 0x6c2a40: 12, 0x6f46b0: 8, 0x90cfc0: 0,
        0x6cfda0: 4, 0x6f09f0: 20, 0x6c38c0: 4, 0x6bce80: 16,
        0x5b5270: 4, 0x6c2be0: 16, 0x715f50: 4, 0x6cb700: 12,
        0x6c4180: 8, 0x6cb930: 8, 0x944cff: 0, 0x90d130: 0,
        0x944c9f: 0, 0x5e8290: 0, 0x6c4130: 4, 0x6f5b80: 4,
        0x6cd5f0: 4, 0x945640: 0}
    stack_at, pending, explicit_stack_offsets = {}, [(START, 0)], []
    while pending:
        site, delta = pending.pop()
        if site in stack_at:
            assert stack_at[site] == delta, (hx(site), delta, stack_at[site])
            continue
        stack_at[site] = delta
        i = at[site]
        for op in i.operands:
            if op.type == CS_OP_MEM and i.reg_name(op.mem.base) == "esp":
                assert op.mem.index == 0
                explicit_stack_offsets.append((site, delta+op.mem.disp, op.size))
        if i.mnemonic == "ret":
            assert delta == 0
            continue
        if i.mnemonic == "push":
            delta -= 4
        elif i.mnemonic == "pop":
            delta += 4
        elif i.mnemonic in ("add", "sub") and i.op_str.startswith("esp,"):
            delta += i.operands[1].imm * (1 if i.mnemonic == "add" else -1)
        elif i.mnemonic == "call":
            delta += cleanup[i.operands[0].imm]
        successors = [site+i.size]
        if i.mnemonic.startswith("j"):
            successors = [i.operands[0].imm] + ([] if i.mnemonic == "jmp" else successors)
        pending.extend((s, delta) for s in successors)
    assert len(stack_at) == len(rows)
    assert all(d+w <= 0 for _, d, w in explicit_stack_offsets)
    stack_check = dict(entry_stack_argument_read=False, all_explicit_esp_accesses_below_entry_esp=True,
        all_cfg_joins_balanced=True, all_returns_restore_entry_esp=True,
        callee_cleanup_inference="local stack-balance contract; normal callee return assumed",
        callee_cleanup_bytes={hx(a): n for a, n in cleanup.items()})
    constants = []
    for va, fmt in [(0x968950, "d"), (0x96a600, "d"), (0x968e18, "d"), (0x968a78, "f")]:
        size = struct.calcsize(fmt)
        constants.append(dict(address=hx(va), width_bytes=size,
             value=struct.unpack("<"+fmt, read(va, size))[0], sha256=digest(read(va, size))))
    native.update(checkpoint="2026-10-18-investigation-13", old_name="FUN_00713fc0",
        instruction_addresses_and_direct_calls_agree=True, incoming_targets_verified=True)
    return dict(work_unit="R14-A", baseline_commit="3d81fa3c056c7d28c3c2a6d99e93d96464f43834",
        specimen_sha256=SHA, export_manifest_sha256=MANIFEST_SHA, annotation_preflight_sha256=PREFLIGHT_SHA,
        evidence_class="static original-instruction mapping; no execution oracle",
        address_kind="virtual addresses; raw file offsets explicitly labelled", decoder="Capstone 5.0.7 x86-32",
        function=dict(entry=hx(START), end_exclusive=hx(END), bytes=END-START,
            raw_file_offset=f"0x{offset(START, END-START):x}", code_sha256=digest(read(START, END-START)),
            instruction_count=len(rows), direct_call_count=len(calls(rows)), branch_count=len(branches),
            native_corroboration=native, incoming_direct_call_sites=[hx(a) for a in refs],
            direct_calls=[dict(site=hx(a), target=hx(b)) for a, b in calls(rows)], returns=returns,
            direct_state_stores=[dict(site=hx(a), width_bytes=w, destination=d, value=v)
                for a, (w, d, v) in expected_stores.items()],
            all_explicit_memory_store_sites=[hx(i.address) for i in stores], branches=branches,
            rng_sites=[dict(site=hx(a), bound=b, local_gate=g) for a, (b, g) in rng.items()],
            local_cfg_acyclic=True, cfg_upper_bound_direct_rng_calls=upper,
            rng_bound_limit="CFG upper bound ignores correlated predicates and transitive calls; R(0) need not advance state",
            stack_balance_check=stack_check, checked_contract_sites=[hx(a) for a in expected]),
        dependency_caller_windows=context_results, constants=constants,
        limits=["No execution oracle, live reachability or connected shot outcome",
                "Incoming references are supplied direct calls, not a completeness proof",
                "Callee effects/RNG remain unresolved except prior bounded contracts",
                "Stack slot consumed by RET4 is not read in local body; do not copy inferred fastcall prototype",
                "No original bytes, bulk assembly, decompilation or private paths emitted"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("evidence/match-dispatch-14-sites.json"))
    arguments = parser.parse_args()
    result = run(arguments)
    arguments.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(f"wrote {arguments.output}; static decoder check only")

#!/usr/bin/env python3
"""Verify R15-A static contract from the private PE/native export; emit no code bytes.

Requires Capstone 5.0.7. This is a decoder/static CFG check, not an execution oracle.
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
MANIFEST_SHA = "65503dc3cf33eff2a9a40c1cdc456f5798bc8e04d1d9bbad6132c06b9677ca58"
PREFLIGHT_SHA = "c20393d151da0afff24f0ff7f806f91857d90f454cbff5a52d7bc0463517d1f1"
START, END = 0x714d40, 0x715f27


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hx(value):
    return f"{value:08x}"


def normalize(text):
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    text = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0], 16)), text)
    text = text.replace("*1", "").replace("st0", "st(0)")
    text = re.sub(r"\s+", "", text)
    if text == "fcomp":
        text = "fcompst(1)"  # Ghidra omits the encoded register operand.
    for old, new in (("jnz", "jne"), ("jz", "je"), ("setz", "sete"), ("setnz", "setne")):
        if text.startswith(old):
            text = new + text[len(old):]
    return text


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
    old = [s for s in json.loads(raw_preflight)["sites"] if s["address"] == hx(START)]
    assert len(old) == 1 and old[0]["instruction_exists"] and old[0]["function_name"] == "FUN_00714d40"
    exported = {f["name"]: f for f in manifest["files"]}
    texts, native = {}, {}
    for suffix in ("asm", "c", "refs"):
        name = f"{hx(START)}.{suffix}"
        raw = (args.exports / name).read_bytes()
        assert len(raw) == exported[name]["bytes"] and digest(raw) == exported[name]["sha256"]
        texts[suffix] = raw.decode("utf-8-sig")
        native[f"{suffix}_sha256"] = digest(raw)
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
        return [(i.address, i.operands[0].imm) for i in rows if i.mnemonic == "call" and i.operands[0].type == CS_OP_IMM]

    rows = decode(START, END)
    at = {i.address: i for i in rows}
    exported_rows = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", texts["asm"], re.M)]
    assert [a for a, _ in exported_rows] == list(at)
    differences = [(hx(a), text, at[a].mnemonic+" "+at[a].op_str) for a, text in exported_rows
                   if normalize(text) != normalize(at[a].mnemonic+" "+at[a].op_str)]
    assert not differences, differences
    refs = [int(m[1], 16) for m in re.finditer(r"^([0-9a-fA-F]{8}) UNCONDITIONAL_CALL\s*$", texts["refs"], re.M)]
    for site in refs:
        assert calls(decode(site, site+5)) == [(site, START)]
    # Capstone omits access flags on some x87 stores; include their explicit destination.
    stores = [i for i in rows if any(op.type == CS_OP_MEM and op.access & capstone.CS_AC_WRITE for op in i.operands)
              or (i.mnemonic in ("fst", "fstp", "fist", "fistp", "fnstsw", "fnstcw")
                  and i.operands and i.operands[0].type == CS_OP_MEM)]
    state_stores = [i for i in stores if any(op.type == CS_OP_MEM and op.access & capstone.CS_AC_WRITE
        and i.reg_name(op.mem.base) != "esp" for op in i.operands)]
    branches = [dict(site=hx(i.address), kind=i.mnemonic, target=hx(i.operands[0].imm)) for i in rows if i.mnemonic.startswith("j")]
    for branch in branches:
        assert int(branch["target"], 16) in at
    returns = [dict(site=hx(i.address), cleanup_bytes=0 if not i.operands else i.operands[0].imm) for i in rows if i.mnemonic == "ret"]
    assert len(returns) == 20 and all(r["cleanup_bytes"] == 0 for r in returns)
    expected_stores = {
        0x714e14: (2,"0xffff"), 0x714e71:(2,"0x68"), 0x714f69:(2,"0x7a"),
        0x714ffe:(2,"0x7a"), 0x7150f9:(2,"0x7a"), 0x715185:(2,"0x7a"),
        0x715268:(2,"0x100"), 0x7153c0:(2,"bp"), 0x7154ab:(2,"0x105"),
        0x7154c1:(2,"0x105"), 0x715583:(4,"0"), 0x7158e5:(2,"0x6b"),
        0x715984:(4,"0"), 0x7159c3:(2,"0x78"), 0x715a6a:(2,"4"),
        0x715a6f:(2,"0x103"), 0x715b2c:(2,"0x103"), 0x715bb6:(2,"0x103"),
        0x715bde:(2,"0x71"), 0x715bf8:(2,"0x71"), 0x715d1c:(2,"4"),
        0x715d27:(2,"0x100"), 0x715ddd:(2,"0x100"), 0x715e00:(2,"bx"),
        0x715e60:(2,"ax"), 0x715edd:(2,"0x104"), 0x715efe:(2,"ax")}
    assert [i.address for i in state_stores] == list(expected_stores)
    for i in state_stores:
        assert (i.operands[0].size, i.op_str.split(",",1)[1].strip()) == expected_stores[i.address]
    rng = {
        0x714d7b:("20", "entry sentinel ff and match+f57a==slot; snapshot slot+107 before call"),
        0x714eb3:("25", "side==0; snapshot signed bytes +105,+106,+10a before call"),
        0x714fa4:("100", "side0 product gate and region pass, first mask/delta dispatch fails"),
        0x715043:("25", "side!=0; snapshot signed bytes +105,+106,+10a before call"),
        0x715134:("100", "nonzero-side product gate and region pass, first mask/delta dispatch fails"),
        0x715378:("EAX from 00945640(float32(slot+dd))", "tactical and opposing/sentinel gate; snapshot signed slot+10d first"),
        0x715394:("EAX from 00945640(x87(float32 grid distance * float32 8.0))", "after 00715378; distance stored float32 before first call"),
        0x715502:("21", "eligible valid partner; 006cb930 AL zero and saved entry lookup bit2 clear"),
        0x7155bd:("EAX from 00945640(x87(float32(slot+e1)+float64 0.5))", "no accepted partner; match sentinel !=ff and saved tactical bit0 clear"),
        0x7155ec:("10", "007155bd result nonzero; signed slot+10d snapshotted before draw"),
        0x71564a:("150", "007155bd result nonzero; compare result+30 with snapshot float32(slot+1a2)"),
        0x7157c2:("s8(match+8d46+(side==0))", "grid threshold and flags permit; tactical bits1 and2 both clear"),
        0x7157cb:("25", "immediately after 007157c2")}
    assert [a for a,b in calls(rows) if b == 0x90cfc0] == list(rng)
    # Treat the diagnostic exit call as terminal. The byte range after it is still
    # decoded/compared; a returning exit would fall through with an extra argument.
    terminal = {0x71599a}
    def successors(i):
        if i.mnemonic == "ret" or i.address in terminal:
            return []
        ordinary = [i.address+i.size]
        if i.mnemonic.startswith("j"):
            return [i.operands[0].imm] + ([] if i.mnemonic == "jmp" else ordinary)
        return ordinary
    visiting, maximum = set(), {}
    def max_rng(site):
        if site in maximum:
            return maximum[site]
        assert site not in visiting, "local control flow cycle"
        visiting.add(site)
        i = at[site]
        own = int(i.mnemonic == "call" and i.operands[0].imm == 0x90cfc0)
        maximum[site] = own+max((max_rng(s) for s in successors(i)), default=0)
        visiting.remove(site)
        return maximum[site]
    upper = max_rng(START)
    cleanup = {0x90cfc0:0, 0x6cfda0:4, 0x5b57c0:4, 0x6c38c0:4, 0x6c2a40:12,
        0x6f46b0:8, 0x6f09f0:20, 0x6c4180:8, 0x945640:0, 0x6cb930:8,
        0x5b5270:4, 0x6cd5f0:4, 0x6c2be0:16, 0x715f50:4, 0x6c4130:4,
        0x6f5b80:4, 0x6cb960:12, 0x6ce110:4, 0x944cff:0, 0x90d130:0,
        0x944c9f:0, 0x5e8290:0, 0x5cc7d0:0, 0x5a8f60:0, 0x945934:0,
        0x6f4920:16, 0x6d6f70:28, 0x6f0630:0, 0x6c3950:16, 0x6cc4e0:16}
    for r in returns:
        pos = list(at).index(int(r["site"],16))
        assert [(i.mnemonic,i.op_str) for i in rows[pos-6:pos]] == [
            ("pop","edi"),("pop","esi"),("pop","ebp"),("pop","ebx"),("mov","esp, ebp"),("pop","ebp")]
    stack_cases = []
    for entry_mod8 in (0,4):
        stack_at, pending, accesses = {}, [(START,0)], []
        while pending:
            site, delta = pending.pop()
            if site in stack_at:
                assert stack_at[site] == delta, (hx(site),delta,stack_at[site])
                continue
            stack_at[site] = delta
            i = at[site]
            for op in i.operands:
                if op.type == CS_OP_MEM and i.reg_name(op.mem.base) == "esp":
                    assert not op.mem.index
                    accesses.append(delta+op.mem.disp+op.size)
            if i.mnemonic == "ret":
                assert delta == 0
                continue
            if i.mnemonic == "push":
                delta -= 4
            elif i.mnemonic == "pop":
                delta += 4
            elif i.mnemonic in ("add","sub") and i.op_str.startswith("esp,"):
                delta += i.operands[1].imm * (1 if i.mnemonic == "add" else -1)
            elif i.mnemonic == "and" and i.op_str.startswith("esp,"):
                assert site == 0x714d43
                delta -= (entry_mod8+delta)%8
            elif i.mnemonic == "mov" and i.op_str == "esp, ebp":
                assert delta == -4-((entry_mod8-4)%8)-0x238
                delta = -4  # saved frame EBP restored by the verified epilogue
            elif i.mnemonic == "call":
                delta += cleanup[i.operands[0].imm]
            pending.extend((s,delta) for s in successors(i))
        assert len(stack_at) == len(rows) and max(accesses) <= 0
        stack_cases.append(dict(entry_esp_mod8=entry_mod8, all_cfg_joins_balanced=True,
            all_returns_restore_entry_esp=True, all_explicit_stack_accesses_below_entry_esp=True))
    constants = []
    for va, fmt in [(0x96d784, "f"), (0x968968, "d"), (0x9689a0, "d"), (0x968ee0, "d"),
                    (0x968940, "d"), (0x968e18, "d"), (0x9689a8, "f")]:
        size = struct.calcsize(fmt)
        constants.append(dict(address=hx(va), width_bytes=size, value=struct.unpack("<"+fmt, read(va, size))[0], sha256=digest(read(va, size))))
    return dict(work_unit="R15-A", baseline_commit="a4fa4bc7745ad3fbc67759325c45a9058ceaecc0", specimen_sha256=SHA,
        export_manifest_sha256=MANIFEST_SHA, annotation_preflight_sha256=PREFLIGHT_SHA,
        evidence_class="static original-instruction mapping; no execution oracle", decoder="Capstone 5.0.7 x86-32",
        address_kind="virtual addresses; raw file offsets explicitly labelled",
        function=dict(entry=hx(START), end_exclusive=hx(END), bytes=END-START,
            raw_file_offset=f"0x{offset(START, END-START):x}", code_sha256=digest(read(START, END-START)),
            instruction_count=len(rows), direct_call_count=len(calls(rows)), branch_count=len(branches),
            native_corroboration=dict(**native, checkpoint=manifest["checkpoint"],
                all_instruction_addresses_mnemonics_operands_agree=True, incoming_targets_verified=True),
            incoming_direct_call_sites=[hx(a) for a in refs], direct_calls=[dict(site=hx(a), target=hx(b)) for a, b in calls(rows)],
            returns=returns, branches=branches,
            direct_state_stores=[dict(site=hx(i.address), width_bytes=i.operands[0].size, operation=i.mnemonic,
                destination=i.op_str.split(",")[0], source=i.op_str.split(",",1)[1].strip()) for i in state_stores],
            all_explicit_memory_store_sites=[hx(i.address) for i in stores],
            rng_sites=[dict(site=hx(a), bound=b, gate=g) for a,(b,g) in rng.items()],
            local_cfg_acyclic=True, cfg_upper_bound_direct_rng_calls=upper,
            stack_checks=stack_cases, inferred_callee_cleanup_bytes={hx(a):n for a,n in cleanup.items()},
            diagnostic_terminal_call="0071599a -> 00945934; normal nonreturn assumed for stack/CFG checks"),
        constants=constants, limits=["No execution oracle or connected shot outcome",
            "Callee effects and transitive RNG unresolved except prior bounded contracts",
            "CFG RNG upper bound ignores correlated predicates; R(0) need not advance exposed state",
            "Normal callee ABI and diagnostic exit nonreturn assumed",
            "Supplied incoming references are checked, not proved exhaustive"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("evidence/match-dependency-15-sites.json"))
    arguments = parser.parse_args()
    arguments.output.write_text(json.dumps(run(arguments), indent=2)+"\n", encoding="utf-8")
    print(f"wrote {arguments.output}; static decoder check only")

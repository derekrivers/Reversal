"""Verify the complete R16-A body and retain compact static evidence, never code bytes."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

SHA = "0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86"
MANIFEST_SHA = "fc92c27bcc9f2f15bedebb4aadbebba7bf0ed5f8801c787e2f0e262c48a7e960"
PREFLIGHT_SHA = "2be810e149b9d5ebe8de028bf9542aab932afd31514e2ec8d737bef8450374bc"
START, END = 0x7109f0, 0x713d5a

# p=entry ECX; m=dword(p+19e); d=entry distance float32; t=the
# float32 result saved at body ESP+60. F means original 00945640, not a host cast.
RNG_BOUNDS = {
    0x710b38: "3; state3 candidate fallback",
    0x710c14: "4; state2 fallback with match x byte zero",
    0x710c22: "4; state2 fallback with match x byte nonzero; alternative to 00710c14",
    0x710cb4: "7; state4 fallback; followed by exactly one side-selected R(3)",
    0x710ccd: "3; state4 side0; alternative to 00710cdd",
    0x710cdd: "3; state4 nonzero side; alternative to 00710ccd",
    0x710d38: "100; state5 after quality preparation; zero selects resolver mode5, otherwise mode1",
    0x710e5e: "F(float32(p+a1)+float32(20)); state6 regional/distance gate",
    0x710eb6: "100; state6 passed distance gate after quality preparation; zero selects mode6, otherwise mode1",
    0x7111a9: "trunc_signed32((v+500)/3), v=F(-0.75*(s8(candidate_count)*s16(candidate_scalar)^2)); v<-500",
    0x71137e: "5; opposite-side team flags mask400h; compare saved s8(p+106)>draw",
    0x711527: "3; distance branch; snapshot s8(p+109) first",
    0x711574: "50; mode low byte4 and preceding distance gate; compare saved s8(p+109)>draw",
    0x7115c2: "F(d*float32(75)-4*snapshot_s8(p+106)); after quality preparation",
    0x7115f5: "wrapping32(-(draw_at_007115c2+F(4*snapshot_s8(p+106)-d*float32(75))))",
    0x711714: "wrapping32(2*(3*(s8(output_at_body_esp4b)-s8(output_at_body_esp4a))+s8(dword(p+69)+5b)))",
    0x7117bf: "4; local byte at body ESP+68 equals2 and match-state/distance gate",
    0x711896: "F(float32(p+99)*float32(10)); grid distance equality/occupancy gate",
    0x7118af: "F(float32(p+95)*float32(10)); immediately after 00711896",
    0x711921: "20; local byte at body ESP+68 zero, score30<3000, mode low byte!=4",
    0x7119b5: "s8(dword(p+69)+5c); after state/region/+106 gates",
    0x7119be: "10; immediately after 007119b5",
    0x711b87: "F(d*float32(20)); selected keeper tactical/byte+2b gate",
    0x711bf5: "F(d); keeper outside selected rectangle",
    0x711c66: "F(d*d*float32(3)); keeper regional, noncentral route",
    0x711d08: "F(d*float32(10)); central keeper and 00713d90 AL zero",
    0x711eea: "F(float32(3000)-t*float32(1000)); regional/predicate t threshold",
    0x711efc: "wrapping32(score30+2000); immediately after 00711eea",
    0x71260c: "F((s8(body_esp27)+1)*(d+float32(1))*d*d*d*float32(200)); tactical bit40 set",
    0x71265b: "same x87 expression as 0071260c; tactical bit40 clear; alternative site",
    0x7126fa: "F(float32(p+e1)); destination/score adjustment join",
    0x71271c: "4; 007126fa zero and tactical bit40 clear",
    0x712895: "F(float32(p+b1)); d in ordered [2,4.5), x in2..6 and p+109 nonzero",
    0x712a26: "wrapping32(2*s8(p+106)+20); getter EAX bit25, regional/scalar gates",
    0x712c71: "F(float32(p+b1)); alternate flag route EAX bit29 and ordered d in[2,4.5)",
    0x712d16: "wrapping32(300*s8(p+2d)); 00713e90 AL neither2 nor p+2c, local byte68 zero",
    0x712dfb: "F(d*float32(10000)); d ordered>=1; compare snapshot s8(p+109)^4>draw",
    0x712eec: "F(x87_result_from_00945ff0+3*s16(p+29)+10000-score30); preceding region/distance gates",
    0x712f3b: "500; match state<4, local byte27<2 and ordered d in[5,7)",
    0x712f57: "F(d*float32(10)); earlier distance/state gates; low AL narrowed signed then clamped to>=10",
    0x712f71: "trunc_signed32(400000/max(10,s8(low8(draw_at_00712f57)))); immediately after 00712f57",
    0x712fee: "F(s8(p+106)*float64(30)); candidate-scan pre-gate",
    0x712ffa: "200; immediately after 00712fee; signed first>second permits loop",
    0x713088: "F(100*s8(p+17)+float32(p+95)*float32(125)); per candidate whose byte+24 is nonzero",
    0x71322c: "score10; local dword4c zero, score10>2000, s16(p+29)>-50",
    0x713241: "current EBX baseline/penalty value; p+106 zero; may include 0071322c result",
    0x71334a: "wrapping32(50*(20-s8(p+106))); first of four score perturbations",
    0x713370: "same expression freshly read; second perturbation",
    0x713396: "same expression freshly read; third perturbation",
    0x7133b8: "same expression freshly read; fourth perturbation",
    0x7134a5: "10; candidate/region preselection fallback; zero rejoins four perturbations",
    0x713528: "10 if action word10h, otherwise2; preceding scalar/region gates; maps zero->choice2, nonzero->choice4",
    0x7135b1: "15; choice3, 006f9f90 AL zero and match byte8ea9==3",
    0x71367b: "120; choice3, outside x2..6 and other regional gates",
    0x7136f0: "s16(low16(F(float32(p+95)))); choice3 fallback, action!=2",
    0x7136fe: "50; immediately after 007136f0; saved s8(p+109) added to first result",
    0x7137ff: "2; choice4 coordinate override, side0 and target x==4",
    0x713839: "2; choice4 coordinate override, nonzero side and target x==4; alternative to 007137ff",
    0x713995: "10; choice4 no usable candidate, mode!=4 and p+109==0"
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hx(n):
    return f"{n:08x}"


def format_evidence(value, level=0):
    """Keep short address/edge records on one line for reviewable compact evidence."""
    def depth(item):
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else []
        return 1+max((depth(c) for c in children), default=0) if isinstance(item,(dict,list)) else 0
    encoded = json.dumps(value)
    if depth(value) <= 2 and len(encoded) <= 240:
        return encoded
    pad, child_pad = "  "*level, "  "*(level+1)
    if isinstance(value, dict):
        return "{\n"+",\n".join(child_pad+json.dumps(k)+": "+format_evidence(v,level+1)
                                  for k,v in value.items())+"\n"+pad+"}"
    if isinstance(value, list):
        return "[\n"+",\n".join(child_pad+format_evidence(v,level+1) for v in value)+"\n"+pad+"]"
    return encoded


def normalize(text):
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    text = text.replace("dword ptr fs:", "fs:")
    text = re.sub(r"0x[0-9a-f]+", lambda m: str(int(m[0], 16)), text)
    text = text.replace("*1", "").replace("st0", "st(0)")
    text = re.sub(r"\s+", "", text)
    text = text.replace("+-", "-").replace("+0]", "]")
    if text in ("fcomp", "faddp", "fsubp", "fmulp", "fdivp", "fxch"):
        text += "st(1)"  # Ghidra omits encoded default register operands.
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
    manifest_raw = (args.exports / "manifest.json").read_bytes()
    if digest(manifest_raw) != MANIFEST_SHA:
        raise ValueError("export manifest SHA-256 mismatch")
    manifest = json.loads(manifest_raw)
    assert manifest["specimen_sha256"] == SHA
    preflight_raw = args.preflight.read_bytes()
    if digest(preflight_raw) != PREFLIGHT_SHA:
        raise ValueError("annotation preflight SHA-256 mismatch")
    preflight = json.loads(preflight_raw)
    assert preflight["sha256"] == SHA
    old = [s for s in preflight["sites"] if s["address"] == hx(START)]
    assert len(old) == 1 and old[0]["instruction_exists"] and old[0]["function_name"] == "FUN_007109f0"
    native = {}
    for name, metadata in manifest["files"].items():
        raw = (args.exports / name).read_bytes()
        assert len(raw) == metadata["bytes"] and digest(raw) == metadata["sha256"]
        if name.startswith(hx(START)):
            native[name.rsplit(".", 1)[1]+"_sha256"] = digest(raw)
    assembly = (args.exports / f"{hx(START)}.asm").read_text(encoding="utf-8-sig")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[:2] == b"MZ" and data[pe:pe+4] == b"PE\0\0"
    assert struct.unpack_from("<H", data, pe+4)[0] == 0x14c
    count = struct.unpack_from("<H", data, pe+6)[0]
    optsize = struct.unpack_from("<H", data, pe+20)[0]
    optional = pe+24
    assert struct.unpack_from("<H", data, optional)[0] == 0x10b
    base = struct.unpack_from("<I", data, optional+28)[0]
    sections = [struct.unpack_from("<IIII", data, optional+optsize+40*n+8)[1:] for n in range(count)]

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
    rows = list(md.disasm(read(START, END-START), START))
    cursor = START
    for row in rows:
        assert row.address == cursor
        cursor += row.size
    assert cursor == END
    at = {i.address: i for i in rows}
    positions = {i.address: n for n, i in enumerate(rows)}
    exported = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", assembly, re.M)]
    assert [a for a, _ in exported] == list(at)
    differences = [(hx(a), text, at[a].mnemonic+" "+at[a].op_str) for a, text in exported
                   if normalize(text) != normalize(at[a].mnemonic+" "+at[a].op_str)]
    assert not differences, differences
    assert len(rows) == 3824
    caller = list(md.disasm(read(0x710650,0x16),0x710650))
    assert [(i.address,i.mnemonic,i.op_str) for i in caller] == [
        (0x710650,"push","0"),(0x710652,"mov","ecx, esi"),(0x710654,"call","0x7109f0"),
        (0x710659,"mov","eax, dword ptr [esi + 0x19e]"),(0x71065f,"mov","byte ptr [eax + 0x1a7], 0")]
    selected = {0x710a05:("sub","esp, 0x29c"),0x710a0e:("mov","esi, ecx"),
        0x710aa7:("add","ecx, -2"),0x710aaa:("cmp","ecx, 6"),
        0x71301b:("xor","bl, bl"),0x713095:("inc","bl"),
        0x71309f:("cmp","bl, byte ptr [edi + eax + 0x58]"),
        0x7130a3:("jl","0x71304a"),0x71376c:("dec","eax"),0x71376d:("cmp","eax, 3"),
        0x713bdc:("mov","al, 1"),0x713bf6:("ret","4"),0x713cd9:("xor","al, al")}
    for site, expected in selected.items():
        assert (at[site].mnemonic,at[site].op_str) == expected, hx(site)
    calls = [i for i in rows if i.mnemonic == "call"]
    assert len(calls) == 211 and all(i.operands[0].type == CS_OP_IMM for i in calls)
    switches = {}
    for site, table, n, first in ((0x710aaf, 0x713d5c, 7, 2), (0x713776, 0x713d78, 4, 1)):
        i = at[site]
        assert i.mnemonic == "jmp" and i.operands[0].type == CS_OP_MEM
        assert i.operands[0].mem.disp == table and i.operands[0].mem.scale == 4
        targets = struct.unpack("<"+"I"*n, read(table, 4*n))
        assert all(t in at for t in targets)
        switches[site] = dict(table_address=hx(table), raw_file_offset=f"0x{offset(table,4*n):x}",
            table_sha256=digest(read(table,4*n)), cases=[dict(value=first+j, target=hx(t)) for j,t in enumerate(targets)])
    terminal = {0x713d55}

    def successors(i):
        if i.mnemonic == "ret" or i.address in terminal:
            return []
        ordinary = [i.address+i.size]
        if i.mnemonic.startswith("j"):
            targets = ([i.operands[0].imm] if i.operands[0].type == CS_OP_IMM else
                       [int(c["target"],16) for c in switches[i.address]["cases"]])
            return list(dict.fromkeys(targets+([] if i.mnemonic == "jmp" else ordinary)))
        return ordinary

    branches = []
    leaders = {START}
    for i in rows:
        if i.mnemonic.startswith("j"):
            targets = successors(i)
            assert all(t in at for t in targets)
            leaders.update(targets)
            leaders.add(i.address+i.size)
            branches.append(dict(site=hx(i.address), kind=i.mnemonic, successors=[hx(s) for s in targets]))
        elif i.mnemonic == "ret" or i.address in terminal:
            if i.address+i.size < END:
                leaders.add(i.address+i.size)
    leaders = sorted(leaders)
    blocks, owner = {}, {}
    for n, start in enumerate(leaders):
        end = leaders[n+1] if n+1 < len(leaders) else END
        items = [i for i in rows if start <= i.address < end]
        assert items
        blocks[start] = items
        owner.update((i.address, start) for i in items)
    edges = {b: successors(items[-1]) for b,items in blocks.items()}
    reached, pending = set(), [START]
    while pending:
        b = pending.pop()
        if b not in reached:
            reached.add(b)
            pending.extend(edges[b])
    assert reached == set(blocks), [hx(b) for b in set(blocks)-reached]
    # SCCs expose actual local cycles, including backward layout jumps that are acyclic.
    index, low, stack, active, sccs = {}, {}, [], set(), []

    def visit(b):
        index[b] = low[b] = len(index)
        stack.append(b)
        active.add(b)
        for s in edges[b]:
            if s not in index:
                visit(s)
                low[b] = min(low[b], low[s])
            elif s in active:
                low[b] = min(low[b], index[s])
        if low[b] == index[b]:
            component = []
            while True:
                s = stack.pop()
                active.remove(s)
                component.append(s)
                if s == b:
                    break
            sccs.append(sorted(component))

    visit(START)
    cycles = [c for c in sccs if len(c)>1 or c[0] in edges[c[0]]]
    assert cycles == [[0x71304a, 0x71305f, 0x713092]]
    rng = [i for i in calls if i.operands[0].imm == 0x90cfc0]
    stores = [i for i in rows if any(op.type == CS_OP_MEM and op.access & capstone.CS_AC_WRITE for op in i.operands)
              or (i.mnemonic in ("fst", "fstp", "fist", "fistp", "fnstsw", "fnstcw")
                  and i.operands and i.operands[0].type == CS_OP_MEM)]
    state_stores = [i for i in stores if any(op.type == CS_OP_MEM and i.reg_name(op.mem.base) != "esp"
                  and (op.access & capstone.CS_AC_WRITE or i.mnemonic.startswith(("fst", "fist", "fnst"))) for op in i.operands)]
    expected_stores = [0x7109fe,0x710ab6,0x710ae5,0x710b73,0x710b86,0x710c46,0x710c59,
        0x710d03,0x710d16,0x710d64,0x710e01,0x710e14,0x710e9d,0x710f78,0x711150,
        0x7111e9,0x7111f3,0x711339,0x711342,0x711721,0x713785,0x7137d1,0x713961,
        0x7139d2,0x713acd,0x713b2d,0x713b53,0x713b5d,0x713b87,0x713bb5,0x713be9,
        0x713c48,0x713d3f]
    assert [i.address for i in state_stores] == expected_stores
    assert len(branches) == 732 and len(blocks) == 836
    assert [i.address for i in rng] == list(RNG_BOUNDS)
    returns = [dict(site=hx(i.address), cleanup_bytes=i.operands[0].imm if i.operands else 0)
               for i in rows if i.mnemonic == "ret"]
    assert returns == [dict(site="00713bf6", cleanup_bytes=4)]
    cleanup = {0x5a8f60:0,0x5b5270:4,0x5cc7d0:0,0x5e8290:0,0x68d020:0,0x68d040:0,
        0x6bba80:0,0x6bcbd0:12,0x6bce80:16,0x6bd5b0:8,0x6c2be0:16,0x6c38c0:4,
        0x6c38f0:4,0x6c3950:16,0x6c3a00:16,0x6c4180:8,0x6c6a30:32,0x6cb700:12,
        0x6cb780:4,0x6cb910:4,0x6cb930:8,0x6cb9b0:12,0x6cc070:16,0x6ce110:4,
        0x6ce310:28,0x6d42a0:4,0x6d6f70:28,0x6f09b0:8,0x6f09f0:20,0x6f4920:16,
        0x6f9f90:24,0x6fa250:20,0x6fa490:8,0x700bd0:8,0x702050:24,0x70ec80:4,
        0x713d90:8,0x713e90:28,0x715f50:4,0x90cfc0:0,0x90d130:0,0x944c9f:0,
        0x944cff:0,0x945640:0,0x945934:0,0x945ff0:0}
    stack_at, pending, arg_accesses, call_depths = {}, [(START,0)], set(), []
    while pending:
        site, delta = pending.pop()
        if site in stack_at:
            assert stack_at[site] == delta, (hx(site), delta, stack_at[site])
            continue
        stack_at[site] = delta
        i = at[site]
        for op in i.operands:
            if op.type == CS_OP_MEM and i.reg_name(op.mem.base) == "esp":
                assert not op.mem.index
                if delta+op.mem.disp >= 0:
                    arg_accesses.add((delta+op.mem.disp,op.size))
        if i.mnemonic == "ret":
            assert delta == 0
        elif i.mnemonic == "push":
            delta -= 4
        elif i.mnemonic == "pop":
            delta += 4
        elif i.mnemonic in ("add","sub") and i.op_str.startswith("esp,"):
            delta += i.operands[1].imm*(1 if i.mnemonic == "add" else -1)
        elif i.mnemonic == "call":
            call_depths.append(dict(site=hx(site), target=hx(i.operands[0].imm),
                pushed_bytes_below_body_frame=-0x2b8-delta, inferred_callee_cleanup_bytes=cleanup[i.operands[0].imm]))
            delta += cleanup[i.operands[0].imm]
        pending.extend((s,delta) for s in successors(i))
    assert len(stack_at) == len(rows)
    assert arg_accesses == {(4,1),(4,4)}, arg_accesses
    # Collapse the sole SCC with at most 127 iterations: BL starts zero, increments
    # once, and compares signed against a byte. This bound assumes admitted calls
    # preserve EBX and do not corrupt the local induction or return normally otherwise.
    component_of = {b:n for n,c in enumerate(sccs) for b in c}
    component_edges = {n:sorted({component_of[s] for b in c for s in edges[b] if component_of[s]!=n})
                       for n,c in enumerate(sccs)}
    weights = {n:(127 if c in cycles else sum(i in rng for b in c for i in blocks[b])) for n,c in enumerate(sccs)}
    longest = {}
    def maximum(n):
        if n not in longest:
            longest[n] = weights[n]+max((maximum(s) for s in component_edges[n]),default=0)
        return longest[n]
    rng_upper = maximum(component_of[START])
    # Only selected state stores and argument-source operands are retained, never the listing.
    predecessors = defaultdict(list)
    for i in rows:
        for s in successors(i):
            predecessors[s].append(i.address)

    def argument_push(site):
        todo, seen, found = list(predecessors[site]), set(), set()
        while todo:
            b = todo.pop()
            if b in seen:
                continue
            seen.add(b)
            j = at[b]
            if j.mnemonic == "push":
                found.add(b)
                continue
            assert j.mnemonic not in ("pop", "call", "ret") and not (
                j.op_str.startswith("esp,") and j.mnemonic in ("add","sub","mov")), hx(site)
            todo.extend(predecessors[b])
        assert len(found) == 1, (hx(site), [hx(s) for s in found])
        return at[found.pop()]

    rng_sites = []
    for i in rng:
        previous = argument_push(i.address)
        rng_sites.append(dict(site=hx(i.address), argument_push=hx(previous.address),
            bound_operand=previous.op_str, cfg_block=hx(owner[i.address]), bound_and_gate=RNG_BOUNDS[i.address]))
    targets = defaultdict(list)
    for i in calls:
        targets[hx(i.operands[0].imm)].append(hx(i.address))
    # Float constant references are read through PE mapping, without retaining table contents.
    constant_specs = set()
    for i in rows:
        if not i.mnemonic.startswith("f"):
            continue
        for op in i.operands:
            if op.type == CS_OP_MEM and not op.mem.base and not op.mem.index and 0x960000 <= op.mem.disp < 0x980000:
                constant_specs.add((op.mem.disp, op.size))
    constants = [dict(address=hx(va), width_bytes=size, value=struct.unpack("<"+{4:"f",8:"d"}[size],read(va,size))[0],
                      sha256=digest(read(va,size))) for va,size in sorted(constant_specs)]
    comparisons = []
    for i in rows:
        if i.mnemonic in ("fcomp", "fcompp", "fcom", "fucom", "fucomp", "fucompp"):
            following = rows[positions[i.address]+1:positions[i.address]+16]
            consumer = next((j for j in following if j.mnemonic.startswith("j")), None)
            test = next((j for j in following if j.mnemonic == "test" and j.op_str.startswith("ah,")),None)
            assert consumer and test and consumer.mnemonic in ("je","jne")
            masks = {1:("less or unordered", "ordered greater or equal"),
                     0x40:("equal or unordered", "ordered unequal"),
                     0x41:("less, equal or unordered", "ordered greater")}
            nonzero, zero = masks[test.operands[1].imm]
            comparisons.append(dict(site=hx(i.address), operation=i.mnemonic, operand=i.op_str,
                branch_when_ST0_vs_operand=nonzero if consumer.mnemonic=="jne" else zero,
                flag_window=[dict(site=hx(j.address), operation=j.mnemonic, operands=j.op_str)
                             for j in following[:following.index(consumer)+1] if j.mnemonic in ("fnstsw","test","sahf") or j==consumer]
                             if consumer else []))
    assert len(comparisons) == 28
    return dict(work_unit="R16-A", specimen_sha256=SHA, export_manifest_sha256=MANIFEST_SHA,
        annotation_preflight_sha256=PREFLIGHT_SHA, evidence_class="complete local static instruction mapping; no execution oracle",
        decoder="Capstone 5.0.7 x86-32", address_kind="virtual addresses; file offsets explicitly labelled",
        function=dict(entry=hx(START), end_exclusive=hx(END), bytes=END-START,
            raw_file_offset=f"0x{offset(START,END-START):x}", code_sha256=digest(read(START,END-START)),
            instruction_count=len(rows), direct_call_count=len(calls), branch_count=len(branches),
            native_corroboration=dict(**native, all_instruction_addresses_mnemonics_operands_agree=True,
                checkpoint_archive_sha256=manifest["checkpoint_archive_sha256"]),
            selected_incoming_boundary=dict(site="00710654", caller="007103e0", ECX="slot in ESI",
                stack_argument=0, return_use="ignored; match pointer reread and byte+1a7 cleared after return",
                original_window_sha256=digest(read(0x710650,0x16)), exhaustive_incoming_list=False),
            direct_call_targets=[dict(target=t, count=len(sites), sites=sites) for t,sites in sorted(targets.items())],
            normal_call_stack_checks=dict(all_instruction_joins_balanced=True, return_restores_entry_esp=True,
                admitted_entry_stack_accesses=[dict(entry_esp_offset=d,width_bytes=w) for d,w in sorted(arg_accesses)],
                inferred_call_sites=sorted(call_depths,key=lambda c:c["site"]),
                limitation="Callee cleanup is inferred from complete local stack consistency, not a full callee contract; diagnostic nonreturn assumed"),
            branches=branches, switches=[dict(site=hx(a),**s) for a,s in switches.items()], returns=returns,
            direct_nonframe_stores=[dict(site=hx(i.address), width_bytes=i.operands[0].size, operation=i.mnemonic,
                destination=i.op_str.split(",")[0], source=i.op_str.split(",",1)[1].strip() if "," in i.op_str else None) for i in state_stores],
            all_explicit_memory_store_sites=[hx(i.address) for i in stores], rng_sites=rng_sites,
            x87_comparisons=comparisons,
            cfg=dict(block_count=len(blocks), all_blocks_reachable_structurally=True,
                block_columns=["start", "end_exclusive", "successors"],
                blocks=[[hx(b),hx(items[-1].address+items[-1].size),[hx(s) for s in edges[b]]] for b,items in blocks.items()],
                strongly_connected_cycles=[[hx(b) for b in c] for c in cycles],
                unbounded_rng_on_raw_graph=True, candidate_loop_max_iterations=127,
                upper_direct_rng_calls_with_loop_bound=rng_upper,
                upper_limit_kind="structural with signed-byte induction bound; ignores correlated predicates and transitive calls; not proved feasible",
                terminal_nonreturn_call="00713d55 -> 00945934")), constants=constants,
        limits=["Calls and exception unwinding may have unresolved transitive effects",
                "Graph reachability is not runtime feasibility; no connected shot-outcome claim",
                "Complete body comparison does not establish floating-point runtime control or input domains",
                "Switch tables lie outside the function body and are independently hash-pinned"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=Path("evidence/match-core-16-sites.json"))
    args = parser.parse_args()
    args.output.write_text(format_evidence(run(args))+"\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.output}; static decoder check only")

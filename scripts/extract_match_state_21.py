"""Check R21-B complete PE bodies against pinned read-only Ghidra exports.

Writes compact static sites, not original instructions, code bytes or game tables.
Integrity uses explicit exceptions and remains active with python -O.
"""
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
MANIFEST_SHA = "4963cc13eed5c5754f1afd776fa4ecf74427d1664029dcff47e047b9b3c8d460"
PREFLIGHT_SHA = "f09d2b563f4622f03e2cb81a6f06620567d87a2c6330c86e75e27cffef8de2a3"
SPECS = {0x6f5810: 772, 0x6c50d0: 271}
# Normal cleanup inferred from local call sequences; not a transitive proof.
CLEANUP = {0x62c3d0: 4, 0x6c38c0: 4, 0x62c590: 8,
           0x6ceb90: 12, 0x6f0630: 0, 0x6f46b0: 8, 0x7160e0: 4}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(n):
    return f"{n:08x}"


def memory_access(instruction, operand):
    # Capstone 5.0.7 labels FST/FSTP memory operands READ; override from x87 semantics.
    if instruction.mnemonic in ("fst", "fstp"):
        return capstone.CS_AC_WRITE
    return operand.access


def normalize(text):
    text = text.lower().replace("float ptr", "dword ptr").replace("double ptr", "qword ptr")
    def integer(m):
        n = int(m[0], 16)
        return str(n - 0x100000000 if n >= 0x80000000 else n)
    text = re.sub(r"0x[0-9a-f]+", integer, text)
    text = re.sub(r"\s+", "", text).replace("*1", "").replace("+-", "-").replace("+0]", "]")
    for old, new in (("jnz", "jne"), ("jz", "je")):
        if text.startswith(old):
            text = new + text[len(old):]
    return text


def compact(value, level=0):
    encoded = json.dumps(value)
    if len(encoded) <= 220:
        return encoded
    pad, child = "  " * level, "  " * (level + 1)
    if isinstance(value, dict):
        return "{\n" + ",\n".join(child + json.dumps(k) + ": " + compact(v, level + 1) for k, v in value.items()) + "\n" + pad + "}"
    if isinstance(value, list):
        return "[\n" + ",\n".join(child + compact(v, level + 1) for v in value) + "\n" + pad + "]"
    return encoded


def run(args):
    data = args.binary.read_bytes()
    require(digest(data) == SHA, "specimen SHA-256 mismatch")
    require(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    manifest_raw = (args.exports / "manifest.json").read_bytes()
    preflight_raw = args.preflight.read_bytes()
    require(digest(manifest_raw) == MANIFEST_SHA, "export manifest SHA-256 mismatch")
    require(digest(preflight_raw) == PREFLIGHT_SHA, "annotation preflight SHA-256 mismatch")
    manifest, preflight = json.loads(manifest_raw), json.loads(preflight_raw)
    require(manifest["specimen_sha256"] == preflight["sha256"] == SHA, "input specimen metadata mismatch")
    require(manifest["preflight_sha256"] == PREFLIGHT_SHA, "manifest preflight mismatch")
    require(set(manifest["files"]) == {hx(s) + "." + ext for s in SPECS for ext in ("asm", "c")}, "unexpected export file set")
    for name, meta in manifest["files"].items():
        raw = (args.exports / name).read_bytes()
        require(len(raw) == meta["bytes"] and digest(raw) == meta["sha256"], "export size/hash mismatch: " + name)
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    require(data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0", "invalid PE header")
    require(struct.unpack_from("<H", data, pe + 4)[0] == 0x14c, "expected x86 PE")
    count, optsize = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    require(struct.unpack_from("<H", data, optional)[0] == 0x10b, "expected PE32")
    base = struct.unpack_from("<I", data, optional + 28)[0]
    sections = [struct.unpack_from("<IIII", data, optional + optsize + 40 * n + 8)[1:] for n in range(count)]
    def offset(va, size):
        for rva, length, raw in sections:
            delta = va - base - rva
            if 0 <= delta and delta + size <= length:
                return raw + delta
        raise ValueError("range not backed by raw PE section")
    def read(va, size):
        pos = offset(va, size)
        return data[pos:pos + size]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    functions = []
    for start, length in SPECS.items():
        old = [s for s in preflight["sites"] if s["address"] == hx(start)]
        require(len(old) == 1 and old[0]["instruction_exists"] and old[0]["function_name"] == "FUN_" + hx(start), "exact-old name/site mismatch")
        require(old[0].get("function_comment") in (None, ""), "unexpected old comment")
        rows = list(md.disasm(read(start, length), start))
        require(sum(i.size for i in rows) == length, "incomplete body decode")
        exported = [(int(m[1], 16), m[2]) for m in re.finditer(r"^([0-9a-fA-F]{8})\s+(.+)$", (args.exports / (hx(start) + ".asm")).read_text(encoding="utf-8-sig"), re.M)]
        require(len(rows) == len(exported), "export instruction count mismatch")
        for i, (address, asm) in zip(rows, exported):
            require(i.address == address and normalize(asm) == normalize(i.mnemonic + " " + i.op_str), "native instruction/operand mismatch at " + hx(i.address))
        at = {i.address: i for i in rows}
        def successors(i):
            if i.mnemonic == "ret":
                return []
            ordinary = [i.address + i.size]
            if i.mnemonic.startswith("j"):
                require(i.operands[0].type == CS_OP_IMM, "indirect local branch")
                return [i.operands[0].imm] + ([] if i.mnemonic == "jmp" else ordinary)
            return ordinary
        branches, leaders = [], {start}
        for i in rows:
            ss = successors(i)
            require(all(s in at for s in ss), "out-of-body successor at " + hx(i.address))
            if i.mnemonic.startswith("j"):
                leaders.update(ss)
                if i.address + i.size in at:
                    leaders.add(i.address + i.size)
                branches.append([hx(i.address), i.mnemonic, [hx(s) for s in ss]])
        leaders = sorted(leaders)
        blocks = {b: [i for i in rows if b <= i.address < (leaders[n + 1] if n + 1 < len(leaders) else start + length)] for n, b in enumerate(leaders)}
        edges = {b: successors(items[-1]) for b, items in blocks.items()}
        reached, todo = set(), [start]
        while todo:
            b = todo.pop()
            if b not in reached:
                reached.add(b)
                todo.extend(edges[b])
        require(reached == set(blocks), "unreachable exported block")
        visiting, visited = set(), set()
        def has_cycle(b):
            if b in visiting:
                return True
            if b in visited:
                return False
            visiting.add(b)
            cycle = any(has_cycle(s) for s in edges[b])
            visiting.remove(b)
            visited.add(b)
            return cycle
        cyclic = has_cycle(start)
        require(cyclic == (start == 0x6c50d0), "unexpected CFG cyclicity")
        if start == 0x6c50d0:
            require([(i.address, s) for i in rows for s in successors(i) if s <= i.address] == [(0x6c51d3, 0x6c5124)], "unexpected scan backedge")
        calls = [i for i in rows if i.mnemonic == "call"]
        require(all(i.operands[0].type == CS_OP_IMM and i.operands[0].imm in CLEANUP for i in calls), "unexpected direct/indirect callee")
        targets = defaultdict(list)
        for i in calls:
            targets[hx(i.operands[0].imm)].append(hx(i.address))
        stack_at, todo, args_access, call_depths = {}, [(start, 0, 0)], set(), []
        while todo:
            site, delta, x87 = todo.pop()
            if site in stack_at:
                require(stack_at[site] == (delta, x87), "stack/x87 join mismatch at " + hx(site))
                continue
            stack_at[site] = (delta, x87)
            i = at[site]
            for o in i.operands:
                if o.type == CS_OP_MEM and i.reg_name(o.mem.base) == "esp" and delta + o.mem.disp >= 0:
                    args_access.add((delta + o.mem.disp, o.size, "write" if memory_access(i, o) & capstone.CS_AC_WRITE else "read"))
            if i.mnemonic == "push":
                delta -= 4
            elif i.mnemonic == "pop":
                delta += 4
            elif i.mnemonic in ("add", "sub") and i.op_str.startswith("esp,"):
                delta += i.operands[1].imm * (1 if i.mnemonic == "add" else -1)
            elif i.mnemonic == "call":
                cleanup = CLEANUP[i.operands[0].imm]
                call_depths.append([hx(site), delta, cleanup])
                delta += cleanup
            if i.mnemonic in ("fld", "fild"):
                x87 += 1
            elif i.mnemonic in ("fstp", "fcomp"):
                x87 -= 1
            require(0 <= x87 <= 8, "x87 stack depth outside range")
            todo.extend((s, delta, x87) for s in successors(i))
        require(len(stack_at) == len(rows), "not every instruction reached by stack analysis")
        returns = [i for i in rows if i.mnemonic == "ret"]
        require(all(stack_at[i.address] == (0, 0) for i in returns), "return stack imbalance")
        require([i.op_str for i in returns] == (["4"] if start == 0x6f5810 else [""]), "unexpected RET cleanup")
        require(args_access == ({(4, 1, "read"), (4, 4, "read"), (4, 4, "write")} if start == 0x6f5810 else set()), "unexpected caller-stack access: " + repr(args_access))
        stores, reads, floats = [], [], []
        for i in rows:
            for n, o in enumerate(i.operands):
                if o.type != CS_OP_MEM or i.mnemonic == "lea":
                    continue
                item = dict(site=hx(i.address), operation=i.mnemonic, operand=i.op_str.split(",")[n].strip(), width_bytes=o.size)
                if memory_access(i, o) & capstone.CS_AC_WRITE:
                    stores.append(item)
                if memory_access(i, o) & capstone.CS_AC_READ:
                    reads.append(item)
            if i.mnemonic.startswith("f"):
                floats.append(dict(site=hx(i.address), operation=i.mnemonic, depth_before=stack_at[i.address][1]))
        state = [s for s in stores if "[esp" not in s["operand"]]
        frame = [s for s in stores if s not in state]
        expected = {0x6f5810: (213, 34, 6, 10, 1), 0x6c50d0: (92, 15, 7, 2, 1)}
        actual = (len(rows), len(branches), len(calls), len(state), len(returns))
        require(actual == expected[start], "summary count mismatch " + repr((hx(start), actual)))
        functions.append(dict(entry=hx(start), native_body_bytes=length, admitted_body_bytes=length,
            body_ranges=[[hx(start), hx(start + length)]], range_end_kind="exclusive", file_offset=f"0x{offset(start, length):x}",
            body_sha256=digest(read(start, length)), instruction_count=len(rows), branch_count=len(branches), call_count=len(calls),
            direct_rng_site_count=0, nonframe_store_count=len(state), all_exported_instructions_match=True,
            native_exports={ext: manifest["files"][hx(start) + "." + ext]["sha256"] for ext in ("asm", "c")},
            branches=branches, direct_calls=[dict(target=t, count=len(s), sites=s) for t, s in sorted(targets.items())],
            normal_stack_check=dict(all_instruction_joins_balanced=True, all_returns_restore_entry_esp=True,
                x87_depth_balanced_assuming_callees_preserve_depth=True,
                entry_stack_access_columns=["entry_esp_offset", "width_bytes", "direction"], entry_stack_accesses=sorted(args_access),
                call_site_columns=["site", "esp_delta_before_call", "inferred_callee_cleanup_bytes"], call_sites=sorted(call_depths),
                limit="Normal callee cleanup and x87 preservation assumptions; no exceptional or transitive proof"),
            returns=[[hx(i.address), 4 if i.op_str else 0] for i in returns], nonframe_stores=state, frame_stores=frame,
            explicit_memory_reads=reads, x87_sites=floats,
            cfg=dict(all_blocks_structurally_reachable=True, contains_cycle=cyclic, block_count=len(blocks), block_columns=["start", "end_exclusive", "successors"],
                blocks=[[hx(b), hx(v[-1].address + v[-1].size), [hx(s) for s in edges[b]]] for b, v in blocks.items()],
                backward_edges=[[hx(i.address), hx(s)] for i in rows for s in successors(i) if s <= i.address],
                limit="Structural reachability does not prove feasible inputs; backwards shared epilogues are not necessarily loops")))
    constants = []
    for va in (0x96a608, 0x968dc0, 0x968910, 0x96d798, 0x96d790):
        raw = read(va, 8)
        constants.append(dict(address=hx(va), file_offset=f"0x{offset(va, 8):x}", width_bytes=8, value=struct.unpack("<d", raw)[0], sha256=digest(raw)))
    return dict(work_unit="R21-B", specimen_sha256=SHA, export_manifest_sha256=MANIFEST_SHA,
        annotation_preflight_sha256=PREFLIGHT_SHA, checkpoint_archive_sha256=manifest["checkpoint_archive_sha256"],
        evidence_class="complete local static instruction mapping; no execution oracle", decoder="Capstone 5.0.7 x86-32",
        integrity_under_python_optimized_mode="explicit ValueError checks; no assert integrity gates", address_kind="virtual; raw file offsets labelled",
        functions=functions, float64_constants=constants,
        limits=["All transitive writes/RNG/failures remain boundaries", "No numerical x87 oracle or actual control-word measurement", "No live pointer validity, lifecycle, connected outcome or subsystem equivalence"])


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("evidence/match-state-21-sites.json"))
    args = p.parse_args()
    result = run(args)  # Validate everything before opening the output.
    args.output.write_text(compact(result) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.output}; static decoder check only")

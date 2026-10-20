"""R41-B: bounded lookup/refresh replay and exact two-build capture map.

No process access. Public outputs use synthetic inputs only. Captures and raw
memory remain private; this tool does not establish a producer or game lifetime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x
from check_gdi_anchors_40 import read_pe, code_at, EXPECTED


ROOT = Path(__file__).resolve().parents[1]
REGS = {n: getattr(x, "UC_X86_REG_" + n.upper())
        for n in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip")}
# All sizes end at instruction boundaries. The skipped initialization arms are
# checked statically; execution admission below does not include their calls.
RANGES = (
    ("lookup-entry", 0x62ed70, 0x62e6e0, 0x15),
    ("lookup-normal-tail", 0x62ede1, 0x62e751, 0x4a),
    ("refresh-guards", 0x62c680, 0x62bff0, 0x116),
    ("refresh-return", 0x62cde1, 0x62c751, 0x14),
    ("effect-consumer", 0x6cfeb8, 0x6cf8e8, 15),
    ("participant-store", 0x6eaead, 0x6ea8dd, 0x32),
    ("match-advance-entry", 0x6b98c0, 0x6b92f0, 17),
    ("staff-base-source", 0x89699f, 0x89618f, 5),
    ("small-bound-rng", 0x90cfc0, 0x90c860, 0x6d),
    ("crt-rng", 0x946a04, 0x946264, 0x1e),
)
# Explicitly authored relocation list. Constants and widths are never normalized.
EXTERNAL_MAP = {
    0x95b0f8: 0x95a938, 0xb63d10: 0xb62c58, 0xb63d08: 0xb62c50,
    0xb63d18: 0xb62c60, 0xb63d20: 0xb62c68, 0xb63d28: 0xb62c70,
    0xae2364: 0xae12b4, 0xae2c90: 0xae1be0, 0xae2c92: 0xae1be2,
    0x54a110: 0x54a2b0, 0x94627a: 0x945ada,
    0x62ce20: 0x62c790, 0x62ce10: 0x62c780, 0x62ce00: 0x62c770,
    0x62c796: 0x62c106, 0x6eaedf: 0x6ea90f, 0x6eaf46: 0x6ea976,
    0xae23bc: 0xae130c, 0xde1f60: 0xde0ea8, 0xde2798: 0xde16e0,
    0xde1f5c: 0xde0ea4, 0xaa2454: 0xaa139c, 0xad6c30: 0xad5b80,
    0x90d02d: 0x90c8cd,
}
GLOBALS = {
    "pinned": {"flags": 0xb63d10, "count": 0xae2364, "date": 0xae2c90,
               "lookup": 0xb63d28, "staff_base": 0xae23bc},
    "gdi": {"flags": 0xb62c58, "count": 0xae12b4, "date": 0xae1be0,
            "lookup": 0xb62c70, "staff_base": 0xae130c},
}
RNG_GLOBALS = {
    "pinned": {"cursor": 0xde1f60, "offset": 0xde1f5c, "limit": 0xde2798,
               "seed": 0xad6c30, "table": 0xaa2454},
    "gdi": {"cursor": 0xde0ea8, "offset": 0xde0ea4, "limit": 0xde16e0,
            "seed": 0xad5b80, "table": 0xaa139c},
}
STACK, STOP = 0x308000, 0x700000
PLAYER, RECEIVER, ROWS, CACHE, ATTRIBUTE = 0x200000, 0x210000, 0x220000, 0x230000, 0x240000


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hx(n):
    return f"{n:08x}"


def relocated(address, build):
    if build == "pinned":
        return address
    for _, start, target, size in RANGES:
        if start <= address < start + size:
            return target + address - start
    need(address in EXTERNAL_MAP, "unlisted address relocation " + hx(address))
    return EXTERNAL_MAP[address]


def operand(ins, op):
    if op.type == capstone.x86.X86_OP_REG:
        return ("reg", op.size, ins.reg_name(op.reg))
    if op.type == capstone.x86.X86_OP_IMM:
        return ("imm", op.size, op.imm & 0xffffffff)
    if op.type == capstone.x86.X86_OP_MEM:
        m = op.mem
        return ("mem", op.size, ins.reg_name(m.segment), ins.reg_name(m.base),
                ins.reg_name(m.index), m.scale, m.disp)
    raise ValueError("unsupported decoded operand")


def evidence(pinned, gdi):
    need(capstone.__version__ == "5.0.7", "requires Capstone 5.0.7")
    images = {"pinned": read_pe(pinned, "pinned"), "gdi": read_pe(gdi, "gdi")}
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    rows, decoded = [], {k: {} for k in images}
    for name, start, target, size in RANGES:
        bodies = [code_at(images[k], a, size) for k, a in (("pinned", start), ("gdi", target))]
        sequences = [list(decoder.disasm(b[0], a)) for b, a in zip(bodies, (start, target))]
        need(all(sum(i.size for i in seq) == size for seq in sequences), "incomplete decode " + name)
        need(len(sequences[0]) == len(sequences[1]), "instruction count mismatch")
        for a, b in zip(*sequences):
            need(b.address - target == a.address - start and a.size == b.size and
                 a.mnemonic == b.mnemonic and len(a.operands) == len(b.operands),
                 "instruction structure mismatch at " + hx(a.address))
            for left, right in zip(a.operands, b.operands):
                first, second = operand(a, left), operand(b, right)
                if first != second:
                    if left.type == capstone.x86.X86_OP_IMM:
                        need(first[:2] == second[:2] and relocated(first[2], "gdi") == second[2],
                             "immediate mismatch at " + hx(a.address))
                    elif left.type == capstone.x86.X86_OP_MEM:
                        need(first[:-1] == second[:-1] and not left.mem.base and not left.mem.index and
                             relocated(first[-1], "gdi") == second[-1],
                             "memory source/width mismatch at " + hx(a.address))
                    else:
                        raise ValueError("register mismatch at " + hx(a.address))
            decoded["pinned"][a.address] = a
            decoded["gdi"][b.address] = b
        rows.append({"name": name, "pinned_va": hx(start), "gdi_va": hx(target),
                     "bytes": size, "instructions": len(sequences[0]),
                     "pinned_file_offset": hx(bodies[0][1]), "gdi_file_offset": hx(bodies[1][1]),
                     "pinned_sha256": sha(bodies[0][0]), "gdi_sha256": sha(bodies[1][0]),
                     "operands_match_explicit_map": True})
    return images, decoded, {
        "schema": "reversal.engine-state-41.map.v1",
        "specimens": {k: {"sha256": EXPECTED[k][0], "bytes": EXPECTED[k][1]} for k in images},
        "ranges": rows, "globals": GLOBALS, "rng_globals": RNG_GLOBALS,
        "scope": "selected disk instructions and explicit operand relocations; no whole-build or runtime equivalence",
        "unexecuted_targets": [hx(a) for a in (0x54a110, 0x94627a, 0x62ce20, 0x62ce10, 0x62ce00)],
    }


def synthetic_schedule():
    return [{"index": index, "count": 64, "mapping": mapping, "flags": flags,
             "date": date, "old_seh": seh, "x87_control": cw,
             "shared_rng": {"cursorIndex": 17, "offset": 999, "crtState": 0x12345678}}
            for index, mapping, flags, date, seh, cw in
            ((i, m, 7 if k % 2 == 0 else 255, 0x001a07ea ^ (k << 16),
              (0, 0x30f000, 0xfedcba98)[k % 3], 0x27f if k % 2 else 0x37f)
             for k, (i, m) in enumerate((i, m) for i in (0, 7, 31) for m in (-1, 0, 2)))]


def validate_input(case):
    need(set(case) == {"index", "count", "mapping", "flags", "date", "old_seh",
                       "x87_control", "shared_rng"}, "unknown/missing input field")
    need(all(isinstance(case[k], int) and not isinstance(case[k], bool)
             for k in ("index", "count", "mapping", "flags", "date", "old_seh", "x87_control")),
         "integer input required")
    need(0 <= case["index"] < case["count"] <= 64, "unsupported staff range")
    need(case["mapping"] in (-1, 0, 2), "unsupported synthetic cache mapping")
    need(0 <= case["flags"] <= 255 and case["flags"] & 7 == 7, "initialization not admitted")
    need(0 <= case["date"] <= 0xffffffff and 0 <= case["old_seh"] <= 0xffffffff, "DWORD required")
    need(case["x87_control"] in (0x27f, 0x37f), "unsupported x87 control")
    rng = case["shared_rng"]
    need(set(rng) == {"cursorIndex", "offset", "crtState"} and
         all(type(n) is int and 0 <= n <= 0xffffffff for n in rng.values()) and
         rng["cursorIndex"] < 51000 and rng["offset"] <= 65535, "shared RNG state shape")


def execute(images, decoded, build, case, _mutate=None):
    validate_input(case)
    need(unicorn.__version__ == "2.1.4", "requires Unicorn 2.1.4")
    image, ins, globals_ = images[build], decoded[build], GLOBALS[build]
    rng_globals = RNG_GLOBALS[build]
    rng_addresses = [rng_globals[k] for k in ("cursor", "offset", "limit", "seed")]
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    pages = {a & ~0xfff for a in ins}
    pages.update({0, STOP, PLAYER, RECEIVER, ROWS, CACHE, ATTRIBUTE})
    pages.update(v & ~0xfff for v in globals_.values())
    pages.update(v & ~0xfff for v in rng_addresses)
    pages.update(range(0x300000, 0x310000, 0x1000))
    for page in sorted(pages):
        uc.mem_map(page, 0x1000)
    for _, start, target, size in RANGES[:4]:
        address = start if build == "pinned" else target
        uc.mem_write(address, code_at(image, address, size)[0])
    write = lambda a, v: uc.mem_write(a, struct.pack("<I", v & 0xffffffff))
    read = lambda a, n=4: int.from_bytes(uc.mem_read(a, n), "little")
    write(0, case["old_seh"])
    write(PLAYER, case["index"]); write(PLAYER + 0x61, ATTRIBUTE)
    write(RECEIVER, ROWS); write(RECEIVER + 4, CACHE); write(RECEIVER + 8, 3)
    row = ROWS + 31 * case["index"]
    write(row, case["date"]); write(row + 4, 0x12345678); write(row + 0xe, case["mapping"])
    uc.mem_write(globals_["flags"], bytes([case["flags"]]))
    write(globals_["count"], case["count"]); write(globals_["date"], case["date"])
    write(globals_["lookup"], RECEIVER)
    rng = case["shared_rng"]
    for key, value in (("cursor", rng_globals["table"] + 4 * rng["cursorIndex"]),
                       ("offset", rng["offset"]), ("limit", rng_globals["table"] + 4 * 50999),
                       ("seed", rng["crtState"])):
        write(rng_globals[key], value)
    rng_bytes = lambda: b"".join(bytes(uc.mem_read(a, 4)) for a in rng_addresses)
    write(STACK, STOP); write(STACK + 4, PLAYER)
    initial = {"eax": 0xdeadbeef, "ebx": 0x12345678, "ecx": RECEIVER, "edx": 0x87654321,
               "esi": 0x01020304, "edi": 0xfeedface, "ebp": 0xcafef00d, "esp": STACK,
               "eip": relocated(0x62ed70, build)}
    for name, value in initial.items():
        uc.reg_write(REGS[name], value)
    uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    uc.reg_write(x.UC_X86_REG_FPCW, case["x87_control"])
    if _mutate is not None:
        _mutate(uc)
    before = {page: bytes(uc.mem_read(page, 0x1000)) for page in pages if page < 0x300000 or page >= 0x310000}
    trace, events, boundaries = [], [], []
    current = 0
    lookup_call, lookup_return = relocated(0x62edfc, build), relocated(0x62ee01, build)
    allowed = {relocated(a, build) for a in (
        0x62ed70,0x62ed76,0x62ed77,0x62ed78,0x62ed7f,0x62ed81,0x62ed83,
        0x62ede1,0x62ede2,0x62ede4,0x62ede5,0x62edeb,0x62edee,0x62edf0,
        0x62edf5,0x62edf7,0x62edf9,0x62edfa,0x62edfc,0x62ee01,0x62ee03,
        0x62ee05,0x62ee08,0x62ee0a,0x62ee0c,0x62ee10,0x62ee13,0x62ee15,
        0x62ee18,0x62ee1b,0x62ee1e,0x62ee1f,0x62ee21,0x62ee22,0x62ee28,
        0x62c680,0x62c682,0x62c687,0x62c68d,0x62c68e,0x62c695,0x62c698,
        0x62c69d,0x62c69e,0x62c69f,0x62c6a0,0x62c6a2,0x62c6a4,0x62c6a6,
        0x62c6aa,0x62c6ae,0x62c6b2,0x62c6b6,0x62c6da,0x62c6df,0x62c6e1,
        0x62c705,0x62c70b,0x62c70d,0x62c70f,0x62c732,0x62c736,0x62c738,
        0x62c73e,0x62c740,0x62c746,0x62c748,0x62c74e,0x62c751,0x62c753,
        0x62c757,0x62c75d,0x62c760,0x62c762,0x62c765,0x62c767,0x62c76a,
        0x62c76c,0x62c770,0x62c775,0x62c779,0x62c77c,0x62c783,0x62c787,
        0x62c789,0x62c790,0x62cde1,0x62cde5,0x62cde6,0x62cde7,0x62cde8,
        0x62cdef,0x62cdf2)}

    def snapshot(kind):
        return {"kind": kind, "site": hx(current), "receiver": uc.reg_read(REGS["ecx"]),
                "stack": uc.reg_read(REGS["esp"]), "argument": read(uc.reg_read(REGS["esp"]))
                if kind == "refresh-call" else None,
                "rng_sha256": sha(rng_bytes()),
                "row_sha256": sha(bytes(uc.mem_read(row, 31)))}

    def on_code(machine, address, size, _):
        nonlocal current
        current = address
        if address == STOP:
            machine.emu_stop()
            return
        need(address in allowed, "execution escaped cached-status admission at " + hx(address))
        trace.append(hx(address))
        need(len(trace) < 160, "unexpected lookup loop")
        if address == lookup_call:
            boundaries.append(snapshot("refresh-call"))
        if address == lookup_return:
            boundaries.append(snapshot("refresh-return"))

    def on_memory(machine, access, address, size, value, _):
        if 0x300000 <= address < 0x310000:
            return
        kind = "read" if access == unicorn.UC_MEM_READ else "write"
        events.append([hx(current), kind, hx(address), size,
                       read(address, size) if kind == "read" else value & ((1 << (size * 8)) - 1)])

    uc.hook_add(unicorn.UC_HOOK_CODE, on_code)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, on_memory)
    uc.emu_start(initial["eip"], STOP + 1, count=160)
    final = {n: uc.reg_read(r) for n, r in REGS.items()}
    expected = 0 if case["mapping"] == -1 else CACHE + 48 * case["mapping"]
    need(final["eip"] == STOP and final["esp"] == STACK + 8 and final["eax"] == expected,
         "lookup return mismatch")
    need(all(final[n] == initial[n] for n in ("ebx", "esi", "edi", "ebp")), "nonvolatile change")
    need(all(bytes(uc.mem_read(p, 0x1000)) == data for p, data in before.items()),
         "represented nonstack memory changed")
    need(uc.reg_read(x.UC_X86_REG_FPCW) == case["x87_control"], "x87 control changed")
    need(len(boundaries) == 2 and all(b["rng_sha256"] == sha(rng_bytes())
                                    for b in boundaries), "call continuity/RNG mismatch")
    need(hx(relocated(0x62c790, build)) in trace, "cached-stamp branch was not executed")
    return {"build": build, "input": case, "initial": initial, "final": final,
            "trace": trace, "events": events, "boundaries": boundaries,
            "result": {"pointer": final["eax"], "mapping": case["mapping"], "row": row,
                       "rng": {"cursorIndex": (read(rng_globals["cursor"]) - rng_globals["table"]) // 4,
                               "offset": read(rng_globals["offset"]), "crtState": read(rng_globals["seed"])},
                       "x87_control": uc.reg_read(x.UC_X86_REG_FPCW),
                       "nonstack_memory_unchanged": True},
            "instruction_steps": len(trace)}


def generate(pinned, gdi):
    images, decoded, mapping = evidence(pinned, gdi)
    cases = [execute(images, decoded, build, case)
             for build in ("pinned", "gdi") for case in synthetic_schedule()]
    return {"schema": "reversal.engine-state-41.synthetic.v1", "mapping": mapping,
            "scope": "separate synthetic lookup entries through actual refresh call/return; no live producer, effect or resolver join",
            "cases": cases, "instruction_steps": sum(c["instruction_steps"] for c in cases)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pinned", type=Path)
    parser.add_argument("gdi", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.pinned, args.gdi)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"cases": len(result["cases"]), "steps": result["instruction_steps"]}))


if __name__ == "__main__":
    main()

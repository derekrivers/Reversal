#!/usr/bin/env python3
"""Run both pinned original iterator entries on deterministic synthetic memory."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

from unicorn import (Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE,
    UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ, UC_MEM_WRITE)
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
    UC_X86_REG_ESP, UC_X86_REG_EIP)

from extract_iterator_helpers_27 import extract, sha

ROOT = 0x200000
NODE = 0x300000
STACK = 0x400000
ESP = STACK + 0x800
STOP = 0x700000
REGS = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX, "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
        "ebp": UC_X86_REG_EBP, "esp": UC_X86_REG_ESP, "eip": UC_X86_REG_EIP}


def u32(n):
    return (n & 0xffffffff).to_bytes(4, "little")


def schedule():
    values = [0, 1, 0x12345678, 0x7fffffff, 0x80000000, 0xffffffff]
    links = [0, NODE + 0x200, 0x7fffffff, 0xffffffff]
    for entry, link in [(0x68d1b0, 6), (0x68d1d0, 10)]:
        for seed in range(16):
            yield {"entry": f"{entry:08x}", "link_offset": link,
                   "seed": seed, "cursor": 0, "payload": 0, "next": 0}
        for seed in range(16):
            for payload in values:
                for next_node in links:
                    yield {"entry": f"{entry:08x}", "link_offset": link,
                           "seed": seed, "cursor": NODE + 0x100,
                           "payload": payload, "next": next_node}


def run(exe, exports, preflight):
    sites = extract(exe, exports, preflight)
    if len(sites["functions"]) != 2:
        raise ValueError("unexpected static site count")
    data = exe.read_bytes()
    cases = []
    covered = set()
    covered_edges = set()
    total_steps = 0
    for item in schedule():
        entry = int(item["entry"], 16)
        static = next(x for x in sites["functions"] if x["entry_va"] == item["entry"])
        body = data[int(static["file_offset"], 16):int(static["file_offset"], 16) + 19]
        if sha(body) != static["body_sha256"]:
            raise ValueError("body changed after static extraction")
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x680000, 0x10000)
        uc.mem_map(ROOT, 0x1000)
        uc.mem_map(NODE, 0x1000)
        uc.mem_map(STACK, 0x1000)
        uc.mem_map(STOP, 0x1000)
        uc.mem_write(entry, body)
        seed = item["seed"]
        receiver = bytes((i*29 + seed*17 + 3) & 255 for i in range(0x1000))
        nodes = bytes((i*37 + seed*23 + 7) & 255 for i in range(0x1000))
        stack = bytes((i*19 + seed*11 + 5) & 255 for i in range(0x1000))
        uc.mem_write(ROOT, receiver)
        uc.mem_write(NODE, nodes)
        uc.mem_write(STACK, stack)
        uc.mem_write(ROOT + 0xa, u32(item["cursor"]))
        if item["cursor"]:
            uc.mem_write(item["cursor"], u32(item["payload"]))
            uc.mem_write(item["cursor"] + item["link_offset"], u32(item["next"]))
        uc.mem_write(ESP, u32(STOP))
        initial = {"eax": (seed*0x1020304 + 0xdeadbeef) & 0xffffffff,
                   "ebx": 0x87654321 ^ seed, "ecx": ROOT,
                   "edx": 0x12345678 ^ seed, "esi": 0x01020304 ^ seed,
                   "edi": 0xfeedface ^ seed, "ebp": 0xcafef00d ^ seed,
                   "esp": ESP, "eip": entry}
        for name, value in initial.items():
            uc.reg_write(REGS[name], value)
        events = []
        trace = []

        def on_mem(_uc, kind, address, width, value, _data):
            if ROOT <= address < ROOT + 0x1000 or NODE <= address < NODE + 0x1000:
                if address + width > (ROOT + 0x1000 if address < NODE else NODE + 0x1000):
                    raise ValueError("cross-region access")
                if kind not in (UC_MEM_READ, UC_MEM_WRITE):
                    raise ValueError("unexpected memory hook kind")
                row = ["read" if kind == UC_MEM_READ else "write", f"{address:08x}", width]
                if kind == UC_MEM_WRITE:
                    row.append(value & ((1 << (8*width)) - 1))
                events.append(row)

        def on_code(_uc, address, size, _data):
            if not entry <= address < entry + 19:
                raise ValueError("executed outside body")
            trace.append(f"{address:08x}")
            if len(trace) > 9:
                raise ValueError("unexpected loop")

        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_mem)
        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.emu_start(entry, STOP, count=20)
        final = {name: uc.reg_read(reg) for name, reg in REGS.items()}
        if final["eip"] != STOP or final["esp"] != ESP + 4:
            raise ValueError("did not return normally")
        if any(final[x] != initial[x] for x in ("ebx", "ecx", "esi", "edi", "ebp")):
            raise ValueError("unexpected preserved-register change")
        if bytes(uc.mem_read(STACK + 0x804, 0x7fc)) != stack[0x804:]:
            raise ValueError("stack mutated")
        digest = [sha(bytes(uc.mem_read(base, 0x1000))) for base in (ROOT, NODE)]
        cases.append({"input": item, "initial": initial, "final": final,
                      "events": events, "trace": trace, "memory_sha256": digest})
        covered.update(trace)
        covered_edges.update(zip(trace, trace[1:]))
        total_steps += len(trace)
    expected_edges = {tuple(edge) for f in sites["functions"] for edge in f["edges"]}
    if (len(cases) != 800 or len(covered) != 18 or total_steps != 5536
            or covered_edges != expected_edges):
        raise ValueError(f"coverage mismatch: {len(cases)} {len(covered)} {total_steps}")
    return {"work_unit": "R27-A", "specimen_sha256": sites["specimen_sha256"],
            "checkpoint_archive_sha256": sites["checkpoint_archive_sha256"],
            "export_manifest_sha256": sites["export_manifest_sha256"],
            "preflight_sha256": sites["preflight_sha256"],
            "sites_sha256": sha((Path("evidence/iterator-helpers-27-sites.json")).read_bytes()),
            "synthetic_only": True, "cases_count": len(cases),
            "executed_instruction_steps": total_steps,
            "covered_instruction_starts": sorted(covered),
            "covered_edges": sorted([list(edge) for edge in covered_edges]), "cases": cases}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    payload = json.dumps(run(args.exe, args.exports, args.preflight), separators=(",", ":"), sort_keys=True).encode()
    with args.output.open("wb") as file:
        with gzip.GzipFile(fileobj=file, mode="wb", filename="", mtime=0, compresslevel=9) as packed:
            packed.write(payload)

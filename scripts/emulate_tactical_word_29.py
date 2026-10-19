#!/usr/bin/env python3
"""Execute both sealed tactical-word entries over synthetic mapped memory."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ, UC_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

from extract_tactical_word_29 import extract, sha

MATCH = 0x300000
SLOT = 0x400000
TABLE = 0x500000
STACK = 0x600000
ESP = STACK + 0x800
STOP = 0x700000
REGS = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX, "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
        "ebp": UC_X86_REG_EBP, "esp": UC_X86_REG_ESP, "eip": UC_X86_REG_EIP}


def u32(value):
    return (value & 0xffffffff).to_bytes(4, "little")


def schedule():
    sides = [0x80, 0xfe, 0xff, 0, 1, 2, 0x7f]
    for entry in (0x6c38c0, 0x6c38f0):
        for index in range(256):
            yield {"entry": f"{entry:08x}", "index": index,
                   "side": sides[index % len(sides)], "seed": index % 4}
        for side in sides:
            for index in (0, 1, 10, 11, 0x7f, 0x80, 0xff):
                yield {"entry": f"{entry:08x}", "index": index,
                       "side": side, "seed": (side+index) % 4}


def run(exe, exports, preflight):
    sites = extract(exe, exports, preflight)
    data = exe.read_bytes()
    cases = []
    covered = set()
    covered_edges = set()
    steps = 0
    for item in schedule():
        entry = int(item["entry"], 16)
        site = next(f for f in sites["functions"] if f["entry_va"] == item["entry"])
        body = data[int(site["file_offset"], 16):int(site["file_offset"], 16)+42]
        if sha(body) != site["body_sha256"]:
            raise ValueError("body changed after static extraction")
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(0x6c3000, 0x1000)
        uc.mem_map(MATCH, 0x10000)
        for base in (SLOT, TABLE, STACK, STOP):
            uc.mem_map(base, 0x1000)
        uc.mem_write(entry, body)
        seed = item["seed"]
        match = bytearray((i*13+seed*17+7) & 255 for i in range(0x10000))
        slot = bytearray((i*29+seed*11+3) & 255 for i in range(0x1000))
        table = bytearray((i*37+seed*23+5) & 255 for i in range(0x1000))
        stack = bytearray((i*19+seed*31+9) & 255 for i in range(0x1000))
        slot[0x19] = item["index"]
        slot[0x27] = item["side"]
        signed_side = item["side"] if item["side"] < 128 else item["side"]-256
        ptr_at = site["table_pointer_offset"] + signed_side*4
        match[ptr_at:ptr_at+4] = u32(TABLE+0x400)
        stack[0x800:0x804] = u32(STOP)
        stack[0x804:0x808] = u32(SLOT)
        for base, blob in ((MATCH, match), (SLOT, slot), (TABLE, table), (STACK, stack)):
            uc.mem_write(base, bytes(blob))
        initial = {"eax": (0xa1350000 | (seed*0x1111)) & 0xffffffff,
                   "ebx": 0x87654321 ^ seed, "ecx": MATCH,
                   "edx": 0x12345678 ^ seed, "esi": 0x01020304 ^ seed,
                   "edi": 0xfeedface ^ seed, "ebp": 0xcafef00d ^ seed,
                   "esp": ESP, "eip": entry}
        for name, value in initial.items():
            uc.reg_write(REGS[name], value)
        events = []
        trace = []

        def on_mem(_uc, kind, address, width, value, _data):
            ranges = ((MATCH, 0x10000), (SLOT, 0x1000), (TABLE, 0x1000), (STACK, 0x1000))
            if not any(base <= address and address+width <= base+size for base, size in ranges):
                raise ValueError(f"access outside admitted memory {address:08x}")
            if kind not in (UC_MEM_READ, UC_MEM_WRITE):
                raise ValueError("unexpected memory event")
            event = ["read" if kind == UC_MEM_READ else "write", f"{address:08x}", width]
            if kind == UC_MEM_WRITE:
                event.append(value & ((1 << (width*8))-1))
            events.append(event)

        def on_code(_uc, address, _size, _data):
            if not entry <= address < entry+42 or len(trace) >= 13:
                raise ValueError("execution left sealed local body")
            trace.append(f"{address:08x}")

        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_mem)
        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.emu_start(entry, STOP, count=20)
        final = {name: uc.reg_read(reg) for name, reg in REGS.items()}
        if final["eip"] != STOP or final["esp"] != ESP+8:
            raise ValueError("did not return with RET 4")
        hashes = [sha(bytes(uc.mem_read(base, size))) for base, size in
                  ((MATCH, 0x10000), (SLOT, 0x1000), (TABLE, 0x1000), (STACK, 0x1000))]
        cases.append({"input": item, "initial": initial, "final": final,
                      "events": events, "trace": trace, "memory_sha256": hashes})
        covered.update(trace)
        covered_edges.update(zip(trace, trace[1:]))
        steps += len(trace)
    expected = {tuple(edge) for site in sites["functions"] for edge in site["edges"]}
    if len(cases) != 610 or len(covered) != 26 or covered_edges != expected:
        raise ValueError("coverage mismatch")
    return {"work_unit": "R29-B", "specimen_sha256": sites["specimen_sha256"],
            "export_manifest_sha256": sites["export_manifest_sha256"],
            "preflight_sha256": sites["preflight_sha256"],
            "sites_sha256": sha(Path("evidence/tactical-word-29-sites.json").read_bytes()),
            "synthetic_only": True, "cases_count": len(cases),
            "executed_instruction_steps": steps,
            "covered_instruction_starts": sorted(covered),
            "covered_edges": sorted([list(edge) for edge in covered_edges]),
            "cases": cases}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("exe", "exports", "preflight", "output"):
        parser.add_argument(name, type=Path)
    a = parser.parse_args()
    payload = json.dumps(run(a.exe, a.exports, a.preflight), separators=(",", ":"), sort_keys=True).encode()
    with a.output.open("wb") as file:
        with gzip.GzipFile(fileobj=file, mode="wb", filename="", mtime=0, compresslevel=9) as packed:
            packed.write(payload)

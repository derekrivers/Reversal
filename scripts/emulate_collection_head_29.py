#!/usr/bin/env python3
"""Original-entry synthetic oracle for R29-C's call-free current payload getter."""
import argparse
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ, UC_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP

from extract_collection_continuation_29 import extract, sha, SPECIMEN

DATA, STACK, STOP = 0x200000, 0x400000, 0x700000
ESP = STACK + 0x800
OFFSETS = (0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 1535, 2047, 3071, 4082)
REGS = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX, "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
        "ebp": UC_X86_REG_EBP, "esp": UC_X86_REG_ESP, "eip": UC_X86_REG_EIP}


def u32(v):
    return (v & 0xffffffff).to_bytes(4, "little")


def run(exe, exports, preflight):
    sites = extract(exe, exports, preflight)
    site = sites["bodies"]["0068d2e0"]
    if site["body_bytes"] != 13 or site["instruction_count"] != 7 or site["direct_calls"]:
        raise ValueError("getter static site changed")
    body = exe.read_bytes()[int(site["file_offset"], 16):][:13]
    if sha(body) != site["body_sha256"]:
        raise ValueError("getter body changed after extraction")
    cases, covered, edges, steps = [], set(), set(), 0
    for mode in range(4):
        for seed in range(16):
            for offset in OFFSETS:
                receiver = DATA + offset
                cursor = 0 if mode == 0 else (receiver if mode == 1 else DATA + 0x800 + ((seed * 31 + offset) % 0x7f0))
                uc = Uc(UC_ARCH_X86, UC_MODE_32)
                for base in (0x68d000, DATA, STACK, STOP):
                    uc.mem_map(base, 0x1000)
                uc.mem_write(0x68d2e0, body)
                uc.mem_write(DATA, bytes((i * 29 + seed * 17 + mode * 11 + 3) & 255 for i in range(0x1000)))
                uc.mem_write(STACK, bytes((i * 19 + seed * 13 + 5) & 255 for i in range(0x1000)))
                uc.mem_write(receiver + 10, u32(cursor))
                if cursor and mode >= 2:
                    uc.mem_write(cursor, u32((seed * 0x10203041 + mode * 0x80000001 + offset) & 0xffffffff))
                uc.mem_write(ESP, u32(STOP))
                initial = {"eax": (0xdeadbeef + seed * 0x10101 + offset) & 0xffffffff,
                           "ebx": 0x87654321 ^ seed, "ecx": receiver, "edx": 0x12345678 ^ offset,
                           "esi": 0x01020304 ^ seed, "edi": 0xfeedface ^ offset,
                           "ebp": 0xcafef00d ^ mode, "esp": ESP, "eip": 0x68d2e0}
                for name, value in initial.items():
                    uc.reg_write(REGS[name], value)
                events, trace = [], []

                def on_code(_uc, address, _size, _):
                    if not 0x68d2e0 <= address < 0x68d2ed or len(trace) >= 8:
                        raise ValueError("execution escaped bounded original body")
                    trace.append(f"{address:08x}")

                def on_mem(_uc, kind, address, width, value, _):
                    if not any(base <= address and address + width <= base + 0x1000 for base in (DATA, STACK)):
                        raise ValueError("unexpected data access")
                    event = ["read" if kind == UC_MEM_READ else "write", f"{address:08x}", width]
                    if kind == UC_MEM_WRITE:
                        event.append(value & ((1 << (width * 8)) - 1))
                    events.append(event)

                uc.hook_add(UC_HOOK_CODE, on_code)
                uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, on_mem)
                uc.emu_start(0x68d2e0, STOP, count=8)
                final = {name: uc.reg_read(reg) & 0xffffffff for name, reg in REGS.items()}
                if final["eip"] != STOP or final["esp"] != ESP + 4:
                    raise ValueError("getter did not return normally")
                covered.update(trace)
                edges.update(zip(trace, trace[1:]))
                steps += len(trace)
                cases.append({"input": {"mode": mode, "seed": seed, "offset": offset, "receiver": receiver, "cursor": cursor},
                              "initial": initial, "final": final, "trace": trace, "events": events,
                              "memory_sha256": [sha(bytes(uc.mem_read(base, 0x1000))) for base in (DATA, STACK)]})
    expected = {"0068d2e0", "0068d2e3", "0068d2e5", "0068d2e7", "0068d2e9", "0068d2ea", "0068d2ec"}
    if covered != expected or len(edges) != site["local_edge_count"]:
        raise ValueError("original-entry coverage mismatch")
    return {"work_unit": "R29-C", "specimen_sha256": SPECIMEN,
            "sites_sha256": sha((Path("evidence") / "collection-continuation-29-sites.json").read_bytes()),
            "domain": "1024 original-entry mapped synthetic inputs; null, receiver-alias and separate cursor cases",
            "cases_count": len(cases), "executed_instruction_steps": steps,
            "covered_instruction_starts": sorted(covered), "covered_edges": sorted(map(list, edges)), "cases": cases}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for field in ("exe", "exports", "preflight", "output"):
        p.add_argument(field, type=Path)
    a = p.parse_args()
    result = run(a.exe, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")
    print("R29-C getter cases/steps:", result["cases_count"], result["executed_instruction_steps"])

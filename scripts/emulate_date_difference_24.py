#!/usr/bin/env python3
"""Original entry-to-RET12 oracle for preinitialized, nonrecursive 0054cc30."""
import argparse
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_ESP, UC_X86_REG_EIP)

from extract_date_difference_24 import extract, SPECIMEN, ARCHIVE, MANIFEST, PREFLIGHT, START, LENGTH

BODY_SHA = "d73e8cd4f09bf3b5859ea806051e0f5c0e86d0521573729594358ddc32e82143"
STOP, STACK, RECEIVER, OUTPUT, GLOBAL = 0x700000, 0x108000, 0x200000, 0x210000, 0x00ae2428
FLAG = 0x00ae249d
REGS = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX, "ebp": UC_X86_REG_EBP, "esi": UC_X86_REG_ESI,
        "edi": UC_X86_REG_EDI, "esp": UC_X86_REG_ESP}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def u32(x):
    return x & 0xffffffff


def s16(x):
    x &= 0xffff
    return x if x < 0x8000 else x - 0x10000


def run_case(body, receiver_day, receiver_year, argument_day, argument_year, global_high, seed):
    # JA is unsigned year comparison; equal-year day comparison is signed.
    need(argument_year < receiver_year or
         (argument_year == receiver_year and s16(argument_day) <= s16(receiver_day)),
         "case reaches recursive call")
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for base, size in ((0, 0x1000), (0x540000, 0x10000), (0x100000, 0x10000),
                       (RECEIVER, 0x1000), (OUTPUT, 0x1000), (0xae2000, 0x2000),
                       (STOP, 0x1000)):
        uc.mem_map(base, size)
    uc.mem_write(START, body)
    uc.mem_write(RECEIVER, struct.pack("<HHI", receiver_day & 0xffff, receiver_year & 0xffff, 0x67234512))
    uc.mem_write(OUTPUT, b"\xa5" * 8)
    uc.mem_write(GLOBAL, struct.pack("<II", 0x19720028, global_high))
    uc.mem_write(FLAG, b"\x01")
    uc.mem_write(0, struct.pack("<I", u32(0x61234567 ^ seed)))
    uc.mem_write(STACK, struct.pack("<IIHHI", STOP, OUTPUT, argument_day & 0xffff,
                                    argument_year & 0xffff, 0x89abcdef))
    initial = {"eax": u32(0x8a000000 ^ seed), "ebx": u32(0x9b000000 ^ seed),
               "ecx": RECEIVER, "edx": u32(0xac000000 ^ seed),
               "ebp": u32(0xbd000000 ^ seed), "esi": u32(0xce000000 ^ seed),
               "edi": u32(0xdf000000 ^ seed), "esp": STACK}
    for name, reg in REGS.items():
        uc.reg_write(reg, initial[name])
    uc.reg_write(UC_X86_REG_EIP, START)
    trace, reads, writes, events = [], [], [], []

    def code_hook(machine, address, size, data):
        if address == STOP:
            machine.emu_stop()
            return
        need(START <= address < START + LENGTH, "escaped original local body")
        trace.append(f"{address:08x}")
        need(len(trace) <= 120, "unexpected loop or call")

    def mem_read(machine, access, address, size, value, data):
        if address in (FLAG, RECEIVER, RECEIVER + 2, GLOBAL, GLOBAL + 4):
            reads.append([f"{address:08x}", size])
            events.append(["read", f"{address:08x}", size])
        elif not (0x100000 <= address < 0x110000 or address == 0):
            raise ValueError(f"unexpected read {address:08x}")

    def mem_write(machine, access, address, size, value, data):
        if address in (GLOBAL, GLOBAL + 2, OUTPUT, OUTPUT + 4):
            writes.append([f"{address:08x}", size, u32(value)])
            events.append(["write", f"{address:08x}", size, u32(value)])
        elif not (0x100000 <= address < 0x110000 or address == 0):
            raise ValueError(f"unexpected write {address:08x}")

    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.hook_add(UC_HOOK_MEM_READ, mem_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, mem_write)
    uc.emu_start(START, STOP + 1, count=125)
    need(uc.reg_read(UC_X86_REG_EIP) == STOP and trace[-1] == "0054cd93", "not RET12")
    final = {name: uc.reg_read(reg) for name, reg in REGS.items()}
    need(final["esp"] == STACK + 16 and final["eax"] == OUTPUT, "ABI result changed")
    need(all(final[n] == initial[n] for n in ("ebx", "ebp", "esi", "edi")), "callee-saved register changed")
    output = list(struct.unpack("<II", uc.mem_read(OUTPUT, 8)))
    global_pair = list(struct.unpack("<II", uc.mem_read(GLOBAL, 8)))
    need(output == global_pair, "output differs from global date pair")
    need(uc.mem_read(FLAG, 1) == b"\x01", "initialization path unexpectedly used")
    need(struct.unpack("<I", uc.mem_read(0, 4))[0] == u32(0x61234567 ^ seed), "FS chain not restored")
    return {"receiver_day": receiver_day & 0xffff, "receiver_year": receiver_year & 0xffff,
            "argument_day": argument_day & 0xffff, "argument_year": argument_year & 0xffff,
            "global_high": global_high, "seed": seed, "initial": initial, "final": final,
            "output": output, "global_pair": global_pair, "reads": reads, "writes": writes,
            "events": events,
            "trace": trace}


def oracle(args):
    need(unicorn.__version__ == "2.1.4", "requires Unicorn 2.1.4")
    sites = extract(args.binary, args.exports, args.preflight)
    need(sites["body_sha256"] == BODY_SHA, "original body changed")
    raw = args.binary.read_bytes()
    off = int(sites["file_offset"], 16)
    body = raw[off:off + LENGTH]
    # Explicit synthetic edge cases for equal-year, year-change, leap and century paths.
    same_days = [(0, 0), (10, 10), (20, 10), (32767, -32768), (-1, -2)]
    years = [0, 1, 2, 4, 100, 400, 1900, 1996, 2000, 2024, 65535]
    samples = [(d1, y, d2, y) for y in years for d1, d2 in same_days]
    samples += [(d1, y, d2, previous) for y, previous in
                ((1, 0), (2, 1), (4, 1), (100, 99), (400, 399), (1900, 1899),
                 (1996, 1995), (2000, 1999), (2024, 2023), (65535, 65534))
                for d1, d2 in ((1, 365), (365, 1), (-1, 1), (0, 0))]
    cases = [run_case(body, a, b, c, d, u32(0x12340000 ^ i * 0x10101), i + 1)
             for i, (a, b, c, d) in enumerate(samples)]
    starts = sorted({s for row in cases for s in row["trace"]})
    return {"work_unit": "R24-B",
            "scope": "synthetic initialized-flag, nonrecursive, mapped-disjoint entry-to-RET12 original x86 execution",
            "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": ARCHIVE,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "entry_va": f"{START:08x}", "body_sha256": BODY_SHA, "emulator": "Unicorn x86-32",
            "function_cases": len(cases), "executed_instruction_steps": sum(len(c["trace"]) for c in cases),
            "covered_instruction_starts": starts, "cases": cases}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = oracle(args)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")

#!/usr/bin/env python3
"""Execute call-free 0062c680 entry-to-RET4 paths from the pinned PE."""
import argparse
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                              UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_ESP,
                              UC_X86_REG_EIP)
from extract_status_refresh_24 import ARCHIVE, LENGTH, MANIFEST, PREFLIGHT, SPECIMEN, START, extract

STOP, STACK, PLAYER, RECEIVER, TABLE = 0x700000, 0x108000, 0x200000, 0x300000, 0x310000
FLAGS, COUNT, STAMP = 0xB63D10, 0xAE2364, 0xAE2C90
BODY_SHA = "10271964e0119f7a886c34ba8741174957ec555c822f8affa7f56acb3dab2fe6"
REGISTERS = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
             "edx": UC_X86_REG_EDX, "ebp": UC_X86_REG_EBP, "esi": UC_X86_REG_ESI,
             "edi": UC_X86_REG_EDI, "esp": UC_X86_REG_ESP}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def run_case(body, kind, index, count, seed):
    need(kind in ("null", "count", "slot-null", "cached"), "unknown case")
    need(kind != "count" or index >= count, "count case enters update")
    need(kind not in ("slot-null", "cached") or 0 <= index < count, "row case enters wrong branch")
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for base, size in ((0, 0x1000), (0x620000, 0x10000), (0x100000, 0x10000),
                       (PLAYER, 0x1000), (RECEIVER, 0x1000), (TABLE, 0x1000),
                       (0xAE2000, 0x2000), (0xB63000, 0x1000), (STOP, 0x1000)):
        uc.mem_map(base, size)
    uc.mem_write(START, body)
    uc.mem_write(FLAGS, b"\x07")
    uc.mem_write(COUNT, struct.pack("<i", count))
    uc.mem_write(STAMP, struct.pack("<II", 0x001A07EA, 0x12345678))
    uc.mem_write(PLAYER, struct.pack("<i", index))
    uc.mem_write(PLAYER+0x61, struct.pack("<I", 0 if kind == "slot-null" else 0x210000))
    uc.mem_write(RECEIVER, struct.pack("<III", TABLE, 0x320000, 2))
    uc.mem_write(TABLE+31*index, struct.pack("<II", 0x001A07EA, 0x12345678)) if index >= 0 else None
    pointer = 0 if kind == "null" else PLAYER
    uc.mem_write(STACK, struct.pack("<III", STOP, pointer, 0xC0DEC0DE))
    initial = {"eax": (0xA5500000 ^ seed) & 0xFFFFFFFF,
               "ebx": (0xB6700000 ^ seed) & 0xFFFFFFFF,
               "ecx": RECEIVER, "edx": (0xD6800000 ^ seed) & 0xFFFFFFFF,
               "ebp": (0xE7900000 ^ seed) & 0xFFFFFFFF,
               "esi": (0xF8A00000 ^ seed) & 0xFFFFFFFF,
               "edi": (0x12340000 ^ seed) & 0xFFFFFFFF, "esp": STACK}
    for name, reg in REGISTERS.items():
        uc.reg_write(reg, initial[name])
    uc.reg_write(UC_X86_REG_EIP, START)
    trace, reads, writes, frame_reads, frame_writes = [], [], [], [], []

    def code_hook(machine, address, size, data):
        if address == STOP:
            machine.emu_stop()
            return
        need(START <= address < START+LENGTH, "execution escaped local body or entered callee")
        trace.append(f"{address:08x}")
        need(len(trace) <= 100, "unexpected loop")

    def mem_hook(machine, access, address, size, value, data):
        if address == 0:
            (frame_reads if access == unicorn.UC_MEM_READ else frame_writes).append(
                [f"{address:08x}", size] if access == unicorn.UC_MEM_READ else
                [f"{address:08x}", size, value & 0xFFFFFFFF])
            return
        if 0x100000 <= address < 0x110000:
            return
        (reads if access == unicorn.UC_MEM_READ else writes).append([f"{address:08x}", size])

    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.hook_add(UC_HOOK_MEM_READ, mem_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, mem_hook)
    uc.emu_start(START, STOP+1, count=101)
    need(uc.reg_read(UC_X86_REG_EIP) == STOP and trace[-1] == "0062cdf2", "did not reach RET4")
    final = {name: uc.reg_read(reg) for name, reg in REGISTERS.items()}
    need(final["esp"] == STACK+8, "RET4 cleanup changed")
    need(all(final[name] == initial[name] for name in ("ebx", "ebp", "esi", "edi")),
         "nonvolatile register changed")
    need(writes == [], "call-free path wrote nonframe memory")
    need(frame_reads == [["00000000", 4]] and
         frame_writes == [["00000000", 4, STACK-12], ["00000000", 4, 0]] and
         uc.mem_read(0, 4) == b"\x00\x00\x00\x00", "SEH frame effects changed")
    return {"kind": kind, "index": index, "count": count, "seed": seed,
            "initial": initial, "final": final, "external_reads": reads,
            "external_writes": writes, "seh_reads": frame_reads,
            "seh_writes": frame_writes, "trace": trace}


def oracle(args):
    need(unicorn.__version__ == "2.1.4", "requires Unicorn 2.1.4")
    sites = extract(args.binary, args.exports, args.preflight)
    need(sites["body_sha256"] == BODY_SHA, "body SHA-256 changed")
    raw = args.binary.read_bytes()
    body = raw[int(sites["file_offset"], 16):int(sites["file_offset"], 16)+LENGTH]
    schedule = ([('null', 0, 100), ('null', 5, -1)] +
                [('count', i, c) for i, c in ((0, 0), (5, 5), (5, -1), (-1, -1), (100, 99))] +
                [('slot-null', i, 100) for i in (0, 1, 2)] +
                [('cached', i, 100) for i in (0, 1, 2)])
    cases = [run_case(body, kind, i, c, n+1) for n, (kind, i, c) in enumerate(schedule)]
    starts = sorted({site for case in cases for site in case["trace"]})
    return {"work_unit": "R24-A", "scope": "call-free guard and cached-stamp entry-to-RET4 paths",
            "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": ARCHIVE,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "entry_va": f"{START:08x}", "body_sha256": BODY_SHA,
            "emulator": "Unicorn x86-32", "function_cases": len(cases),
            "executed_instruction_steps": sum(len(case["trace"]) for case in cases),
            "covered_instruction_starts": starts,
            "domain": "synthetic mapped disjoint state; FS:[0] old value zero; initialization bits 0..2 pre-set; null/count/player+61-null/cached-stamp exits; no callees, asynchronous mutation, exception or unsafe index",
            "cases": cases}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    result = oracle(args)
    args.output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8", newline="\n")

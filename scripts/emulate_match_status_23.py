#!/usr/bin/env python3
"""Run the original 0062c400 instructions to RET4 on the no-callee count-guard path."""
import argparse
import json
from pathlib import Path
import struct

from extract_match_status_23 import ARCHIVE, LENGTH, MANIFEST, PREFLIGHT, SPECIMEN, START, extract
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_ESP, UC_X86_REG_EIP

STOP, STACK, POINTER, COUNT = 0x700000, 0x108000, 0x200000, 0xAE2364
BODY_SHA = "d46c16dcd2399b668c86134339f40e225a4575e09318fac4d09e2a0de236babc"
REGISTERS = {"eax": UC_X86_REG_EAX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
             "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI, "esp": UC_X86_REG_ESP}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def u32(value):
    return value & 0xFFFFFFFF


def signed(value):
    value = u32(value)
    return value if value < 0x80000000 else value - 0x100000000


def run_case(body, index, count, seed):
    need(signed(index) >= signed(count), "case reaches a callee")
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0x620000, 0x10000)
    uc.mem_write(START, body)
    uc.mem_map(0x100000, 0x10000)
    uc.mem_map(POINTER, 0x1000)
    uc.mem_map(0xAE2000, 0x2000)
    uc.mem_map(STOP, 0x1000)
    uc.mem_write(POINTER, struct.pack("<I", u32(index)))
    uc.mem_write(COUNT, struct.pack("<I", u32(count)))
    uc.mem_write(STACK, struct.pack("<III", STOP, POINTER, 0xC0DEC0DE))
    initial = {"eax": u32(0x9a5a1234 ^ seed), "ecx": u32(0xDE000000 ^ seed),
               "edx": u32(0x75ABC000 ^ seed), "esi": u32(0x12345000 ^ seed),
               "edi": u32(0x56789000 ^ seed), "esp": STACK}
    for name, reg in REGISTERS.items():
        uc.reg_write(reg, initial[name])
    uc.reg_write(UC_X86_REG_EIP, START)
    trace, external_reads, external_writes = [], [], []

    def code_hook(machine, address, size, data):
        if address == STOP:
            machine.emu_stop()
            return
        need(START <= address < START+LENGTH, "execution escaped local body")
        trace.append(address)
        need(len(trace) <= 30, "unexpected loop or call")

    def read_hook(machine, access, address, size, value, data):
        if address in (POINTER, COUNT):
            external_reads.append([f"{address:08x}", size])
        elif not 0x100000 <= address < 0x110000:
            raise ValueError("unexpected external read")

    def write_hook(machine, access, address, size, value, data):
        if not 0x100000 <= address < 0x110000:
            external_writes.append([f"{address:08x}", size])

    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.hook_add(UC_HOOK_MEM_READ, read_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    uc.emu_start(START, STOP+1, count=32)
    need(uc.reg_read(UC_X86_REG_EIP) == STOP and trace[-1] == 0x62C47B, "did not reach guard RET4")
    final = {name: uc.reg_read(reg) for name, reg in REGISTERS.items()}
    need(final["esp"] == STACK+8, "RET4 stack cleanup changed")
    need(final["esi"] == initial["esi"] and final["edi"] == initial["edi"] and
         final["edx"] == initial["edx"], "nonvolatile/EDX register change")
    need(external_reads == [[f"{POINTER:08x}", 4], [f"{COUNT:08x}", 4]], "external read sequence changed")
    need(external_writes == [], "unexpected external write")
    return {"index": u32(index), "count": u32(count), "seed": seed, "initial": initial,
            "final": final, "external_reads": external_reads, "external_writes": [],
            "trace": [f"{site:08x}" for site in trace]}


def oracle(args):
    need(unicorn.__version__ == "2.1.4", "requires Unicorn 2.1.4")
    sites = extract(args.binary, args.exports, args.preflight)
    need(sites["body_sha256"] == BODY_SHA, "body SHA-256 changed")
    raw = args.binary.read_bytes()
    body = raw[int(sites["file_offset"], 16):int(sites["file_offset"], 16)+LENGTH]
    counts = [-2147483648, -5, -1, 0, 1, 5, 100, 2147483647]
    indices = [-2147483648, -6, -5, -1, 0, 1, 5, 99, 100, 2147483647]
    pairs = [(i, c) for c in counts for i in indices if i >= c]
    cases = [run_case(body, i, c, n+1) for n, (i, c) in enumerate(pairs)]
    steps = sum(len(c["trace"]) for c in cases)
    starts = sorted({site for c in cases for site in c["trace"]})
    need(all((c["final"]["eax"] & 0xFF) == 0 for c in cases), "guard low-byte result changed")
    return {"work_unit": "R23-A", "scope": "synthetic no-callee signed count-guard path; complete entry-to-RET4 original execution",
            "specimen_sha256": SPECIMEN, "checkpoint_archive_sha256": ARCHIVE,
            "export_manifest_sha256": MANIFEST, "annotation_preflight_sha256": PREFLIGHT,
            "entry_va": f"{START:08x}", "body_sha256": BODY_SHA,
            "emulator": "Unicorn x86-32", "function_cases": len(cases),
            "executed_instruction_steps": steps, "covered_instruction_starts": starts,
            "domain": "non-null mapped pointer; signed *pointer >= signed count; disjoint stable memory; no callee, invalid pointer, alias or concurrent mutation",
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

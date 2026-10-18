#!/usr/bin/env python3
"""Original-instruction oracle for bounded no-callee 00601070 paths on synthetic memory."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ, UC_PROT_EXEC
from unicorn import x86_const as x
from extract_selection_probe_23 import extract, need

ENTRY, STOP = 0x00601070, 0x30000000
GLOBAL, RECEIVER, TABLE, RECORD, STACK = 0x00ae0000, 0x10000000, 0x11000000, 0x12000000, 0x20000000
SP, TABLE_BASE = STACK + 0x800, TABLE + 0x20000
BRANCHES = {0x00601080, 0x00601097, 0x006010d9, 0x006010e5, 0x006010f4,
            0x006010f9, 0x0060111b, 0x00601143}
CALLEES = {0x006010ad, 0x0060117a, 0x006011aa, 0x006011c4, 0x006011d4, 0x006011e4}


def s8(n):
    return n if n < 128 else n - 256


def cases():
    out = []
    for pointer_mode in ("direct", "fallback"):
        for slot in (0, 1, 3):
            for status in (0, 1, 2, 255):
                for field in (0, 1, 49):
                    for record_id in (-1, 0, 5, 65535):
                        out.append(dict(pointer_mode=pointer_mode, slot=slot, status=status,
                                        field=field, record_id=record_id))
    return out


def pack32(v):
    return struct.pack("<I", v & 0xffffffff)


def generate(binary_path, exports, preflight):
    need(unicorn.__version__ == "2.1.4", "requires Unicorn 2.1.4")
    static = extract(binary_path, exports, preflight)
    image = binary_path.read_bytes()
    pos = int(static["file_offset"], 16)
    body = image[pos:pos + static["body_bytes"]]
    need(hashlib.sha256(body).hexdigest() == static["body_sha256"], "body changed after verification")
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(ENTRY & ~4095, 4096)
    uc.mem_write(ENTRY, body)
    uc.mem_protect(ENTRY & ~4095, 4096, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(GLOBAL, 0x100000)
    uc.mem_map(RECEIVER, 4096)
    uc.mem_map(TABLE, 0x100000)
    uc.mem_map(RECORD, 4096)
    uc.mem_map(STACK, 4096)
    trace, reads, writes = [], [], []
    uc.hook_add(UC_HOOK_CODE, lambda u, address, size, _: trace.append(address))
    uc.hook_add(UC_HOOK_MEM_READ, lambda u, access, address, size, value, _: reads.append([address, size]))
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, access, address, size, value, _: writes.append([address, size, value & ((1 << (size * 8)) - 1)]))
    rows, seen = [], set()
    for case in cases():
        slot, status, field, record_id = (case[k] for k in ("slot", "status", "field", "record_id"))
        uc.mem_write(GLOBAL, bytes(0x100000))
        uc.mem_write(RECEIVER, bytes(4096))
        uc.mem_write(TABLE, bytes(0x100000))
        uc.mem_write(RECORD, bytes(4096))
        uc.mem_write(STACK, bytes(4096))
        global_base = 0x12000100
        output_base = 0x13000000
        uc.mem_write(0x00ae2364, pack32(global_base))
        uc.mem_write(0x00ae23bc, pack32(output_base))
        uc.mem_write(0x00b77c7a, struct.pack("<H", 1))
        uc.mem_write(0x00b74c26 + 0x300, pack32(RECORD))
        uc.mem_write(RECORD, pack32(global_base - 16 + slot))
        uc.mem_write(RECEIVER, pack32(TABLE_BASE) + pack32(4))
        uc.mem_write(TABLE_BASE + slot * 0xa6ef + 0x9a69, bytes([status]))
        lookup = TABLE_BASE + slot * 0xa6ef + 0x1e05 + (0 if status == 1 else s8(status)) * 0x1ecd + field * 4
        uc.mem_write(lookup, pack32(record_id))
        arg_pointer = RECORD if case["pointer_mode"] == "direct" else 0
        uc.mem_write(SP, pack32(STOP) + pack32(field) + pack32(arg_pointer))
        original = {x.UC_X86_REG_EBX: 0x11223344, x.UC_X86_REG_ESI: 0x55667788,
                    x.UC_X86_REG_EBP: 0x33445566, x.UC_X86_REG_EDI: 0x778899aa}
        for reg, val in original.items():
            uc.reg_write(reg, val)
        uc.reg_write(x.UC_X86_REG_ECX, RECEIVER)
        uc.reg_write(x.UC_X86_REG_EAX, 0xdeadbeef)
        uc.reg_write(x.UC_X86_REG_EDX, 0xa5a5a5a5)
        uc.reg_write(x.UC_X86_REG_ESP, SP)
        uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
        trace.clear(); reads.clear(); writes.clear()
        uc.emu_start(ENTRY, STOP, count=200)
        need(uc.reg_read(x.UC_X86_REG_EIP) == STOP and uc.reg_read(x.UC_X86_REG_ESP) == SP + 12,
             "RET8/sentinel mismatch")
        need(all(uc.reg_read(reg) == val for reg, val in original.items()), "callee-save register mismatch")
        need(not any(a in CALLEES for a in trace), "case reached unresolved callee")
        need(not [w for w in writes if not STACK <= w[0] < STACK + 4096], "nonstack write")
        data_reads = [r for r in reads if not STACK <= r[0] < STACK + 4096]
        expected = []
        if not arg_pointer:
            expected.extend([[0x00b77c7a, 2], [0x00b74c26 + 0x300, 4]])
        expected.extend([[RECORD, 4], [0x00ae2364, 4], [RECEIVER + 4, 4], [RECEIVER, 4],
                         [TABLE_BASE + slot * 0xa6ef + 0x9a69, 1], [lookup, 4]])
        if record_id != -1:
            expected.append([0x00ae23bc, 4])
        need(data_reads == expected, "ordered nonstack reads mismatch: " + repr((case, data_reads, expected)))
        branch_schedule = [[a, trace[n + 1]] for n, a in enumerate(trace[:-1]) if a in BRANCHES]
        seen.update(trace)
        rows.append({**case, "eax": uc.reg_read(x.UC_X86_REG_EAX), "ecx": uc.reg_read(x.UC_X86_REG_ECX),
                     "edx": uc.reg_read(x.UC_X86_REG_EDX), "instruction_steps": len(trace),
                     "branch_schedule": branch_schedule, "ordered_data_reads": data_reads})
    need({0x00601163, 0x006011fc} <= seen, "both original RET paths not covered")
    return {"work_unit": "R23-C", "specimen_sha256": static["specimen_sha256"],
            "export_manifest_sha256": static["export_manifest_sha256"],
            "annotation_preflight_sha256": static["annotation_preflight_sha256"],
            "entry_va": static["entry_va"], "body_sha256": static["body_sha256"],
            "scope": "bounded no-callee whole-function executions, direct and fallback pointers, mapped synthetic memory",
            "fixture": {"record_pointer": RECORD, "receiver": RECEIVER, "table_base": TABLE_BASE,
                        "global_base": 0x12000100, "output_base": 0x13000000,
                        "fallback_slot": 1, "receiver_count": 4},
            "unicorn_version": unicorn.__version__, "python_version": platform.python_version(),
            "case_count": len(rows), "instruction_starts_seen": len(seen),
            "branch_sites_seen": len(seen & BRANCHES),
            "executed_instruction_steps": sum(r["instruction_steps"] for r in rows),
            "cases": rows}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary", type=Path)
    p.add_argument("--exports", type=Path, required=True)
    p.add_argument("--preflight", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = generate(a.binary, a.exports, a.preflight)
    a.output.write_text(json.dumps(result, separators=(",", ":")) + "\n", encoding="utf-8", newline="\n")

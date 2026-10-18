#!/usr/bin/env python3
"""Execute R25-C nonzero-mode original instructions on synthetic memory."""
import argparse
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_EXEC, UC_PROT_READ
from unicorn import x86_const as x

from extract_copy_helper_25 import extract, need, sha, ENTRY, SIZE

SRC, DST, GLOBAL, STACK, STOP = 0x200000, 0x210000, 0xde4000, 0x10000000, 0x30000000
SOURCE, DEST, SP = SRC+0xf00, DST+0xf00, STACK+0x800
SAVED = {"ebx": x.UC_X86_REG_EBX, "ebp": x.UC_X86_REG_EBP,
         "esi": x.UC_X86_REG_ESI, "edi": x.UC_X86_REG_EDI}
REGS = {"eax": x.UC_X86_REG_EAX, "ecx": x.UC_X86_REG_ECX,
        "edx": x.UC_X86_REG_EDX, "esp": x.UC_X86_REG_ESP}


def samples():
    patterns = [
        [0], [65, 66, 0], [0x81, 66, 67, 0], [65, 0x81, 66, 67, 0],
        [0x81, 0], [65, 0x81, 0], [0xe0, 0x81, 66, 0],
        [65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 0],
        [0x81, 0x81, 0xe0, 66, 0], [0xe0, 0],
    ]
    return [(n, pattern, index) for index, pattern in enumerate(patterns)
            for n in range(18)]


def generate(binary, exports, preflight, output):
    need(unicorn.__version__ == "2.1.4", "requires Unicorn 2.1.4")
    static = extract(binary, exports, preflight)
    raw = binary.read_bytes()
    off = int(static["file_offset"], 16)
    body = raw[off:off+SIZE]
    need(sha(body) == static["body_sha256"], "PE body changed")
    instruction_starts = {int(line.split()[0], 16) for line in
                          (exports/"00948851.asm").read_text().splitlines()}
    need(len(instruction_starts) == static["instruction_count"], "instruction-start inventory")
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(ENTRY & ~4095, 4096)
    uc.mem_write(ENTRY, body)
    uc.mem_protect(ENTRY & ~4095, 4096, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(SRC, 4096)
    uc.mem_map(DST, 4096)
    uc.mem_map(GLOBAL, 4096)
    uc.mem_map(STACK, 4096)
    uc.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
    logs = {"trace": [], "events": []}

    def on_code(machine, address, size, user):
        need(address in instruction_starts and address != 0x94886b,
             "execution escaped call-free complete local body")
        logs["trace"].append(f"{address:08x}")

    def on_read(machine, access, address, size, value, user):
        if SOURCE <= address < SOURCE+32:
            need(size == 1, "unexpected source read width")
            logs["events"].append(["source", address-SOURCE, size,
                                   machine.mem_read(address, size)[0]])
        elif 0xde4521 <= address < 0xde4521+256:
            need(size == 1, "unexpected locale-table read width")
            logs["events"].append(["table", address-0xde4521, size,
                                   machine.mem_read(address, size)[0]])
        elif address == 0xde441c:
            need(size == 4, "unexpected mode read width")
        else:
            need(STACK <= address < STACK+4096 or DEST <= address < DEST+32,
                 f"unexpected read {address:08x}")

    def on_write(machine, access, address, size, value, user):
        if DEST <= address and address+size <= DEST+32:
            logs["events"].append(["dest", address-DEST, size,
                                   value & ((1 << (size*8))-1)])
        else:
            need(STACK <= address and address+size <= STACK+4096,
                 f"unexpected write {address:08x}")

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ, on_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    cases, covered, steps = [], set(), 0
    for n, (count, pattern, pattern_id) in enumerate(samples()):
        src = bytearray(((i*13+n*17+0x5a) & 255) for i in range(32))
        src[:len(pattern)] = bytes(pattern)
        dest = bytearray(((i*23+n*7+0xa5) & 255) for i in range(32))
        table = bytearray(256)
        table[0x81] = 4
        table[0xe0] = 0x84
        uc.mem_write(SOURCE, bytes(src))
        uc.mem_write(DEST, bytes(dest))
        uc.mem_write(0xde441c, struct.pack("<I", 1))
        uc.mem_write(0xde4521, bytes(table))
        uc.mem_write(SP, struct.pack("<IIII", STOP, DEST, SOURCE, count))
        initial = {"eax": (0xa1200000+n)&0xffffffff,
                   "ecx": (0xb2300000+n)&0xffffffff,
                   "edx": (0xc3400000+n)&0xffffffff,
                   "esp": SP,
                   "ebx": (0xd4500000+n)&0xffffffff,
                   "ebp": (0xe5600000+n)&0xffffffff,
                   "esi": (0xf6700000+n)&0xffffffff,
                   "edi": (0x17800000+n)&0xffffffff}
        for name, register in (REGS | SAVED).items():
            uc.reg_write(register, initial[name])
        uc.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
        for log in logs.values():
            log.clear()
        uc.emu_start(ENTRY, STOP, count=400)
        final = {name: uc.reg_read(register) for name, register in (REGS | SAVED).items()}
        need(uc.reg_read(x.UC_X86_REG_EIP) == STOP and final["eax"] == DEST and
             final["esp"] == SP+4, "return ABI mismatch")
        need(all(final[k] == initial[k] for k in SAVED), "callee-saved register changed")
        need(logs["trace"] and logs["trace"][0] == "00948851" and
             logs["trace"][-1] == "009488da", "entry-to-return trace mismatch")
        before, after = bytes(dest), bytes(uc.mem_read(DEST, 32))
        replay = bytearray(before)
        for kind, offset, size, value in logs["events"]:
            if kind == "dest":
                replay[offset:offset+size] = value.to_bytes(size, "little")
        need(bytes(replay) == after, "unlogged destination mutation")
        covered.update(logs["trace"])
        steps += len(logs["trace"])
        cases.append({"case": n, "pattern": pattern_id, "count": count,
                      "source": list(src), "dest_before": list(before),
                      "dest_after": list(after), "table_flags": [0x81, 0xe0],
                      "initial": initial, "final": final,
                      "events": list(logs["events"]), "trace": list(logs["trace"])})
    need(any("009488b0" in row["trace"] for row in cases) and
         any("009488b6" in row["trace"] for row in cases) and
         any("009488cc" in row["trace"] for row in cases) and
         any("009488d3" in row["trace"] for row in cases),
         "truncation and padding path coverage missing")
    result = {"schema_version": 1, "unit": "R25-C", "entry_va": "00948851",
              "specimen_sha256": static["specimen_sha256"],
              "checkpoint_archive_sha256": static["checkpoint_archive_sha256"],
              "export_manifest_sha256": static["export_manifest_sha256"],
              "annotation_preflight_sha256": static["annotation_preflight_sha256"],
              "body_sha256": static["body_sha256"],
              "mode": "nonzero synthetic locale mode; original entry-to-RET instructions",
              "mode_zero_callee_executed": False,
              "cases_count": len(cases), "executed_instruction_steps": steps,
              "covered_instruction_starts": sorted(covered), "cases": cases,
              "limits": ["Synthetic disjoint mapped buffers; DF clear; valid pointers",
                         "Mode-zero _strncpy callee and locale initialization excluded",
                         "No caller or general path-library equivalence"]}
    need(not output.exists(), "output must be a new file")
    output.write_text(json.dumps(result, separators=(",", ":"))+"\n",
                      encoding="utf-8", newline="\n")
    print(json.dumps({"cases": len(cases), "steps": steps,
                      "covered_instruction_starts": len(covered), "oracle_sha256": sha(output.read_bytes())}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/copy-helper-25-oracle.json"))
    args = parser.parse_args()
    generate(args.binary, args.exports, args.preflight, args.output)

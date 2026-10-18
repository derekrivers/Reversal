#!/usr/bin/env python3
"""Original-entry slot-effect oracle for kind=-1, severity>50, low result."""
import argparse
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_ESP, UC_X86_REG_EIP)

from extract_slot_effect_25 import extract, SPECIMEN, ARCHIVE, MANIFEST, PREFLIGHT, START, LENGTH

BODY_SHA = "8a618f5a01c2e2a0796c5a564d642b7ff40618d07fa814ba9be4934353d2f74b"
STOP, STACK, MATCH, TARGET, OTHER = 0x700000, 0x108000, 0x300000, 0x400000, 0x410000
REGS = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
        "edx": UC_X86_REG_EDX, "ebp": UC_X86_REG_EBP, "esi": UC_X86_REG_ESI,
        "edi": UC_X86_REG_EDI, "esp": UC_X86_REG_ESP}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def s16(x):
    return x if x < 0x8000 else x-0x10000


def run_case(body, constants, counter, latch, severity, initial_float, other_present, other_word, seed):
    need(-3 <= counter <= 3 and latch in (0, 1) and 51 <= severity <= 127,
         "case escapes no-callee admitted path")
    need(initial_float-severity*severity < 5000, "case may use external setter")
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for base, size in ((0x6d0000, 0x10000), (0x100000, 0x10000),
                       (MATCH, 0x10000), (TARGET, 0x1000), (OTHER, 0x1000),
                       (0x960000, 0x10000), (STOP, 0x1000)):
        uc.mem_map(base, size)
    uc.mem_write(START, body)
    uc.mem_write(0x960000, constants)
    uc.mem_write(MATCH+0xf639, struct.pack('<h', counter))
    uc.mem_write(MATCH+0x8eb5, bytes([latch]))
    uc.mem_write(TARGET+0x4d, struct.pack('<f', float(initial_float)))
    uc.mem_write(TARGET+0x1c, b'\x00')
    uc.mem_write(TARGET+0x1d, b'\x00')
    uc.mem_write(TARGET+0x55, struct.pack('<I', 0xdeadbeef))
    uc.mem_write(OTHER+0x31, struct.pack('<h', other_word))
    other = OTHER if other_present else 0
    uc.mem_write(STACK, struct.pack('<IIIIII', STOP, 0xffffffff, severity, TARGET, other, 0xa55aa55a))
    initial = {"eax": (0x11000000 ^ seed), "ebx": (0x22000000 ^ seed),
               "ecx": MATCH, "edx": (0x33000000 ^ seed), "ebp": (0x44000000 ^ seed),
               "esi": (0x55000000 ^ seed), "edi": (0x66000000 ^ seed), "esp": STACK}
    for name, reg in REGS.items():
        uc.reg_write(reg, initial[name])
    uc.reg_write(UC_X86_REG_EIP, START)
    trace, writes = [], []

    def code_hook(machine, address, size, data):
        if address == STOP:
            machine.emu_stop()
            return
        need(START <= address < START+LENGTH, "unexpected external call or body escape")
        trace.append(f'{address:08x}')
        need(len(trace) <= 150, "unexpected loop")

    def write_hook(machine, access, address, size, value, data):
        if MATCH <= address < MATCH+0x10000:
            obj, off = 'match', address-MATCH
        elif TARGET <= address < TARGET+0x1000:
            obj, off = 'target', address-TARGET
        elif OTHER <= address < OTHER+0x1000:
            obj, off = 'other', address-OTHER
        else:
            need(0x100000 <= address < 0x110000, f'unexpected write {address:08x}')
            return
        writes.append([obj, off, size, value & ((1 << (size*8))-1)])

    uc.hook_add(UC_HOOK_CODE, code_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
    uc.emu_start(START, STOP+1, count=155)
    need(uc.reg_read(UC_X86_REG_EIP) == STOP and trace[-1] == '006d0b56', 'not local RET16')
    final = {name: uc.reg_read(reg) for name, reg in REGS.items()}
    need(final['esp'] == STACK+20, 'RET16 stack cleanup changed')
    need(all(final[n] == initial[n] for n in ('ebx', 'ebp', 'esi', 'edi')), 'callee-saved register changed')
    need(all(not (0x006d0a28 <= int(x,16) <= 0x006d0a8b) for x in trace), 'severity<=50 path entered')
    need('006d09ed' not in trace and '006d0ada' not in trace and '006d0ae5' not in trace,
         'external callee entered')
    result = {"match_counter": s16(struct.unpack('<H', uc.mem_read(MATCH+0xf639,2))[0]),
              "match_latch": uc.mem_read(MATCH+0x8eb5,1)[0],
              "target_float_bits": struct.unpack('<I', uc.mem_read(TARGET+0x4d,4))[0],
              "target_flag_1c": uc.mem_read(TARGET+0x1c,1)[0],
              "target_flag_1d": uc.mem_read(TARGET+0x1d,1)[0],
              "target_other": struct.unpack('<I', uc.mem_read(TARGET+0x55,4))[0],
              "other_word": s16(struct.unpack('<H', uc.mem_read(OTHER+0x31,2))[0])}
    return {"counter":counter,"latch":latch,"severity":severity,"initial_float":initial_float,
            "other_present":other_present,"other_word":other_word,"seed":seed,"initial":initial,
            "final":final,"result":result,"writes":writes,"trace":trace}


def oracle(args):
    need(unicorn.__version__ == '2.1.4', 'requires Unicorn 2.1.4')
    sites = extract(args.binary,args.exports,args.preflight)
    need(sites['body_sha256'] == BODY_SHA and sites['file_offset'] == '0x2d0980', 'original body changed')
    raw = args.binary.read_bytes()
    body = raw[0x2d0980:0x2d0980+LENGTH]
    constants = raw[0x560000:0x570000]
    need(struct.unpack_from('<d',constants,0x88e8)[0] == 5000.0
         and struct.unpack_from('<d',constants,0x7890)[0] == 1.0
         and struct.unpack_from('<d',constants,0x8910)[0] == 10000.0,
         'original floating constants changed')
    cases = []
    for counter in (-3,0,3):
        for latch in (0,1):
            for severity in (51,75,127):
                for initial_float in (1,500,4000,6000):
                    for other_present in (False,True):
                        cases.append(run_case(body,constants,counter,latch,severity,initial_float,
                                              other_present,-32760 if other_present else 17,len(cases)+1))
    starts = sorted({x for c in cases for x in c['trace']})
    return {"work_unit":"R25-B","scope":"synthetic kind=-1, severity>50, result<5000, counter<=3 no-callee entry-to-RET16",
            "specimen_sha256":SPECIMEN,"checkpoint_archive_sha256":ARCHIVE,
            "export_manifest_sha256":MANIFEST,"annotation_preflight_sha256":PREFLIGHT,
            "entry_va":f'{START:08x}',"body_sha256":BODY_SHA,"function_cases":len(cases),
            "executed_instruction_steps":sum(len(c['trace']) for c in cases),
            "covered_instruction_starts":starts,"cases":cases}


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path)
    p.add_argument('--exports',type=Path,required=True)
    p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    a.output.write_text(json.dumps(oracle(a),indent=2)+'\n',encoding='utf-8',newline='\n')

#!/usr/bin/env python3
"""Execute the complete original 0062c3d0 body on synthetic mapped memory."""
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
from extract_match_scalar_22 import extract, need

ENTRY, STOP = 0x0062c3d0, 0x30000000
GLOBAL, RECEIVER, TABLE, STACK = 0x00ae2000, 0x10000000, 0x11000000, 0x20000000
SP = STACK+0x800
STARTS = [0x62c3d0,0x62c3d4,0x62c3da,0x62c3dc,0x62c3de,0x62c3e0,0x62c3e3,0x62c3e5,0x62c3e8,0x62c3ea,0x62c3ec,0x62c3f1]


def rows():
    result = []
    for count in [-5, 0, 1, 5, 20, 100]:
        for index in range(-20, 25):
            result.append([index & 0xffffffff, count & 0xffffffff, len(result)])
    for index in (0x7fffffff, 0xffffffff, 0x100, 0xffff):
        result.append([index, 20, len(result)])
    return result


def field(index, seed):
    return (index*13037 + seed*577 + 0x8135) & 0xffff


def fixture(index, count, seed):
    table = bytearray((i*13 + seed*7 + 83) & 255 for i in range(4096))
    for signed_index in range(-20, 25):
        start = 0x800 + signed_index*31 + 12
        table[start:start+2] = struct.pack('<H', field(signed_index, seed))
    return bytes(table)


def generate(binary_path, exports, preflight):
    need(unicorn.__version__ == '2.1.4', 'requires Unicorn 2.1.4')
    static = extract(binary_path, exports, preflight)
    source = binary_path.read_bytes()
    fn = static['functions'][0]
    pos = int(fn['file_offset'], 16)
    body = source[pos:pos+fn['body_bytes']]
    need(hashlib.sha256(body).hexdigest() == fn['body_sha256'], 'body changed after validation')
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(ENTRY & ~4095, 4096)
    uc.mem_write(ENTRY, body)
    uc.mem_protect(ENTRY & ~4095, 4096, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(STOP, 4096, UC_PROT_READ | UC_PROT_EXEC)
    for base in (GLOBAL, RECEIVER, TABLE, STACK):
        uc.mem_map(base, 4096)
    trace, reads, writes = [], [], []
    uc.hook_add(UC_HOOK_CODE, lambda u, address, size, _: trace.append(address))
    uc.hook_add(UC_HOOK_MEM_READ, lambda u, access, address, size, value, _: reads.append([address,size]))
    uc.hook_add(UC_HOOK_MEM_WRITE, lambda u, access, address, size, value, _: writes.append([address,size,value]))
    results = []
    all_seen = set()
    for index, count, seed in rows():
        uc.mem_write(GLOBAL, bytes(4096))
        uc.mem_write(RECEIVER, bytes(4096))
        uc.mem_write(TABLE, fixture(index,count,seed))
        uc.mem_write(STACK, bytes(4096))
        uc.mem_write(0x00ae2364, struct.pack('<I',count))
        table_pointer = TABLE+0x800
        uc.mem_write(RECEIVER+0x20, struct.pack('<I',table_pointer))
        uc.mem_write(SP, struct.pack('<II',STOP,index))
        initial = {x.UC_X86_REG_EAX:(0x11330000+seed)&0xffffffff,
                   x.UC_X86_REG_EDX:(0x22440000+seed*3)&0xffffffff,
                   x.UC_X86_REG_EBX:0x33445566, x.UC_X86_REG_EBP:0x44556677,
                   x.UC_X86_REG_ESI:0x55667788, x.UC_X86_REG_EDI:0x66778899}
        for reg,value in initial.items():
            uc.reg_write(reg,value)
        uc.reg_write(x.UC_X86_REG_ECX, RECEIVER+0x20)
        uc.reg_write(x.UC_X86_REG_ESP,SP)
        uc.reg_write(x.UC_X86_REG_EFLAGS,0x202)
        trace.clear(); reads.clear(); writes.clear()
        uc.emu_start(ENTRY,STOP,count=20)
        need(uc.reg_read(x.UC_X86_REG_EIP) == STOP, 'failed to return to sentinel')
        need(uc.reg_read(x.UC_X86_REG_ESP) == SP+8, 'RET4 stack effect mismatch')
        need(uc.reg_read(x.UC_X86_REG_ECX) == RECEIVER+0x20, 'ECX changed')
        need(all(uc.reg_read(reg) == value for reg,value in initial.items() if reg not in (x.UC_X86_REG_EAX,x.UC_X86_REG_EDX)), 'nonvolatile register changed')
        need(set(trace) <= set(STARTS) and trace[-1] in (0x62c3e0,0x62c3f1), 'trace escaped body')
        need(not writes, 'query unexpectedly wrote memory')
        signed_index = index if index < 0x80000000 else index-0x100000000
        signed_count = count if count < 0x80000000 else count-0x100000000
        expected_reads = [[SP+4,4],[0x00ae2364,4]]
        if signed_index < signed_count:
            expected_reads += [[RECEIVER+0x20,4],[(table_pointer+signed_index*31+12)&0xffffffff,2]]
        expected_reads.append([SP,4])
        need(reads == expected_reads, 'ordered memory reads mismatch: '+repr((reads,expected_reads)))
        all_seen.update(trace)
        results.append({'index':index,'count':count,'seed':seed,
                        'eax':uc.reg_read(x.UC_X86_REG_EAX), 'edx':uc.reg_read(x.UC_X86_REG_EDX),
                        'instruction_steps':len(trace), 'ordered_reads':[item.copy() for item in reads]})
    need(all_seen == set(STARTS), 'not every original instruction observed')
    return {'work_unit':'R22-A','specimen_sha256':static['specimen_sha256'],
            'export_manifest_sha256':static['export_manifest_sha256'],
            'annotation_preflight_sha256':static['annotation_preflight_sha256'],
            'checkpoint_archive_sha256':static['checkpoint_archive_sha256'],
            'python_version':platform.python_version(),'unicorn_version':unicorn.__version__,
            'entry_va':'0062c3d0','file_offset':fn['file_offset'],'body_sha256':fn['body_sha256'],
            'fixture':'synthetic mapped receiver/global/table/stack; negative indices -20..-1 are mapped',
            'cases':results,'case_count':len(results),'executed_instruction_steps':sum(r['instruction_steps'] for r in results),
            'instruction_starts_seen':len(all_seen),'native_memory_writes':0,
            'limits':['EFLAGS not compared by TypeScript','fault and alias behavior excluded','no connected match claim']}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path); p.add_argument('--exports',type=Path,required=True)
    p.add_argument('--preflight',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result=generate(a.binary,a.exports,a.preflight)
    a.output.write_text(json.dumps(result, separators=(',',':'))+'\n',encoding='utf-8',newline='\n')

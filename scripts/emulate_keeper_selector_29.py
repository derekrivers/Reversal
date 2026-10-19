#!/usr/bin/env python3
"""Original-entry R29-A oracle over bounded synthetic match and tactical state."""
import argparse
import gzip
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,
 UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)
from extract_keeper_selector_29 import extract,need,sha,SPECIMEN,MANIFEST,PREFLIGHT,CHECKPOINT,ENTRY,SIZE

MATCH, TABLE, STACK, STOP = 0x200000,0x300000,0x100800,0x700000
REGIONS=((MATCH,0x10000),(TABLE,0x1000))
REGS=dict(zip(('eax','ebx','ecx','edx','esi','edi','ebp','esp'),
 (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP)))
BASES=(0x4796,0x6a6e)
CACHES=(0xf59e,0xf5a2)
STRIDE=0x1be

def make_memory(modes):
    match=bytearray(0x10000);table=bytearray(0x1000)
    def w32(a,v):struct.pack_into('<I',match,a,v&0xffffffff)
    for side,mode in enumerate(modes):
        base=BASES[side]
        for i in range(20):
            slot=base+i*STRIDE
            match[slot+0x19]=match[slot+0x1a]=0xff
            match[slot+0x27]=side
        w32(0x8ebc+4*side,TABLE+side*0x100)
        def slot(i):return base+i*STRIDE
        def status(i,v):match[slot(i)+0x19]=v&255
        def tact(index,value,which=0):struct.pack_into('<H',table,side*0x100+which*0x40+index*2,value)
        if mode==0:
            status(2,2);w32(CACHES[side],MATCH+slot(2))
        elif mode==1:
            status(3,1);w32(CACHES[side],MATCH+slot(2));tact(1,1)
        elif mode==2:
            status(2,3);status(5,1);tact(1,1)
        elif mode==3:
            status(5,2)
        elif mode in (4,5):
            status(5,2);status(12,0xfe);match[slot(12)+0x1a]=3
            match[slot(12)+0x20]=0xff
            match[slot(12)+0x27]=side+2
            w32(0x8ebc+4*(side+2),TABLE+side*0x100+0x40)
            tact(3,1,1)
            if mode==4:tact(3,1)
        elif mode==6:
            pass
        elif mode==7:
            status(1,11);w32(CACHES[side],MATCH+slot(1))
        elif mode==8:
            status(1,0);status(3,1);tact(0,1);tact(1,1)
        elif mode==9:
            w32(CACHES[side],MATCH+slot(2))
        elif mode==10:
            status(5,11)
        elif mode in (11,12,13,14):
            status(5,2);status(12,0xfd if mode==13 else 0xfe)
            match[slot(12)+0x1a]=11 if mode==11 else 3
            match[slot(12)+0x20]=0 if mode==14 else 0xff
            match[slot(12)+0x27]=side+2
            w32(0x8ebc+4*(side+2),TABLE+side*0x100+0x40)
            if mode!=12:tact(3,1,1)
        else:raise ValueError('unknown mode')
    return match,table

def run_case(body,left,right,selector):
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    for address,size in ((0x6ce000,0x1000),(0x100000,0x1000),(STOP,0x1000),*REGIONS):uc.mem_map(address,size)
    uc.mem_write(ENTRY,body)
    match,table=make_memory((left,right))
    uc.mem_write(MATCH,bytes(match));uc.mem_write(TABLE,bytes(table))
    uc.mem_write(STACK,struct.pack('<III',STOP,selector,0xc0dec0de))
    initial={name:(0x12340000+left*0x1000+right*0x100+selector*0x10+k*0x101)&0xffffffff
             for k,name in enumerate(REGS)}
    initial.update(ecx=MATCH,esp=STACK)
    for name,r in REGS.items():uc.reg_write(r,initial[name])
    trace=[];effects=[]
    def code(m,a,size,data):
        need(ENTRY<=a<ENTRY+SIZE,'execution escaped body')
        trace.append(f'{a:08x}')
        need(len(trace)<3000,'step budget exceeded')
    def read(m,access,a,size,value,data):
        if MATCH<=a<MATCH+0x10000 or TABLE<=a<TABLE+0x1000:
            effects.append(['read',f'{a:08x}',size])
    def write(m,access,a,size,value,data):
        if MATCH<=a<MATCH+0x10000 or TABLE<=a<TABLE+0x1000:
            effects.append(['write',f'{a:08x}',size,value&((1<<(8*size))-1)])
    uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(ENTRY,STOP,count=3000)
    need(uc.reg_read(UC_X86_REG_EIP)==STOP,'did not return')
    final={name:uc.reg_read(r) for name,r in REGS.items()}
    need(final['esp']==STACK+8 and final['ecx']==MATCH and
         all(final[n]==initial[n] for n in ('ebx','ebp','esi','edi')),'ABI mismatch')
    return {'input':[left,right,selector],'initial':initial,'final':final,'trace':trace,
            'effects':effects,'memory_sha256':[sha(bytes(uc.mem_read(a,s))) for a,s in (*REGIONS,(0x100000,0x1000))]}

def oracle(args):
    need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    sites=extract(args.binary,args.exports,args.preflight)
    need(sites['entry_va']=='006ce110' and sites['body_bytes']==SIZE,'body metadata mismatch')
    pe=args.binary.read_bytes();off=int(sites['file_offset'],16);body=pe[off:off+SIZE]
    schedule=[(a,b,s) for a in range(10) for b in range(10) for s in (0,1,2)]
    schedule += [(m,m,s) for m in range(10,15) for s in (0,1,2)]
    rows=[run_case(body,a,b,s) for a,b,s in schedule]
    return {'schema_version':1,'unit':'R29-A','entry_va':'006ce110','specimen_sha256':SPECIMEN,
            'checkpoint_archive_sha256':CHECKPOINT,'export_manifest_sha256':MANIFEST,
            'annotation_preflight_sha256':PREFLIGHT,'body_sha256':sites['body_sha256'],
            'emulator':'Unicorn 2.1.4 x86-32','scope':'synthetic disjoint stable match and tactical tables; original entry to RET4',
            'function_cases':len(rows),'executed_instruction_steps':sum(len(r['trace']) for r in rows),
            'covered_instruction_starts':sorted({a for r in rows for a in r['trace']}),
            'covered_local_edges':sorted({tuple(pair) for r in rows for pair in zip(r['trace'],r['trace'][1:])}),
            'cases':rows}

def normalize_gzip_header(packed):
    """Normalize gzip's OS byte: Python/zlib emit FF, 03 or 0A by platform."""
    need(packed[:9]==bytes.fromhex('1f8b08000000000002') and len(packed)>=18,
         'unexpected deterministic gzip header')
    return packed[:9]+b'\xff'+packed[10:]

def canonical_gzip(payload):
    packed=normalize_gzip_header(gzip.compress(payload,compresslevel=9,mtime=0))
    need(gzip.decompress(packed)==payload,'canonical gzip round trip failed')
    return packed

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path)
    p.add_argument('--exports',type=Path,required=True);p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    result=oracle(args)
    args.output.write_bytes(canonical_gzip(json.dumps(result,separators=(',',':')).encode('utf-8')))
    print(result['function_cases'],result['executed_instruction_steps'],len(result['covered_instruction_starts']))

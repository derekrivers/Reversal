#!/usr/bin/env python3
"""Execute admitted 0062e700 original-entry no-callee paths on synthetic memory."""
import argparse
import json
from pathlib import Path
import struct
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,
 UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP)
from extract_match_dependencies_26 import SPECIMEN,MANIFEST,PREFLIGHT,ARCHIVE,extract,need,sha

STACK,STOP,PLAYER,OBJECT,TABLE,RECORDS,COUNT=0x108000,0x700000,0x200000,0x300000,0x401000,0x501000,0xae2364
REGIONS=((PLAYER,0x1000),(OBJECT,0x1000),(0x400000,0x2000),(0x500000,0x2000),(0xae2000,0x1000))
REGS=dict(zip(('eax','ebx','ecx','edx','esi','edi','ebp','esp'),(UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP)))
def u32(n): return n&0xffffffff

def configurations():
    values=(-2147483648,-2,-1,0,1,5,6,2147483647)
    rows=[dict(kind='count',index=i,count=c,link=-1,flag=0,active=0) for c in values for i in values if i>=c]
    rows += [dict(kind='sentinel',index=i,count=6,link=-1,flag=0,active=0) for i in (-2,-1,0,1,5)]
    rows += [dict(kind='invalidate',index=i,count=6,link=l,flag=f,active=a)
             for i in (-2,0,5) for l in (-2,0,3) for f,a in ((0,0),(0,0x12345678),(1,0),(0xffffffff,0))]
    return rows

def run_case(body,config,ordinal):
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    for address,size in ((0x620000,0x10000),(0x100000,0x10000),(STOP,0x1000),*REGIONS): uc.mem_map(address,size)
    uc.mem_write(0x62e700,body)
    for address,size in REGIONS: uc.mem_write(address,bytes(((n*37+ordinal*11)&255 for n in range(size))))
    def write32(a,v): uc.mem_write(a,struct.pack('<I',u32(v)))
    write32(STACK,STOP);write32(STACK+4,PLAYER);write32(STACK+8,config['flag']);write32(STACK+12,0xc0dec0de)
    write32(PLAYER,config['index']);write32(PLAYER+0x39,config['active']);write32(COUNT,config['count'])
    write32(OBJECT,TABLE);write32(OBJECT+4,RECORDS)
    if config['kind']!='count': write32(TABLE+31*config['index']+14,config['link'])
    if config['kind']=='invalidate': uc.mem_write(RECORDS+48*config['link'],b'Q')
    initial={n:u32(0x12345000+(ordinal*0x127)+(k*0x10001)) for k,n in enumerate(REGS)}
    initial.update(ecx=OBJECT,esp=STACK)
    for n,r in REGS.items():uc.reg_write(r,initial[n])
    trace,effects=[],[]
    def code(m,a,size,data):
        need(0x62e700<=a<0x62e700+len(body),'execution escaped local body or reached callee')
        trace.append(f'{a:08x}');need(len(trace)<100,'step budget exceeded')
    def read(m,access,a,size,value,data):
        if not 0x100000<=a<0x110000: effects.append(['read',f'{a:08x}',size])
    def write(m,access,a,size,value,data):
        if not 0x100000<=a<0x110000: effects.append(['write',f'{a:08x}',size,u32(value)&((1<<(size*8))-1)])
    uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,write)
    uc.emu_start(0x62e700,STOP,count=100)
    need(uc.reg_read(UC_X86_REG_EIP)==STOP,'entry failed to reach RET8')
    final={n:uc.reg_read(r) for n,r in REGS.items()}
    need(final['esp']==STACK+12,'RET8 cleanup mismatch')
    need(all(final[n]==initial[n] for n in ('ebx','esi','edi','ebp')),'nonvolatile changed')
    return dict(input=config,seed=ordinal,initial=initial,final=final,effects=effects,trace=trace,
                memory_sha256=[sha(bytes(uc.mem_read(a,s))) for a,s in REGIONS])

def oracle(args):
    need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    sites=extract(args.binary,args.exports,args.preflight)
    meta=sites['bodies']['0062e700'];start=int(meta['file_offset'],16)
    body=args.binary.read_bytes()[start:start+meta['body_bytes']]
    rows=[run_case(body,c,n+1) for n,c in enumerate(configurations())]
    return dict(work_unit='R26-A',entry_va='0062e700',specimen_sha256=SPECIMEN,
       checkpoint_archive_sha256=ARCHIVE,export_manifest_sha256=MANIFEST,annotation_preflight_sha256=PREFLIGHT,
       body_sha256=meta['body_sha256'],emulator='Unicorn 2.1.4 x86-32',
       scope='synthetic stable disjoint mapped memory; original entry to RET8; count/sentinel/0x51 invalidation bypass paths; no callees',
       function_cases=len(rows),executed_instruction_steps=sum(len(r['trace']) for r in rows),
       covered_instruction_starts=sorted({a for r in rows for a in r['trace']}),cases=rows)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path)
    p.add_argument('--exports',type=Path,required=True);p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    result=oracle(args);args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')

#!/usr/bin/env python3
"""Original-entry Unicorn oracle for R28-A byte swap; synthetic mapped memory."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ
from unicorn.x86_const import *
from extract_sort_helpers_28 import extract, need, sha, pe_offset, SPECIMEN

ENTRY=0x9454d5
SENTINEL=0x700000
DATA=0x300000
STACK=0x400000
CODE=0x940000
REGS={'eax':UC_X86_REG_EAX,'ebx':UC_X86_REG_EBX,'ecx':UC_X86_REG_ECX,'edx':UC_X86_REG_EDX,
      'esi':UC_X86_REG_ESI,'edi':UC_X86_REG_EDI,'ebp':UC_X86_REG_EBP,'esp':UC_X86_REG_ESP,'eip':UC_X86_REG_EIP}

def u32(n): return n & 0xffffffff
def hexd(n): return f'{n:08x}'

def schedule():
    widths=[0,1,2,3,4,7,8,15,16,31]
    deltas=[0,1,2,3,7,16,32,64]
    return [{'seed':seed,'width':width,'delta':delta,'first':DATA+0x100}
            for seed in range(8) for width in widths for delta in deltas]

def emulate(pe, item):
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    uc.mem_map(CODE,0x10000);uc.mem_map(DATA,0x1000);uc.mem_map(STACK,0x1000)
    uc.mem_write(CODE,pe[0x540000:0x550000])
    data=bytes((i*37+item['seed']*23+7)&255 for i in range(0x1000))
    stack=bytes((i*19+item['seed']*11+5)&255 for i in range(0x1000))
    uc.mem_write(DATA,data);uc.mem_write(STACK,stack)
    esp=STACK+0x800
    p1=item['first'];p2=p1+item['delta'];width=item['width']
    uc.mem_write(esp,SENTINEL.to_bytes(4,'little')+p1.to_bytes(4,'little')+p2.to_bytes(4,'little')+width.to_bytes(4,'little'))
    initial={'eax':u32(0x10203040+item['seed']),'ebx':u32(0xa0b0c0d0+item['seed']),
             'ecx':u32(0x29384756+item['seed']),'edx':u32(0x50607080+item['seed']),
             'esi':u32(0x718293a4+item['seed']),'edi':u32(0xb3c4d5e6+item['seed']),
             'ebp':u32(0xc2d3e4f5+item['seed']),'esp':esp,'eip':ENTRY}
    for key,val in initial.items():uc.reg_write(REGS[key],val)
    trace=[];events=[]
    def code(_uc,addr,size,_user):
        trace.append(hexd(addr))
        need(len(trace)<1000,'unexpected loop bound')
    def memory(_uc,kind,addr,size,value,_user):
        if DATA<=addr and addr+size<=DATA+0x1000:
            if kind==UC_MEM_READ: events.append(['read',hexd(addr),size,int.from_bytes(_uc.mem_read(addr,size),'little')])
            else: events.append(['write',hexd(addr),size,value&((1<<(8*size))-1)])
    uc.hook_add(UC_HOOK_CODE,code)
    uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
    uc.emu_start(ENTRY,SENTINEL,count=1000)
    final={key:uc.reg_read(reg) for key,reg in REGS.items()}
    need(final['eip']==SENTINEL and final['esp']==esp+4,'did not return through original RET')
    return {'input':item,'initial':initial,'final':final,'events':events,'trace':trace,
            'data_sha256':sha(bytes(uc.mem_read(DATA,0x1000))),
            'stack_sha256':sha(bytes(uc.mem_read(STACK,0x1000)))}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary',type=Path);p.add_argument('--exports',type=Path,required=True)
    p.add_argument('--preflight',type=Path,required=True);p.add_argument('--sites',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); sites=extract(a.binary,a.exports,a.preflight)
    raw=a.sites.read_bytes();need(json.loads(raw)==sites,'site evidence mismatch')
    pe=a.binary.read_bytes();need(sha(pe)==SPECIMEN,'specimen mismatch')
    need(pe_offset(pe,ENTRY,44)==0x5454d5,'unexpected PE offset')
    cases=[emulate(pe,item) for item in schedule()]
    covered=sorted({addr for row in cases for addr in row['trace']})
    edges=sorted({(a,b) for row in cases for a,b in zip(row['trace'],row['trace'][1:])})
    swap=next(f for f in sites['functions'] if f['entry_va']=='009454d5')
    need(covered==swap['instruction_starts'],'instruction coverage incomplete')
    need([list(e) for e in edges]==sorted(swap['edges']),'edge coverage incomplete')
    result={'schema_version':1,'unit':'R28-A swap','specimen_sha256':SPECIMEN,
            'sites_sha256':sha(raw),'synthetic_only':True,'cases_count':len(cases),
            'executed_instruction_steps':sum(len(c['trace']) for c in cases),
            'covered_instruction_starts':covered,'covered_edges':[list(e) for e in edges],
            'cases':cases}
    a.output.write_bytes(gzip.compress((json.dumps(result,separators=(',',':'))+'\n').encode(),mtime=0))
    print(result['cases_count'],result['executed_instruction_steps'],len(covered),len(edges),sha(a.output.read_bytes()))

if __name__=='__main__':main()

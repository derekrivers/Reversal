#!/usr/bin/env python3
"""Original-entry Unicorn oracle for the 14-byte merge collection initializer."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ, UC_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                              UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP)

from extract_merge_dependencies_28 import extract, sha, PINNED

DATA = 0x200000
STACK = 0x400000
STOP = 0x700000
ESP = STACK+0x800
OFFSETS = [0,1,2,3,4,5,7,8,15,16,31,63,127,255,511,0x7f0]
REGS = {"eax":UC_X86_REG_EAX,"ebx":UC_X86_REG_EBX,"ecx":UC_X86_REG_ECX,
        "edx":UC_X86_REG_EDX,"esi":UC_X86_REG_ESI,"edi":UC_X86_REG_EDI,
        "ebp":UC_X86_REG_EBP,"esp":UC_X86_REG_ESP,"eip":UC_X86_REG_EIP}


def u32(value):
    return (value & 0xffffffff).to_bytes(4, "little")


def run(exe, exports, preflight):
    sites = extract(exe, exports, preflight)
    if len(sites["functions"]) != 2:
        raise ValueError("unexpected function count")
    static = sites["functions"][0]
    if static["entry_va"] != "0068d020" or static["calls"] or static["instruction_count"] != 7:
        raise ValueError("initializer site mismatch")
    body = exe.read_bytes()[int(static["file_offset"],16):][:17]
    if sha(body) != static["body_sha256"]:
        raise ValueError("body changed after extraction")
    cases=[]
    covered=set()
    edges=set()
    steps=0
    for seed in range(16):
        for offset in OFFSETS:
            receiver=DATA+0x100+offset
            uc=Uc(UC_ARCH_X86, UC_MODE_32)
            for base in (0x68d000, DATA, STACK, STOP):
                uc.mem_map(base,0x1000)
            uc.mem_write(0x68d020,body)
            uc.mem_write(DATA,bytes((i*29+seed*17+3)&255 for i in range(0x1000)))
            uc.mem_write(STACK,bytes((i*19+seed*11+5)&255 for i in range(0x1000)))
            uc.mem_write(ESP,u32(STOP))
            initial={"eax":(0xdeadbeef+seed*0x10101+offset)&0xffffffff,
                     "ebx":0x87654321^seed,"ecx":receiver,"edx":0x12345678^offset,
                     "esi":0x01020304^seed,"edi":0xfeedface^offset,"ebp":0xcafef00d^seed,
                     "esp":ESP,"eip":0x68d020}
            for name,value in initial.items():
                uc.reg_write(REGS[name],value)
            events=[]
            trace=[]

            def on_code(_uc,addr,_size,_):
                if not 0x68d020 <= addr < 0x68d031 or len(trace)>=16:
                    raise ValueError("execution escaped bounded original body")
                trace.append(f"{addr:08x}")

            def on_mem(_uc,kind,address,width,value,_):
                if not any(base<=address and address+width<=base+0x1000 for base in (DATA,STACK)):
                    raise ValueError("unexpected data access")
                event=["read" if kind==UC_MEM_READ else "write",f"{address:08x}",width]
                if kind==UC_MEM_WRITE:
                    event.append(value&((1<<(8*width))-1))
                events.append(event)

            uc.hook_add(UC_HOOK_CODE,on_code)
            uc.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,on_mem)
            uc.emu_start(0x68d020,STOP,count=16)
            final={name:uc.reg_read(reg)&0xffffffff for name,reg in REGS.items()}
            if final["eip"]!=STOP or final["esp"]!=ESP+4:
                raise ValueError("initializer did not return normally")
            covered.update(trace)
            edges.update(zip(trace,trace[1:]))
            steps+=len(trace)
            cases.append({"input":{"seed":seed,"offset":offset,"receiver":receiver},
                          "initial":initial,"final":final,"trace":trace,"events":events,
                          "memory_sha256":[sha(bytes(uc.mem_read(base,0x1000))) for base in (DATA,STACK)]})
    native_edges={tuple(pair) for pair in static["edges"]}
    if covered!={f"{0x68d020+x:08x}" for x in (0,2,4,7,10,13,16)} or edges!=native_edges:
        raise ValueError("original-entry instruction/CFG coverage mismatch")
    return {"work_unit":"R28-B", "specimen_sha256":PINNED,
            "sites_sha256":sha((Path("evidence")/"merge-dependencies-28-sites.json").read_bytes()),
            "domain":"256 synthetic mapped, stable receiver/stack inputs; original entry to RET",
            "cases_count":len(cases),"executed_instruction_steps":steps,
            "covered_instruction_starts":sorted(covered),"covered_edges":sorted(map(list,edges)),
            "cases":cases}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("exe","exports","preflight","output"):
        parser.add_argument(name,type=Path)
    args=parser.parse_args()
    result=run(args.exe,args.exports,args.preflight)
    args.output.write_bytes(gzip.compress((json.dumps(result,separators=(",",":"))+"\n").encode(),mtime=0))

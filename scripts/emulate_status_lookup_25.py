#!/usr/bin/env python3
"""Execute original local helper entries on mapped synthetic memory until RET4."""
import argparse
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_ESP, UC_X86_REG_EIP)

from extract_status_lookup_25 import SPECIMEN, MANIFEST, PREFLIGHT, ARCHIVE, extract, need

STACK, STOP, PLAYER, OBJECT, TABLE, COUNT = 0x108000, 0x700000, 0x200000, 0x300000, 0x9e7ad9, 0xae2364
REGS = {"eax": UC_X86_REG_EAX, "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
        "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI, "esp": UC_X86_REG_ESP}


def u32(value):
    return value & 0xffffffff


def signed(value):
    value = u32(value)
    return value if value < 0x80000000 else value-0x100000000


def table_byte(index):
    return ((index*73+41)^0x5a)&0xff


def run_case(body, site, config, ordinal):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    for address, length in ((0x620000,0x10000),(0x100000,0x10000),(PLAYER,0x1000),
                            (OBJECT,0x2000),(0x9e6000,0x4000),(0xae2000,0x2000),(STOP,0x1000)):
        uc.mem_map(address,length)
    start = int(site,16)
    uc.mem_write(start,body)
    initial = {"eax":u32(0x9a5a1200 ^ (ordinal*0x1237)), "ecx":OBJECT,
               "edx":u32(0x75abc000 ^ ordinal), "esi":u32(0x12345000 ^ ordinal),
               "edi":u32(0x56789000 ^ ordinal), "esp":STACK}
    if site == "0062ec00":
        initial["ecx"] = u32(0xcafe1300 ^ ordinal)
        uc.mem_write(STACK,struct.pack("<III",STOP,u32(config["input"]),0xc0dec0de))
        for index in range(-128,128):
            uc.mem_write(TABLE+13*index,bytes([table_byte(index)]))
    elif site == "0062ece0":
        uc.mem_write(STACK,struct.pack("<III",STOP,PLAYER if config["nonnull"] else 0,0xc0dec0de))
        uc.mem_write(PLAYER,struct.pack("<I",u32(config["index"])))
        uc.mem_write(PLAYER+0x61,struct.pack("<I",config["active"]))
        uc.mem_write(COUNT,struct.pack("<I",u32(config["count"])))
        uc.mem_write(OBJECT,struct.pack("<I",OBJECT+0x100))
        if 0 <= config["index"] <= 5:
            row = OBJECT+0x100+31*config["index"]
            uc.mem_write(row+0x12,bytes([config["sentinel"]]))
            uc.mem_write(row+0x13,bytes([config["value"]&0xff]))
    else:
        need(signed(config["index"]) >= signed(config["count"]), "lookup case reaches refresh callee")
        uc.mem_write(STACK,struct.pack("<III",STOP,PLAYER,0xc0dec0de))
        uc.mem_write(PLAYER,struct.pack("<I",u32(config["index"])))
        uc.mem_write(COUNT,struct.pack("<I",u32(config["count"])))
    for name, reg in REGS.items():
        uc.reg_write(reg,initial[name])
    uc.reg_write(UC_X86_REG_EIP,start)
    trace, reads, writes = [], [], []

    def hook_code(machine,address,size,data):
        if address == STOP:
            machine.emu_stop()
            return
        need(start <= address < start+len(body), "execution escaped local body")
        trace.append(f"{address:08x}")
        need(len(trace) <= 80, "unexpected execution length")

    def hook_read(machine,access,address,size,value,data):
        if not 0x100000 <= address < 0x110000:
            reads.append([f"{address:08x}",size])

    def hook_write(machine,access,address,size,value,data):
        if not 0x100000 <= address < 0x110000:
            writes.append([f"{address:08x}",size])

    uc.hook_add(UC_HOOK_CODE,hook_code)
    uc.hook_add(UC_HOOK_MEM_READ,hook_read)
    uc.hook_add(UC_HOOK_MEM_WRITE,hook_write)
    uc.emu_start(start,STOP+1,count=90)
    need(uc.reg_read(UC_X86_REG_EIP) == STOP, "entry did not reach RET4")
    final = {name:uc.reg_read(reg) for name,reg in REGS.items()}
    need(final["esp"] == STACK+8, "RET4 stack cleanup changed")
    need(final["esi"] == initial["esi"] and final["edi"] == initial["edi"], "callee-saved register changed")
    need(writes == [], "unexpected external memory write")
    return {"input":config,"initial":initial,"final":final,"external_reads":reads,
            "external_writes":writes,"trace":trace}


def oracle(args):
    need(unicorn.__version__ == "2.1.4", "requires Unicorn 2.1.4")
    sites = extract(args.binary,args.exports,args.preflight)
    binary = args.binary.read_bytes()
    byte_configs = [{"nonnull":False,"index":0,"count":5,"active":0,"sentinel":0,"value":0}]
    byte_inputs = [(0,0,1,0,0),(5,5,1,0,0),(-1,5,1,0,0),(0,5,0,0,0)]
    byte_inputs += [(i,6,1,s,v) for i in (0,1,5) for s,v in
                    ((0xff,0),(0x80,0),(0x7f,0),(0,0x80),(0,0xff),(0,0),(0,1),(0,2),(0,127))]
    byte_configs += [{"nonnull":True,"index":i,"count":c,"active":a,"sentinel":s,"value":v}
                     for i,c,a,s,v in byte_inputs]
    configs = {
        "0062ec00": [{"input":n} for n in range(-128,128)],
        "0062ece0": byte_configs,
        "0062ed70": [{"index":i,"count":c} for c in (-2147483648,-5,-1,0,1,5,100,2147483647)
                       for i in (-2147483648,-6,-5,-1,0,1,5,99,100,2147483647) if i >= c],
    }
    entries = {}
    for site, cases in configs.items():
        meta = sites["bodies"][site]
        start = int(meta["file_offset"],16)
        body = binary[start:start+meta["body_bytes"]]
        rows = [run_case(body,site,config,n+1) for n,config in enumerate(cases)]
        entries[site] = {"body_sha256":meta["body_sha256"],"function_cases":len(rows),
                         "executed_instruction_steps":sum(len(r["trace"]) for r in rows),
                         "covered_instruction_starts":sorted({p for r in rows for p in r["trace"]}),
                         "cases":rows}
    return {"work_unit":"R25-A","specimen_sha256":SPECIMEN,"checkpoint_archive_sha256":ARCHIVE,
            "export_manifest_sha256":MANIFEST,"annotation_preflight_sha256":PREFLIGHT,
            "emulator":"Unicorn x86-32","scope":"0062ec00 and 0062ece0 complete local bodies on synthetic mapped memory; 0062ed70 original-entry signed count-guard path only; no callees executed",
            "entries":entries}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary",type=Path)
    p.add_argument("--exports",type=Path,required=True)
    p.add_argument("--preflight",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args = p.parse_args()
    result = oracle(args)
    args.output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n")

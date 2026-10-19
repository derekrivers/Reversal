#!/usr/bin/env python3
"""R30-B: pin and compare the original participant-effect diagnostic frontier."""
import argparse
import json
from pathlib import Path

import capstone
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_OP_IMM
from emulate_action33_prefix_30 import EXPECTED,decode,pe_offset,need,sha,hx,compact
from extract_action33_prefix_30 import compare,rows,verify_manifest,RUNTIME_MANIFEST,CALLER_HASH

RANGES=((0x7024b4,0x7024b9),(0x6cfe10,0x6cfec7),(0x62ed70,0x62ed99))
BODIES={0x6cfe10:2624,0x62ed70:187}
HASHES={
 '006cfe10.asm':'91c571aa3902a311fac6ea69f36836dde6cb2d2427c9a9d9ce687e82e3e91cf9',
 '006cfe10.c':'a5fc488802c3f25de5f9e1ccb7299328fbd93f3d2b5be3b46a0142f370124dd1',
 '0062ed70.asm':'9b0bd12347e822108343cd47f26cfd81f47a577075c6463f853bde53cefd476e',
 '0062ed70.c':'b2cfcc78913bf10d8822ed7eb0427cb47aa4b36ad01f5f676783d6d79488c83f'}
PREFIX_ORACLE='08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f'
PREFIX_SCRIPT='9486fdba017157b918081023641a2360a392839c2339c287e2a8fa97d28cee32'


def instructions(data):
    decode(data)  # mandatory specimen and decoder gates before any extraction
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True;all_ins={};ranges=[]
    for a,b in RANGES:
        off=pe_offset(data,a,b-a);body=data[off:off+b-a];seq=list(md.disasm(body,a))
        need(sum(i.size for i in seq)==len(body),'incomplete effect range decode')
        all_ins.update((i.address,i) for i in seq)
        ranges.append({'start':hx(a),'end_exclusive':hx(b),'file_offset':hx(off),
                       'bytes':len(body),'sha256':sha(body),'instructions':len(seq)})
    return all_ins,ranges


def extract(binary,exports09,exports10,runtime):
    data=binary.read_bytes();insns,ranges=instructions(data);native={}
    try:pe_offset(data,0xb63d28,4)
    except ValueError:pass
    else:raise ValueError('lookup global unexpectedly has raw PE backing')
    for name,digest in HASHES.items():
        folder=exports09 if name.startswith('006cfe10') else exports10
        raw=(folder/name).read_bytes();need(sha(raw)==digest,'native export digest mismatch '+name)
        if name.endswith('.asm'):native.update(rows(folder/name))
    caller=exports09/'00702050.asm';need(sha(caller.read_bytes())==CALLER_HASH,'caller native export digest mismatch')
    native.update(rows(caller));compare(insns,native)
    verify_manifest(runtime,RUNTIME_MANIFEST)
    # Compare all actually executable RNG/CRT instructions, not only call sites.
    prefix_ins,_=decode(data)
    rng_instruction_count=0
    for name,a,b in (('0090cfc0',0x90cfc0,0x90d02d),('00946a04',0x946a04,0x946a22)):
        selected={k:v for k,v in prefix_ins.items() if a<=k<b};rng_instruction_count+=len(selected)
        compare(selected,rows(runtime/(name+'.asm')))
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True;bodies=[]
    for a,n in BODIES.items():
        off=pe_offset(data,a,n);body=data[off:off+n];seq=list(md.disasm(body,a));starts={i.address for i in seq}
        need(sum(i.size for i in seq)==n,'incomplete whole-body decode')
        folder=exports09 if a==0x6cfe10 else exports10;listing=rows(folder/(hx(a)+'.asm'))
        need(starts==set(listing),'full native address set mismatch')
        compare({i.address:i for i in seq},listing)
        calls=[];branches=[];indirect=[];returns=[];edges=[];stores=[]
        for i in seq:
            if i.mnemonic=='call':calls.append([hx(i.address),hx(i.operands[0].imm)])
            if i.mnemonic.startswith('ret'):returns.append([hx(i.address),int(i.op_str or '0',0)]);targets=[]
            elif i.mnemonic.startswith('j'):
                if i.operands[0].type==CS_OP_IMM:
                    targets=[i.operands[0].imm]+([] if i.mnemonic=='jmp' else [i.address+i.size])
                    need(all(t in starts for t in targets),'direct CFG escape')
                    branches.append([hx(i.address),i.mnemonic,[hx(t) for t in targets]])
                else:targets=[];indirect.append(hx(i.address))
            else:targets=[i.address+i.size]
            edges.extend([[hx(i.address),hx(t)] for t in targets])
            for op in i.operands:
                if op.type==capstone.CS_OP_MEM and op.access&capstone.CS_AC_WRITE:stores.append([hx(i.address),op.size])
        bodies.append({'entry':hx(a),'bytes':n,'file_offset':hx(off),'sha256':sha(body),'instructions':len(seq),
          'calls':calls,'direct_branches':branches,'unresolved_indirect_branches':indirect,'returns':returns,
          'explicit_memory_store_sites_and_widths':stores,'direct_cfg_edges':len(edges),'direct_cfg_sha256':sha(compact(edges))})
    need(insns[0x6cfec2].operands[0].imm==0x62ed70,'participant lookup target changed')
    # The stop instruction itself is compared but never admitted for execution.
    a=0x62ed99;off=pe_offset(data,a,5);stop=list(md.disasm(data[off:off+5],a))
    need(len(stop)==1 and stop[0].mnemonic=='call' and stop[0].operands[0].imm==0x944cff,'diagnostic target changed')
    compare({a:stop[0]},native)
    return {'unit':'R30-B','specimen_sha256':EXPECTED,'prefix_baseline':'2d947281a9c94620cb1927960b2075c47f644fff',
      'prefix_oracle_sha256':PREFIX_ORACLE,'prefix_emulator_sha256':PREFIX_SCRIPT,
      'native_export_sha256':HASHES,'caller_native_sha256':CALLER_HASH,'runtime_manifest_sha256':RUNTIME_MANIFEST,
      'admitted_ranges':ranges,'admitted_instruction_count':len(insns)+rng_instruction_count,
      'lookup_global_has_raw_PE_backing':False,
      'full_body_operand_comparisons':bodies,'boundary_instruction':{'site':'0062ed99','target':'00944cff','bytes':5,'sha256':sha(data[off:off+5]),'executed':False},
      'scope':'original caller boundary through two initial RNG groups and null-player diagnostic prefix; effect helper does not return',
      'first_state_gap':{'read_site':'006cfeb8','field':'shooter+69','value':0,'lookup_global':'00b63d28','lookup_value':0,
        'lookup_call':'006cfec2','null_branch':'0062ed83 not taken','first_unsupported_call':'0062ed99 -> 00944cff'}}


def parser():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path)
    for name in ('exports09','exports10','runtime','output'):p.add_argument('--'+name,type=Path,required=True)
    return p


if __name__=='__main__':
    a=parser().parse_args();result=extract(a.binary,a.exports09,a.exports10,a.runtime)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(result['admitted_instruction_count'],'admitted original/native instructions match')

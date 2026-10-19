#!/usr/bin/env python3
"""R32-B: execute the original slot initializer before participant placement."""
import argparse
import json
from pathlib import Path

import capstone
import unicorn
import extract_action33_lifecycle_31 as life

BASELINE='06de3f3db9da6627a9efae47e5d0d87942b696ae'
SLOT_MANIFEST='4a50131744515c61a2f18ed4149342950e81c0e051bb79399aaefd349737ed3d'
BASE_RANGES=dict(life.RANGES)
EXTRA_RANGES={0x6eada0:0xf8,0x6eaea0:0x6eaf98-0x6eaea0,
              0x6eb190:0xa,0x6eb481:3,0x6b7e50:0x3a,
              0x6b7f41:0x13,0x9463af:0x6a,0x946419:0x18}
# Authored independently from the initializer's fixed member assignments.
ZERO8=(0x27,0x102,0x103,0x25,0x26,0x1c,0xff,0x1a,0x101,0xfe,1,0x24,
       2,3,4,5,6,7,8,9,10,11,12,0x10,0xd,0xe,0xf,0x11,0x12,0x13,0x14,0x15,0x23,0x16,0xfd)
ZERO16=(0x37,0x29,0x19c,0x1ba)
ZERO32=(0x19e,0x69,0x6d,0x55,0x1a6,0x1a2,0x1aa,0x1ae,0x1b2,0x1b6,0x4d,0xf9)
INIT_CHANGES=([(n,1,0) for n in ZERO8]+[(n,2,0) for n in ZERO16]+
              [(n,4,0) for n in ZERO32]+[(n,4,0xffffffff) for n in (0x5d,0x61,0x65)]+
              [(0x19,1,0xfb),(0,1,0xff),(0x2b,1,0xff),(0x28,1,0xff),(0x1b,1,6),(0x35,2,0x17d4)])


def extract(a):
    life.RANGES=dict(BASE_RANGES)
    pe,decoded,native,sites=life.extract(a)
    raw=(a.slot/'manifest.json').read_bytes()
    life.need(life.sha(raw)==SLOT_MANIFEST,'slot manifest mismatch')
    manifest=json.loads(raw)
    life.need(manifest['specimen_sha256']==life.SPECIMEN and
              manifest['source_archive_sha256']==life.ARCHIVES['focused'] and
              manifest['source_checkpoint']=='29 fresh disposable extraction; function 006eada0..006eae97 created only in disposable project',
              'slot specimen/archive provenance mismatch')
    extra_native={}
    for name,meta in manifest['files'].items():
        data=(a.slot/name).read_bytes()
        life.need(len(data)==meta['bytes'] and life.sha(data)==meta['sha256'],'slot export mismatch '+name)
        if name.endswith('.asm'):
            extra_native[int(name[:-4],16)]=life.rows(data)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    new_ranges=[]
    for start,size in EXTRA_RANGES.items():
        off=life.offset(pe,start,size);body=pe[off:off+size];seq=list(md.disasm(body,start))
        life.need(sum(i.size for i in seq)==size,'incomplete slot range')
        owner=0x6eaea0 if start==0x6eb190 else 0x6b7f30 if start==0x6b7f41 else start
        selected=extra_native[owner] if owner in extra_native else native[owner]
        life.compare(seq,selected);decoded.update((i.address,i) for i in seq)
        new_ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(start+size),
                           'file_offset':life.hx(off),'bytes':size,'sha256':life.sha(body),
                           'instructions':len(seq),'all_native_operands_match':True})
    life.RANGES=dict(BASE_RANGES)
    life.RANGES.update(EXTRA_RANGES)
    sites['unit']='R32-B';sites['baseline_commit']=BASELINE
    sites['slot_manifest_sha256']=SLOT_MANIFEST
    sites['slot_export_hashes']={name:meta['sha256'] for name,meta in manifest['files'].items()}
    sites['ranges']=[r for r in sites['ranges'] if r['entry']!='006eaea0']+new_ranges
    sites['scope']='selected static ranges and synthetic original entries; no game caller, completed slot or live lifecycle'
    return pe,decoded,native,sites


def produce(pe,decoded):
    life.need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    cases=[]
    for club in range(4):
        for index in range(20):
            m=life.Machine(pe,decoded,club);slot=0x280000+0x1be*index
            staff_id=(club*11+index)%32;staff=0x230000+staff_id*0x6e;attribute=0x240000+staff_id*0x46
            initial=m.entry(0x6eada0,slot,[])
            before,after,init,events=m.run(0x6eada0,life.STOP,set())
            life.expected_data(before,after,[(slot+n,width,value) for n,width,value in INIT_CHANGES])
            final=m.registers()
            life.need(final['eax']==slot and final['esp']==life.SP+4,'initializer receiver/RET ABI mismatch')
            life.need(all(final[r]==initial[r] for r in ('ebx','esi','edi','ebp')),'initializer nonvolatile ABI mismatch')
            side_write=[e for e in events if e[1]=='write' and e[2]==life.hx(slot+0x27)]
            life.need(side_write==[['006eadb2','write',life.hx(slot+0x27),1]],'initializer side write width/source mismatch')
            init.update(receiver=slot,initial_registers=initial,final_registers=final,
                        function_returned=True,side_write=side_write[0],side_value=m.uc.mem_read(slot+0x27,1)[0])
            cell=0x210000+0x91*club+2+4*index
            for address,value in ((0x200601,0x210000),(0x220000,club),(0x2200cf,0),
                (0xae2350,1),(0xae235c,8),(0xae2364,64),(0xae23bc,0x230000),
                (cell,staff_id),(staff,staff_id),(staff+0x61,attribute)):
                m.set32(address,value)
            m.uc.mem_write(attribute+0x45,bytes([40+club]))
            initial=m.entry(0x8968f0,0x200000,[0x220000,0xa5a50000|index,0])
            before,after,lookup,_=m.run(0x8968f0,life.STOP,life.LOOKUP_CALLS)
            final=m.registers();returned=final['eax']
            life.need(returned==staff and final['esp']==life.SP+16,'lookup result/RET ABI mismatch')
            life.need(all(final[r]==initial[r] for r in ('ebx','esi','edi','ebp')),'lookup nonvolatile ABI mismatch')
            life.expected_data(before,after,[])
            lookup.update(returned_record=returned,initial_registers=initial,final_registers=final)
            m.set32(0x260023,0x280000);m.set32(0x260012,0x250000)
            m.uc.mem_write(0x260018,bytes([club]));extra=0x89abcd80|club
            m.entry(0x6e0d00,0x260000,[0xa5a50000|index,returned,extra])
            before,after,placement,events=m.run(0x6e0d00,0x6eaf8f,{(0x6e0dde,0x6eaea0)})
            life.need(placement['call_frames']==[{'site':'006e0dde','target':'006eaea0','ecx':slot,
                'arguments':[0x250000,returned,0x89abcd00|club,0xa5a50000|index,extra]}],
                'placement argument provenance mismatch')
            life.expected_data(before,after,[(slot+0x19e,4,0x250000),(slot+0x69,4,returned),
                (slot+0x6d,4,attribute),(slot,1,index),(slot+0x2e,1,extra&255),(slot+0x17,1,40+club)])
            side_read=[e for e in events if e[2]==life.hx(slot+0x27)]
            life.need(side_read==[['006eaf77','read',life.hx(slot+0x27),1]],'placement side read width/source mismatch')
            life.need(m.uc.mem_read(slot+0x27,1)==b'\0','initializer side output not preserved')
            final=m.registers()
            life.need(final['eax']==0x250000 and final['ecx']&255==0,'side consumer branch provenance mismatch')
            life.need(not any(e[2]==life.hx(0x250000+0x4792) for e in events),'read next unproduced owner field')
            placement.update(slot=slot,staff_alias=m.word(slot+0x69),attribute_alias=m.word(slot+0x6d),
                side_read=side_read[0],side_value=0,final_registers=final,function_returned=False,
                stop_reason='before 006eaf8f reads unproduced match+4792 owner pointer')
            life.need(m.word(0xb63d28)==0 and m.uc.mem_read(0xb63d10,1)==b'\0','process initialization was invented')
            m.entry(0x62ed70,0,[returned])
            before,after,status,_=m.run(0x62ed70,0x946214,life.STATUS_CALLS)
            life.expected_data(before,after,[(0xb63d10,1,1),(0xb63d08,2,40),(0xb63d0a,2,1972),(0xb63d0c,4,1),(0,4,life.SP-540)])
            life.need(status['calls']==[[life.hx(a),life.hx(b)] for a,b in
                 ((0x62edfc,0x62c680),(0x62c6c8,0x54a110),(0x62c6d2,0x94627a),(0x94627e,0x94620d))],
                 'normal status call order changed')
            life.need(m.word(m.uc.reg_read(life.REGS['esp']))==0,'exit-list base is not loader zero')
            status.update(record_argument=returned,lookup_global=m.word(0xb63d28),unsupported_argument=0,
                function_returned=False,stop_reason='before 00946214 -> 0094bef1 with loader-zero exit-list base')
            cases.append({'club_id':club,'index':index,'staff_id':staff_id,'initializer':init,
                          'lookup':lookup,'placement':placement,'status':status})
    return {'unit':'R32-B','specimen_sha256':life.SPECIMEN,'synthetic_only':True,
       'pipeline_scope':'separate original entries preserve slot initializer output and consume original returned staff pointer',
       'cases':cases,'coverage':{'initializer_returns':80,'lookup_returns':80,'placement_frontiers':80,
       'normal_status_frontiers':80,'instruction_steps':sum(c[s]['instruction_steps'] for c in cases for s in ('initializer','lookup','placement','status'))}}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','state','staff','focused','support','exports25','slot','output'):
        p.add_argument(name,type=Path)
    return p


def generate(a):
    pe,decoded,_,sites=extract(a)
    return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.write_bytes(life.pack(result))
    print(json.dumps(result['oracle']['coverage']))

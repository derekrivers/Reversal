#!/usr/bin/env python3
"""R35-B: auxiliary allocation requests and bounded static lifecycle evidence."""
import argparse
import json
from pathlib import Path
import capstone
import unicorn
import extract_action33_lifecycle_31 as life

BASELINE='eabc39b'
SCOPE='synthetic interior allocation-request windows only; no allocator return, auxiliary table, receiver, contract row or live lifecycle produced'
COUNTS=(0,1,2,31,64,255,0x3333333,0x80000000,0xffffffff)
# Native-checked static ranges. No listing or code bytes are retained.
RANGES={
 0x82849a:(0x8284be,0x828110),0x82852b:(0x8285bb,0x828110),
 0x8286f2:(0x828759,0x828110),0x8297ca:(0x82980e,0x828110),
 0x82af34:(0x82af8e,0x82a9c0),0x82b140:(0x82b19d,0x82a9c0),
 0x82b2ed:(0x82b351,0x82a9c0),0x82b464:(0x82b4c2,0x82a9c0),
 0x82b614:(0x82b696,0x82a9c0),0x82c7ba:(0x82c7f5,0x82a9c0),
 0x83036c:(0x8303c4,0x82ff40),0x82ff40:(0x82ff53,0x82ff40)}
PE_ONLY={0x4c7040:0x4a6,0x4c74f0:0x64,0x944e46:0x12}


def parser():
    p=argparse.ArgumentParser();p.add_argument('binary',type=Path)
    p.add_argument('state',type=Path);p.add_argument('output',type=Path)
    return p


def extract(a):
    pe=a.binary.read_bytes()
    life.need(len(pe)==7192576 and life.sha(pe)==life.SPECIMEN,'pinned specimen mismatch')
    life.need(capstone.__version__=='5.0.7','requires Capstone 5.0.7')
    life.need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    raw=(a.state/'manifest.json').read_bytes()
    life.need(life.sha(raw)==life.MANIFESTS['state'],'state manifest mismatch')
    manifest=json.loads(raw);native={};hashes={}
    life.need(manifest['specimen_sha256']==life.SPECIMEN and manifest['source_archive_sha256']==life.ARCHIVES['state'],'state provenance mismatch')
    life.need(set(manifest['files'])=={n+e for n in life.INVENTORIES['state'] for e in ('.asm','.c')},'state inventory mismatch')
    for name,meta in manifest['files'].items():
        raw=(a.state/name).read_bytes()
        life.need(len(raw)==meta['bytes'] and life.sha(raw)==meta['sha256'],'state export mismatch '+name)
        hashes[name]=life.sha(raw)
        if name.endswith('.asm'):native[int(name[:-4],16)]=life.rows(raw)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    decoded={};ranges=[]
    for start,(end,parent) in RANGES.items():
        size=end-start;off=life.offset(pe,start,size);raw=pe[off:off+size];seq=list(md.disasm(raw,start))
        life.need(sum(i.size for i in seq)==size,'incomplete native range')
        # Ghidra prints the unsigned-below opcode as JC; Capstone prints JB.
        equivalent={address:('JB '+text[3:] if text.startswith('JC ') else text)
                    for address,text in native[parent].items()}
        life.compare(seq,equivalent);decoded.update((i.address,i) for i in seq)
        ranges.append(dict(entry=life.hx(start),end_exclusive=life.hx(end),file_offset=life.hx(off),bytes=size,sha256=life.sha(raw),instructions=len(seq),native_operands_match=True,executed=False))
    for start,size in PE_ONLY.items():
        off=life.offset(pe,start,size);raw=pe[off:off+size];seq=list(md.disasm(raw,start))
        life.need(sum(i.size for i in seq)==size,'incomplete PE-only range')
        decoded.update((i.address,i) for i in seq)
        ranges.append(dict(entry=life.hx(start),end_exclusive=life.hx(start+size),file_offset=life.hx(off),bytes=size,sha256=life.sha(raw),instructions=len(seq),native_operands_match=False,executed=False))
    expected={0x8284a7:('shl','ecx, 4'),0x8284aa:('sub','ecx, eax'),
      0x82854e:('mov','dword ptr [esi], 0xffffffff'),0x828556:('mov','dword ptr [esi + 4], 0xffffffff'),
      0x828746:('add','esi, 0x4f'),0x82af3b:('push','4'),0x82af3d:('push','0xae2d10'),
      0x82b640:('push','0x4f'),0x4c74e3:('ret','4'),0x4c7553:('ret','')}
    # Normalize decimal/hex spelling without relaxing operand order or width.
    for address,(mnemonic,operands) in expected.items():
        ins=decoded[address]
        from extract_status_lookup_25 import normalized
        life.need(normalized(ins.mnemonic+' '+ins.op_str)==normalized(mnemonic+' '+operands),'lifecycle semantic site changed '+life.hx(address))
    for offset in range(0,0x3c,4):
        stores=[i for i in decoded.values() if 0x4c7158<=i.address<=0x4c7181 and i.mnemonic=='mov' and i.operands[0].type==capstone.x86.X86_OP_MEM and i.operands[0].mem.disp==offset]
        life.need(len(stores)==1 and stores[0].operands[0].size==4 and stores[0].operands[1].reg==capstone.x86.X86_REG_EBX,'constructor member width changed')
    life.need(decoded[0x4c7073].op_str=='dword ptr [0x9670f8]','constructor OS boundary changed')
    for va in (0xae2d0c,0xae2d10,0xae1050):
        base,sections=life.pe_sections(pe);section=next(s for s in sections if base+s[2]<=va<base+s[2]+s[1])
        life.need(va-base-section[2]>=section[3],'global unexpectedly raw backed')
    return pe,decoded,{'unit':'R35-B','baseline_commit':BASELINE,'specimen_sha256':life.SPECIMEN,
      'scope':SCOPE,'state_manifest_sha256':life.MANIFESTS['state'],'state_archive_sha256':life.ARCHIVES['state'],
      'state_export_sha256':hashes,'selected_ranges':ranges,'constructor_imports':life.constructor_imports(pe),
      'static_lifecycle':{'auxiliary_global':'00ae2d0c','auxiliary_count':'00ae2d10','stride':79,
        'new_count_source':'00ae2364','new_allocate_call':'008284ad -> 00944e46','new_publish':'008284b7',
        'load_count_read':'0082af42 -> 00932c30: destination 00ae2d10, size 4, count 1',
        'load_allocate_call':'0082af61 -> 00944e46','load_publish':'0082af6d',
        'current_load_read':'0082b643 -> 00932c30: size 79, count 00ae2d10',
        'new_primary_secondary_defaults':[-1,-1],'default_sites':['0082854e','00828556'],
        'auxiliary_release_call':'008303b6 -> 009452ca','auxiliary_clear':'008303be',
        'receiver_bytes':60,'receiver_setup':['008297fc','0082c7ea'],
        'receiver_constructor':'004c7040','receiver_first_os_call':'004c7073',
        'receiver_release':'00830378 -> 004c74f0; 0083037e -> 00944c94','receiver_clear':'00830386'},
      'contract_frontier':{'instruction':'004cf62b','advanced':False,'reason':'no original allocator return, auxiliary records or initialized receiver'},
      'evidence_class':'selected static native/PE observations and synthetic interior allocation-request execution'}


def produce(pe,decoded):
    # Use only the two admitted interior ranges. No earlier setup call is bypassed
    # with a fabricated return and neither allocator call is executed.
    life.RANGES.clear();life.RANGES.update({0x82849a:0x8284ad-0x82849a,0x82af53:0x82af61-0x82af53})
    cases=[]
    for path,entry,stop,count_global in (('new',0x82849a,0x8284ad,0xae2364),('load',0x82af53,0x82af61,0xae2d10)):
        for seed,count in enumerate(COUNTS):
            m=life.Machine(pe,decoded,seed);m.set32(count_global,count);m.entry(entry,0,[])
            before,after,row,events=m.run(entry,stop,set());size=count*79&0xffffffff
            changes=[(0xae2d10,4,count)] if path=='new' else []
            life.expected_data(before,after,changes)
            expected=bytearray(before['stack']);at=life.SP-4-life.DATA_REGIONS['stack'][0]
            expected[at:at+4]=size.to_bytes(4,'little')
            life.need(bytes(expected)==after['stack'],'allocation complete stack mismatch')
            life.need(m.word(life.SP-4)==size and m.registers()['esp']==life.SP-4,'allocation request size mismatch')
            life.need(m.word(0xae2d0c)==0 and m.word(0xae1050)==0,'invented auxiliary or receiver state')
            cases.append({'path':path,'count':count,'requested_bytes':size,'allocator_call_executed':False,
              'auxiliary_base_after':0,'receiver_after':0,'function_entry':False,'function_returned':False,
              'frontier':row,'observed_events':events})
    return {'unit':'R35-B','specimen_sha256':life.SPECIMEN,'synthetic_only':True,'scope':SCOPE,'cases':cases,
      'coverage':{'allocation_request_windows':len(cases),'instruction_steps':sum(c['frontier']['instruction_steps'] for c in cases),
        'allocators_executed':0,'records_produced':0,'contract_lookup_advanced':False}}


def generate(a):
    pe,decoded,sites=extract(a);return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();value=generate(a);a.output.write_bytes(life.pack(value))
    print(json.dumps(value['oracle']['coverage']))

#!/usr/bin/env python3
"""R30-D: compact static provenance and bounded synthetic slot-producer evidence."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
import unicorn
from unicorn import x86_const as x86
from extract_status_lookup_25 import normalized

SPECIMEN = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
MANIFEST = 'b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a'
STAFF_MANIFEST = 'c6457fcd1b68d524d2d4ce623d144e77a3e5ae23c9a4699e157b9ec2181f7b35'
LIFECYCLE_MANIFEST = '83d24d0790139ab37f7e3c82e12dfff9844456a8273e8d5ee10d1036359c7daf'
ARCHIVE = 'ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a'
CONTEXT = {'0062ed70.asm': '9b0bd12347e822108343cd47f26cfd81f47a577075c6463f853bde53cefd476e',
           '00944cff.asm': '2c77d5adb326a4288cc212ffd485d46b9e0785b9e5a48819d69f121293892113',
           '006cfe10.asm': '91c571aa3902a311fac6ea69f36836dde6cb2d2427c9a9d9ce687e82e3e91cf9'}
# Endpoints are exclusive. These are selected ranges, not new whole-body contracts.
RANGES = [('006dbb80',0x6dbba9,0x6dbbd8),('006dbb80',0x6dbc15,0x6dbc1f),
          ('006e0d00',0x6e0d00,0x6e0d17),('006e0d00',0x6e0d9e,0x6e0def),
          ('006eaea0',0x6eaea0,0x6eaf46),('006eaea0',0x6ebd48,0x6ebd5a),
          ('00828110',0x82812b,0x828131),('00828110',0x82876e,0x828770),
          ('00828110',0x8292f3,0x829330),
          ('0082a9c0',0x82c32b,0x82c366),('0082ff40',0x82ff40,0x82ff51),
          ('0082ff40',0x8300e8,0x830108),('0062a680',0x62a680,0x62a6d1),
          ('0062a680',0x62a6f8,0x62a727),
          ('0062a680',0x62a83f,0x62a895),('0062a8a0',0x62a8a0,0x62a914),
          ('0062ed70',0x62ed70,0x62ee2b),('00944cff',0x944cff,0x944d13),
          ('006cfe10',0x6cfeb0,0x6cfec7),
          ('008968f0',0x8968f0,0x896a8e),('008982b0',0x8982b0,0x898302),
          ('00528080',0x528080,0x528088),('00528080',0x528168,0x528186),
          ('00528540',0x528cfe,0x528d30),('00528540',0x529df8,0x529e0c)]
REGS = {name:getattr(x86,'UC_X86_REG_'+name.upper())
        for name in ('eax','ebx','ecx','edx','esi','edi','ebp','esp','eip')}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(value):
    return f'{value:08x}'


def pe_sections(pe):
    nt=struct.unpack_from('<I',pe,0x3c)[0]
    need(pe[:2]==b'MZ' and pe[nt:nt+4]==b'PE\0\0','invalid PE')
    need(struct.unpack_from('<H',pe,nt+4)[0]==0x14c and
         struct.unpack_from('<H',pe,nt+24)[0]==0x10b,'requires PE32 x86')
    count,opt=struct.unpack_from('<H',pe,nt+6)[0],struct.unpack_from('<H',pe,nt+20)[0]
    base=struct.unpack_from('<I',pe,nt+52)[0]
    return base,[struct.unpack_from('<8sIIII',pe,nt+24+opt+40*k) for k in range(count)]


def offset(pe,va,size):
    base,sections=pe_sections(pe)
    matches=[raw_off+va-base-rva for _,virtual,rva,raw,raw_off in sections
             if 0<=va-base-rva and va-base-rva+size<=min(virtual,raw)]
    need(len(matches)==1,'not uniquely raw backed')
    return matches[0]


def native_rows(raw):
    return {int(m[1],16):m[2] for m in re.finditer(r'^([0-9a-fA-F]{8})\s+(.+)$',
            raw.decode('utf-8-sig'),re.M)}


def compare(seq,native):
    for ins in seq:
        need(ins.address in native and normalized(ins.mnemonic+' '+ins.op_str)==normalized(native[ins.address]),
             'PE/native operand mismatch at '+hx(ins.address))


def imports(pe):
    nt=struct.unpack_from('<I',pe,0x3c)[0]
    base,_=pe_sections(pe)
    descriptor=offset(pe,base+struct.unpack_from('<I',pe,nt+24+104)[0],20)
    result={}
    def string(rva):
        pos=offset(pe,base+rva,1)
        return pe[pos:pe.index(b'\0',pos)].decode('ascii')
    while True:
        orig,_,_,name,first=struct.unpack_from('<IIIII',pe,descriptor)
        if not name:
            return result
        n=0
        while True:
            thunk=struct.unpack_from('<I',pe,offset(pe,base+(orig or first)+4*n,4))[0]
            if not thunk:
                break
            if base+first+4*n in (0x9670f8,0x967100):
                need(not thunk&0x80000000,'unexpected ordinal import')
                result[hx(base+first+4*n)]={'dll':string(name),'symbol':string(thunk+2)}
            n+=1
        descriptor+=20


def extract(binary,exports,exports09,exports24,exports25,staff_exports,lifecycle_exports):
    pe=binary.read_bytes()
    need(len(pe)==7192576 and sha(pe)==SPECIMEN,'pinned specimen mismatch')
    need(capstone.__version__=='5.0.7','requires Capstone 5.0.7')
    raw=(exports/'manifest.json').read_bytes()
    need(sha(raw)==MANIFEST,'native manifest mismatch')
    manifest=json.loads(raw)
    need(manifest['specimen_sha256']==SPECIMEN and manifest['source_archive_sha256']==ARCHIVE,
         'native provenance mismatch')
    expected={name+ext for name in ('0062a680','0062a8a0','006dbb80','006e0d00',
               '006eaea0','00828110','0082a9c0','0082ff40') for ext in ('.asm','.c')}
    need(set(manifest['files'])==expected,'native inventory mismatch')
    native={};hashes={}
    for name,meta in manifest['files'].items():
        payload=(exports/name).read_bytes()
        need(len(payload)==meta['bytes'] and sha(payload)==meta['sha256'],'native export mismatch')
        hashes[name]=sha(payload)
        if name.endswith('.asm'):
            native[name[:-4]]=native_rows(payload)
    staff_raw=(staff_exports/'manifest.json').read_bytes()
    need(sha(staff_raw)==STAFF_MANIFEST,'staff manifest mismatch')
    staff_manifest=json.loads(staff_raw)
    need(staff_manifest['specimen_sha256']==SPECIMEN and staff_manifest['source_archive_sha256']==ARCHIVE,
         'staff native provenance mismatch')
    need(set(staff_manifest['files'])=={name+ext for name in ('008968f0','008982b0')
         for ext in ('.asm','.c')},'staff export inventory mismatch')
    for name,meta in staff_manifest['files'].items():
        payload=(staff_exports/name).read_bytes()
        need(len(payload)==meta['bytes'] and sha(payload)==meta['sha256'],'staff export mismatch')
        hashes[name]=sha(payload)
        if name.endswith('.asm'):
            native[name[:-4]]=native_rows(payload)
    lifecycle_raw=(lifecycle_exports/'manifest.json').read_bytes()
    need(sha(lifecycle_raw)==LIFECYCLE_MANIFEST,'lifecycle manifest mismatch')
    lifecycle_manifest=json.loads(lifecycle_raw)
    need(lifecycle_manifest['specimen_sha256']==SPECIMEN and lifecycle_manifest['source_archive_sha256']==ARCHIVE,
         'lifecycle native provenance mismatch')
    need(set(lifecycle_manifest['files'])=={name+ext for name in ('00528080','00528540')
         for ext in ('.asm','.c')},'lifecycle export inventory mismatch')
    for name,meta in lifecycle_manifest['files'].items():
        payload=(lifecycle_exports/name).read_bytes()
        need(len(payload)==meta['bytes'] and sha(payload)==meta['sha256'],'lifecycle export mismatch')
        hashes[name]=sha(payload)
        if name.endswith('.asm'):
            native[name[:-4]]=native_rows(payload)
    for folder,name in ((exports25,'0062ed70.asm'),(exports24,'00944cff.asm'),(exports09,'006cfe10.asm')):
        payload=(folder/name).read_bytes()
        need(sha(payload)==CONTEXT[name],'context export mismatch')
        native[name[:-4]]=native_rows(payload);hashes[name]=sha(payload)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[];decoded={}
    for owner,a,b in RANGES:
        off=offset(pe,a,b-a);body=pe[off:off+b-a];seq=list(md.disasm(body,a))
        need(sum(i.size for i in seq)==b-a,'incomplete selected range')
        compare(seq,native[owner]);decoded.update((i.address,i) for i in seq)
        ranges.append({'owner':owner,'start':hx(a),'end_exclusive':hx(b),'file_offset':hx(off),
                       'bytes':b-a,'sha256':sha(body),'instructions':len(seq),'all_native_operands_match':True})
    # An exhaustive encoded-literal search is narrower than a computed-write census.
    base,sections=pe_sections(pe);text=next(s for s in sections if s[0].rstrip(b'\0')==b'.text')
    _,virtual,rva,size,raw_off=text;needle=struct.pack('<I',0xb63d28);positions=[];writers=set();pos=raw_off
    while True:
        pos=pe.find(needle,pos,raw_off+min(virtual,size))
        if pos<0:
            break
        positions.append(pos)
        for start in range(max(raw_off,pos-6),pos):
            seq=list(md.disasm(pe[start:pos+12],base+rva+start-raw_off,count=1))
            if seq and seq[0].address+seq[0].size>=base+rva+pos-raw_off+4:
                ins=seq[0]
                if any(o.type==capstone.x86.X86_OP_MEM and o.mem.disp==0xb63d28 and
                       not o.mem.base and not o.mem.index and o.access&capstone.CS_AC_WRITE for o in ins.operands):
                    need(ins.address in decoded,'unreviewed encoded global writer')
                    writers.add(ins.address)
        pos+=1
    need(writers=={0x829325,0x82c35b,0x830102},'global encoded writers changed')
    section=next(s for s in sections if base+s[2]<=0xb63d28<base+s[2]+s[1])
    need(0xb63d28-base-section[2]>=section[3],'global acquired raw backing')
    api=imports(pe)
    need(api=={'009670f8':{'dll':'KERNEL32.dll','symbol':'GetLogicalDriveStringsA'},
               '00967100':{'dll':'KERNEL32.dll','symbol':'GetDriveTypeA'}},'constructor imports changed')
    source_off=offset(pe,0x9e7f28,1);source=pe[source_off:pe.index(b'\0',source_off)+1]
    evidence={'unit':'R30-D','specimen_sha256':SPECIMEN,'checkpoint_archive_sha256':ARCHIVE,
      'native_manifest_sha256':MANIFEST,'staff_manifest_sha256':STAFF_MANIFEST,
      'lifecycle_manifest_sha256':LIFECYCLE_MANIFEST,
      'scope':'selected PE/native ranges and direct encoded references; no whole-body upgrade',
      'address_kind':'virtual unless file_offset is explicit','native_export_hashes':hashes,'ranges':ranges,
      'encoded_global_reference_scan':{'text_literal_occurrences':len(positions),'confirmed_direct_absolute_write_sites':sorted(map(hx,writers)),
         'limit':'does not exclude computed-address stores, bulk initialization or alias writes'},
      'global_storage':{'va':'00b63d28','section':'.data','section_va':hx(base+section[2]),
         'section_raw_bytes':section[3],'section_virtual_bytes':section[1],'delta':0xb63d28-base-section[2],
         'raw_backed':False,'loader_initial_value':0,'game_initializer_executed_in_R30_A_B':False},
      'constructor_imports':api,'diagnostic_source':{'va':'009e7f28','nul_inclusive_bytes':len(source),'sha256':sha(source),
         'raw_string_retained':False},'static_only':['global setup and teardown','roster lookup 008968f0','diagnostic and refresh callees']}
    return pe,decoded,native,evidence


def check_producer_call(call,seed,index):
    staff=0x230000+seed*0x80;extra=0x89abcd80|seed
    need(call=={'site':'006e0dde','target':'006eaea0','ecx':0x210000+0x1be*index,
          'arguments':[0x220000,staff,(extra&0xffffff00)|seed,0xa5a50000|index,extra]},
         'producer call ABI mismatch')


def emulate_producer(pe,decoded):
    need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    cases=[]
    for seed in range(4):
        for index in range(20):
            uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
            for start,length in ((0x6e0000,0x1000),(0x6ea000,0x1000),(0x200000,0x1000),
                (0x210000,0x4000),(0x220000,0x1000),(0x230000,0x1000),(0x240000,0x1000),(0x300000,0x2000)):
                uc.mem_map(start,length)
            for a,b in ((0x6e0d00,0x6e0def),(0x6eaea0,0x6eaf46)):
                uc.mem_write(a,pe[offset(pe,a,b-a):offset(pe,a,b-a)+b-a])
            regions=[(0x200000,0x1000),(0x210000,0x4000),(0x220000,0x1000),(0x230000,0x1000),(0x240000,0x1000),(0x300000,0x2000)]
            for a,n in regions:
                uc.mem_write(a,bytes((k*29+seed*17+index)&255 for k in range(n)))
            sp=0x301800;staff=0x230000+seed*0x80;player=0x240000+seed*0x80;slot=0x210000+0x1be*index
            def set32(a,value): uc.mem_write(a,struct.pack('<I',value&0xffffffff))
            set32(0x200023,0x210000);set32(0x200012,0x220000);uc.mem_write(0x200018,bytes([seed]))
            set32(staff+0x61,player)
            raw_index=0xa5a50000|index;extra=0x89abcd80|seed
            need(extra&255!=seed,'synthetic argument bytes must differ')
            for k,value in enumerate((0x700000,raw_index,staff,extra)): set32(sp+4*k,value)
            initial={'eax':0xdeadbeef,'ebx':0x12345678,'ecx':0x200000,'edx':0x87654321,
                     'esi':0x01020304,'edi':0xfeedface,'ebp':0xcafef00d,'esp':sp,'eip':0x6e0d00}
            for name,value in initial.items(): uc.reg_write(REGS[name],value)
            before=[bytes(uc.mem_read(a,n)) for a,n in regions];trace=[];events=[];calls=[]
            def code(machine,a,size,_):
                need(a in decoded,'producer escaped selected instructions');trace.append(hx(a))
                ins=decoded[a]
                if ins.mnemonic=='call':
                    need(a==0x6e0dde and ins.operands[0].imm==0x6eaea0,'unexpected producer call')
                    csp=machine.reg_read(REGS['esp'])
                    calls.append({'site':hx(a),'target':'006eaea0','ecx':machine.reg_read(REGS['ecx']),
                       'arguments':list(struct.unpack('<5I',machine.mem_read(csp,20)))})
            def memory(machine,kind,a,size,value,_):
                need(any(base<=a and a+size<=base+n for base,n in regions),'producer touched unadmitted memory')
                events.append([hx(a),size,'write' if kind==unicorn.UC_MEM_WRITE else 'read'])
            uc.hook_add(unicorn.UC_HOOK_CODE,code)
            uc.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(0x6e0d00,0x6eaf46,count=100)
            need(uc.reg_read(REGS['eip'])==0x6eaf46,'producer failed to reach prefix stop')
            expected=[bytearray(raw) for raw in before]
            d=slot-0x210000
            for at,value in ((0x19e,0x220000),(0x69,staff),(0x6d,player)):
                expected[1][d+at:d+at+4]=struct.pack('<I',value)
            expected[1][d]=index;expected[1][d+0x2e]=extra&255
            # Explicit stack effects of the original wrapper CALL and prefix PUSH/local stores.
            for at,value in ((sp-516,initial['esi']),(sp-520,extra),(sp-524,raw_index),
                (sp-528,(extra&0xffffff00)|seed),(sp-532,staff),(sp-536,0x220000),
                (sp-540,0x6e0de3),(sp-568,initial['ebx']),(sp-572,initial['ebp']),
                (sp-576,staff),(sp-560,0)):
                expected[5][at-0x300000:at-0x300000+4]=struct.pack('<I',value)
            expected[5][sp-561-0x300000]=0
            after=[bytes(uc.mem_read(a,n)) for a,n in regions]
            need(after==list(map(bytes,expected)),'producer full-memory mismatch')
            need(len(calls)==1,'producer call count mismatch')
            check_producer_call(calls[0],seed,index)
            cases.append({'seed':seed,'index':index,'slot':slot,'staff':staff,'attribute_record':player,
                          'stop_before':'006eaf46','function_returned':False,'call':calls[0],
                          'instruction_steps':len(trace),'ordered_event_count':len(events),
                          'trace_sha256':sha(json.dumps(trace,separators=(',',':')).encode()),
                          'events_sha256':sha(json.dumps(events,separators=(',',':')).encode()),
                          'full_memory_sha256':[sha(value) for value in after]})
    return {'unit':'R30-D','specimen_sha256':SPECIMEN,'scope':'80 synthetic original-entry 006e0d00 -> 006eaea0 prefixes; caller-supplied staff+61 nonnull; stop before 006eaf46; no function return or live state claim',
            'cases':cases,'case_count':len(cases),'instruction_steps':sum(c['instruction_steps'] for c in cases)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','exports','exports09','exports24','exports25','staff_exports','lifecycle_exports','output'):
        p.add_argument(name,type=Path)
    a=p.parse_args()
    pe,decoded,native,sites=extract(a.binary,a.exports,a.exports09,a.exports24,a.exports25,a.staff_exports,a.lifecycle_exports)
    oracle=emulate_producer(pe,decoded)
    # Negative gates do not mutate private inputs, and run equally under python -O.
    bad=copy.copy(native['006eaea0']);bad[0x6eaecb]='MOV dword ptr [ESI + 0x6d],EBP'
    try: compare([decoded[0x6eaecb]],bad)
    except ValueError: pass
    else: raise ValueError('resealed native operand admitted')
    result={'sites':sites,'producer_oracle':oracle,'integrity':{'optimized_python':'explicit ValueError gates; no assert',
      'negative_probes':['resealed producer operand rejected'],'privacy':'only compact sites and deterministic synthetic scalars/digests; no PE bytes, source paths or page dumps'}}
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({'unit':'R30-D','selected_ranges':len(RANGES),'producer_cases':oracle['case_count'],'steps':oracle['instruction_steps']}))


if __name__=='__main__':
    main()

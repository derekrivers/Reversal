#!/usr/bin/env python3
"""R31-B: original-entry participant fixture kernels and lifecycle frontiers."""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct

import capstone
import unicorn
from unicorn import x86_const as x86
from extract_status_lookup_25 import normalized

SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
BASELINE='36b44d8701b6abe332bc5a112198a570a8946536'
MANIFESTS={
 'state':'b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a',
 'staff':'c6457fcd1b68d524d2d4ce623d144e77a3e5ae23c9a4699e157b9ec2181f7b35',
 'focused':'27093fe32f6bcf31c94cb78c108eb78b025713c14215cc3602daeb2db57aad68',
 'support':'92d0708d6eada4983366d522314881e04c293b0bfaab4c467eb08f71992d7741'}
ARCHIVES={
 'state':'ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a',
 'staff':'ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a',
 'focused':'f787a4dd87cb0efc9d7b270f8be0656e49d0f5f64738f1d19aab759540936bdd',
 'support':'f787a4dd87cb0efc9d7b270f8be0656e49d0f5f64738f1d19aab759540936bdd'}
INVENTORIES={'state':('006eaea0','006e0d00','006dbb80','0062a680','0062a8a0','00828110','0082a9c0','0082ff40'),
 'staff':('008968f0','008982b0'),'focused':('00600a50','005409b0','0053b900','0053b3d0','0062c680'),
 'support':('0054a110','0094627a','0094620d')}
CONTEXT_HASH='9b0bd12347e822108343cd47f26cfd81f47a577075c6463f853bde53cefd476e'
RANGES={0x8968f0:414,0x8982b0:317,0x600a50:568,0x5409b0:156,0x53b900:159,
 0x6e0d00:239,0x6eaea0:0x6eaf77-0x6eaea0,0x62ed70:187,
 0x62c680:0x62c6da-0x62c680,0x54a110:21,0x94627a:18,
 0x94620d:0x946219-0x94620d,0x62a680:0x62a6b7-0x62a680}
REGS={name:getattr(x86,'UC_X86_REG_'+name.upper())
      for name in ('eax','ebx','ecx','edx','esi','edi','ebp','esp','eip')}
SP,STOP=0x308000,0x700000
DATA_REGIONS={'tactics':(0x200000,0x1000),'rows':(0x210000,0x1000),
 'club':(0x220000,0x1000),'staff':(0x230000,0x2000),'attributes':(0x240000,0x1000),
 'match':(0x250000,0x10000),'manager':(0x260000,0x1000),'slots':(0x280000,0x4000),
 'constructor_storage':(0x290000,0x1000),'stack':(0x300000,0x10000),
 'database_globals':(0xae2000,0x1000),'owner_globals':(0xae1000,0x1000),
 'status_globals':(0xb63000,0x1000),'crt_globals':(0xde4000,0x1000),'seh':(0,0x1000)}
SCRATCH={'eax':0xdeadbeef,'ebx':0x12345678,'ecx':0,'edx':0x87654321,
         'esi':0x01020304,'edi':0xfeedface,'ebp':0xcafef00d,'esp':SP,'eip':0}
ARG_COUNTS={0x8982b0:2,0x600a50:5,0x5409b0:1,0x53b900:1,0x6eaea0:5,
            0x62c680:1,0x54a110:0,0x94627a:1,0x94620d:1}


def need(ok,message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(value):
    return f'{value:08x}'


def pe_sections(pe):
    nt=struct.unpack_from('<I',pe,0x3c)[0]
    need(pe[:2]==b'MZ' and pe[nt:nt+4]==b'PE\0\0','invalid PE')
    need(struct.unpack_from('<H',pe,nt+4)[0]==0x14c and struct.unpack_from('<H',pe,nt+24)[0]==0x10b,'not PE32 x86')
    count,opt=struct.unpack_from('<H',pe,nt+6)[0],struct.unpack_from('<H',pe,nt+20)[0]
    base=struct.unpack_from('<I',pe,nt+52)[0]
    return base,[struct.unpack_from('<8sIIII',pe,nt+24+opt+40*k) for k in range(count)]


def offset(pe,va,size):
    base,sections=pe_sections(pe)
    matches=[raw_off+va-base-rva for _,virtual,rva,raw,raw_off in sections
             if 0<=va-base-rva and va-base-rva+size<=min(virtual,raw)]
    need(len(matches)==1,'not uniquely PE raw backed')
    return matches[0]


def rows(raw):
    return {int(m[1],16):m[2] for m in re.finditer(r'^([0-9a-fA-F]{8})\s+(.+)$',raw.decode('utf-8-sig'),re.M)}


def compare(seq,native):
    def canonical(value):
        value=normalized(value)
        return re.sub(r'^(mov(?:al|bl|cl|dl),)byteptr(?=\[)',r'\1',value)
    for ins in seq:
        need(ins.address in native and canonical(ins.mnemonic+' '+ins.op_str)==canonical(native[ins.address]),
             'PE/native operand mismatch '+hx(ins.address))


def constructor_imports(pe):
    nt=struct.unpack_from('<I',pe,0x3c)[0];base,_=pe_sections(pe)
    descriptor=offset(pe,base+struct.unpack_from('<I',pe,nt+24+104)[0],20);result={}
    def string(rva):
        pos=offset(pe,base+rva,1)
        return pe[pos:pe.index(b'\0',pos)].decode('ascii')
    while True:
        original,_,_,name,first=struct.unpack_from('<IIIII',pe,descriptor)
        if not name:
            break
        n=0
        while True:
            value=struct.unpack_from('<I',pe,offset(pe,base+(original or first)+4*n,4))[0]
            if not value:
                break
            if base+first+4*n in (0x9670f8,0x967100):
                need(not value&0x80000000,'unexpected ordinal import')
                result[hx(base+first+4*n)]={'dll':string(name),'symbol':string(value+2)}
            n+=1
        descriptor+=20
    need(result=={'009670f8':{'dll':'KERNEL32.dll','symbol':'GetLogicalDriveStringsA'},
                  '00967100':{'dll':'KERNEL32.dll','symbol':'GetDriveTypeA'}},'constructor imports changed')
    return result


def extract(a):
    pe=a.binary.read_bytes()
    need(len(pe)==7192576 and sha(pe)==SPECIMEN,'pinned specimen mismatch')
    need(capstone.__version__=='5.0.7','requires Capstone 5.0.7')
    native={};export_hashes={}
    for group,pinned in MANIFESTS.items():
        folder=getattr(a,group);raw=(folder/'manifest.json').read_bytes()
        need(sha(raw)==pinned,'manifest mismatch '+group)
        manifest=json.loads(raw)
        need(manifest['specimen_sha256']==SPECIMEN and manifest['source_archive_sha256']==ARCHIVES[group],
             'native provenance mismatch '+group)
        need(set(manifest['files'])=={name+ext for name in INVENTORIES[group] for ext in ('.asm','.c')},
             'native inventory mismatch '+group)
        for name,meta in manifest['files'].items():
            raw=(folder/name).read_bytes()
            need(len(raw)==meta['bytes'] and sha(raw)==meta['sha256'],'native export mismatch '+name)
            export_hashes[group+'/'+name]=sha(raw)
            if name.endswith('.asm'):
                native[int(name[:-4],16)]=rows(raw)
    raw=(a.exports25/'0062ed70.asm').read_bytes()
    need(sha(raw)==CONTEXT_HASH,'status context hash mismatch')
    native[0x62ed70]=rows(raw);export_hashes['exports25/0062ed70.asm']=sha(raw)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    decoded={};sites=[]
    for start,size in RANGES.items():
        off=offset(pe,start,size);body=pe[off:off+size];seq=list(md.disasm(body,start))
        need(sum(i.size for i in seq)==size,'incomplete range')
        compare(seq,native[start]);decoded.update((i.address,i) for i in seq)
        sites.append({'entry':hx(start),'end_exclusive':hx(start+size),'file_offset':hx(off),
                     'bytes':size,'sha256':sha(body),'instructions':len(seq),'all_native_operands_match':True})
    base,sections=pe_sections(pe)
    unbacked={}
    for va in (0xb63d28,0xb63d10,0xde4634,0xde4638):
        section=next(s for s in sections if base+s[2]<=va<base+s[2]+s[1])
        need(va-base-section[2]>=section[3],'process global unexpectedly raw backed')
        unbacked[hx(va)]={'loader_zero':True,'game_initializer_executed':False}
    return pe,decoded,native,{'unit':'R31-B','baseline_commit':BASELINE,'specimen_sha256':SPECIMEN,
       'manifest_sha256':MANIFESTS,'source_archive_sha256':ARCHIVES,'export_hashes':export_hashes,
       'ranges':sites,'zero_tail_globals':unbacked,'constructor_imports':constructor_imports(pe),
       'scope':'bounded lookup and initialization frontiers; no new whole-body register, live database or match claim'}


class Machine:
    def __init__(self,pe,decoded,seed):
        self.uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32);self.decoded=decoded;self.current=0
        pages={i.address&~0xfff for i in decoded.values()}
        pages|={0x967000,STOP}
        for page in sorted(pages): self.uc.mem_map(page,0x1000)
        for start,size in RANGES.items(): self.uc.mem_write(start,pe[offset(pe,start,size):offset(pe,start,size)+size])
        # Preserve the on-disk IAT page, but stop before calling an unresolved import.
        self.uc.mem_write(0x967000,pe[offset(pe,0x967000,0x1000):offset(pe,0x967000,0x1000)+0x1000])
        for name,(start,size) in DATA_REGIONS.items():
            self.uc.mem_map(start,size)
            self.uc.mem_write(start,bytes((k*13+seed*17)&255 for k in range(size)) if name in
                              ('rows','staff','attributes','slots','stack','constructor_storage') else bytes(size))
        self.set32(0,0x13579bdf)

    def set32(self,address,value): self.uc.mem_write(address,struct.pack('<I',value&0xffffffff))
    def word(self,address): return struct.unpack('<I',self.uc.mem_read(address,4))[0]
    def snapshots(self): return {name:bytes(self.uc.mem_read(start,size)) for name,(start,size) in DATA_REGIONS.items()}
    def registers(self): return {name:self.uc.reg_read(reg) for name,reg in REGS.items()}

    def entry(self,address,receiver,args):
        initial=dict(SCRATCH,ecx=receiver,esp=SP,eip=address)
        for name,value in initial.items(): self.uc.reg_write(REGS[name],value)
        self.uc.reg_write(x86.UC_X86_REG_EFLAGS,0x202)
        for k,value in enumerate((STOP,*args)): self.set32(SP+4*k,value)
        return initial

    def run(self,entry,stop,allowed_calls):
        trace=[];events=[];calls=[];frames=[]
        def code(machine,address,size,_):
            need(address in self.decoded,'unadmitted instruction '+hx(address))
            self.current=address;trace.append(hx(address));need(len(trace)<=1000,'instruction budget exceeded')
            ins=self.decoded[address]
            if ins.mnemonic=='call':
                need(ins.operands[0].type==capstone.x86.X86_OP_IMM,'executed unresolved import')
                target=ins.operands[0].imm
                need((address,target) in allowed_calls,'unsupported executed call '+hx(address))
                calls.append([hx(address),hx(target)])
                sp=machine.reg_read(REGS['esp'])
                frames.append({'site':hx(address),'target':hx(target),'ecx':machine.reg_read(REGS['ecx']),
                               'arguments':[self.word(sp+4*k) for k in range(ARG_COUNTS[target])]})
        def memory(machine,kind,address,size,value,_):
            need(any(base<=address and address+size<=base+n for base,n in DATA_REGIONS.values()) or
                 0x967000<=address and address+size<=0x968000,'unadmitted data memory '+hx(address))
            need(kind!=unicorn.UC_MEM_WRITE or not 0x967000<=address<0x968000,'write to original IAT page')
            events.append([hx(self.current),'write' if kind==unicorn.UC_MEM_WRITE else 'read',hx(address),size])
        hooks=[self.uc.hook_add(unicorn.UC_HOOK_CODE,code),
               self.uc.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        before=self.snapshots()
        try: self.uc.emu_start(entry,stop,count=1000)
        finally:
            for hook in hooks: self.uc.hook_del(hook)
        need(self.uc.reg_read(REGS['eip'])==stop,'entry failed to reach stop')
        after=self.snapshots()
        return before,after,{'entry':hx(entry),'stop':hx(stop),'calls':calls,'call_frames':frames,'instruction_steps':len(trace),
             'ordered_memory_events':len(events),'trace_sha256':sha(compact(trace)),
             'events_sha256':sha(compact(events)),'before_memory_sha256':{k:sha(v) for k,v in before.items()},
             'after_memory_sha256':{k:sha(v) for k,v in after.items()}},events


def compact(value): return json.dumps(value,separators=(',',':')).encode()


def pack(value):
    output=io.BytesIO()
    with gzip.GzipFile(fileobj=output,filename='',mode='wb',mtime=0) as stream:
        stream.write(compact(value)+b'\n')
    return output.getvalue()


def privacy_check(raw,pe):
    need(len(raw)<=300000,'compressed evidence size limit')
    samples=[pe[offset(pe,start,min(32,size)):offset(pe,start,min(32,size))+min(32,size)]
             for start,size in RANGES.items()]
    pos=offset(pe,0x9e7f28,1);samples.append(pe[pos:pe.index(b'\0',pos)])
    forms=[value for sample in samples for value in (sample,sample.hex().encode(),base64.b64encode(sample))]
    need(not any(value in raw for value in forms),'private fragment in compressed evidence')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        expanded=stream.read(2000001)
    need(len(expanded)<=2000000,'expanded evidence size limit')
    need(not any(value in expanded for value in forms),'private fragment in expanded evidence')
    value=json.loads(expanded)
    need(pack(value)==raw,'noncanonical evidence gzip/JSON')
    return value


def expected_data(before,after,changes):
    expected={name:bytearray(raw) for name,raw in before.items()}
    for address,width,value in changes:
        region=next(name for name,(base,size) in DATA_REGIONS.items() if base<=address and address+width<=base+size)
        at=address-DATA_REGIONS[region][0]
        expected[region][at:at+width]=value.to_bytes(width,'little')
    for name in expected:
        if name!='stack': need(bytes(expected[name])==after[name],'complete nonstack memory mismatch '+name)


LOOKUP_CALLS={(0x89695c,0x8982b0),(0x8982c8,0x600a50),(0x600be6,0x5409b0),(0x8969cb,0x53b900)}
STATUS_CALLS={(0x62edfc,0x62c680),(0x62c6c8,0x54a110),(0x62c6d2,0x94627a),(0x94627e,0x94620d)}


def produce(pe,decoded):
    need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    cases=[]
    for club_id in range(4):
        for index in range(20):
            for nonnull_attribute in (True,False):
                m=Machine(pe,decoded,club_id);staff_id=(club_id*11+index)%32
                staff=0x230000+staff_id*0x6e;attribute=0x240000+staff_id*0x46
                cell=0x210000+0x91*club_id+2+4*index
                for address,value in ((0x200601,0x210000),(0x220000,club_id),(0x2200cf,0),
                    (0xae2350,1),(0xae235c,8),(0xae2364,64),(0xae23bc,0x230000),
                    (cell,staff_id),(staff,staff_id),(staff+0x61,attribute if nonnull_attribute else 0)):
                    m.set32(address,value)
                m.uc.mem_write(attribute+0x45,bytes([40+club_id]))
                initial=m.entry(0x8968f0,0x200000,[0x220000,0xa5a50000|index,0])
                before,after,lookup,_=m.run(0x8968f0,STOP,LOOKUP_CALLS)
                final=m.registers();returned=staff if nonnull_attribute else 0
                need(final['eax']==returned and final['esp']==SP+16,'lookup result/RET ABI mismatch')
                need(all(final[r]==initial[r] for r in ('ebx','esi','edi','ebp')),'lookup nonvolatile ABI mismatch')
                expected_data(before,after,[] if nonnull_attribute else [(cell,4,0xffffffff)])
                lookup.update(returned_record=returned,initial_registers=initial,final_registers=final)
                case={'club_id':club_id,'index':index,'staff_id':staff_id,'attribute_nonnull':nonnull_attribute,
                      'table_cell':cell,'lookup':lookup}
                if nonnull_attribute:
                    # A separate fixture-builder entry consumes the actual original lookup result.
                    # It does not claim execution of the game's enclosing caller 006dbb80.
                    m.set32(0x260023,0x280000);m.set32(0x260012,0x250000)
                    m.uc.mem_write(0x260018,bytes([club_id]))
                    extra=0x89abcd80|club_id
                    m.entry(0x6e0d00,0x260000,[0xa5a50000|index,returned,extra])
                    before,after,placement,_=m.run(0x6e0d00,0x6eaf77,{(0x6e0dde,0x6eaea0)})
                    slot=0x280000+0x1be*index
                    need(placement['call_frames']==[{'site':'006e0dde','target':'006eaea0','ecx':slot,
                         'arguments':[0x250000,returned,0x89abcd00|club_id,0xa5a50000|index,extra]}],
                         'placement argument provenance mismatch')
                    expected_data(before,after,[(slot+0x19e,4,0x250000),(slot+0x69,4,returned),
                       (slot+0x6d,4,attribute),(slot,1,index),(slot+0x2e,1,extra&255),(slot+0x17,1,40+club_id)])
                    placement.update(slot=slot,staff_alias=m.word(slot+0x69),attribute_alias=m.word(slot+0x6d),
                       function_returned=False,stop_reason='next read 006eaf77 requires pre-existing slot+27 side byte')
                    case['placement']=placement
                # The lookup global and static-init flags retain the original loader-zero state.
                need(m.word(0xb63d28)==0 and m.uc.mem_read(0xb63d10,1)==b'\0','process initialization was invented')
                m.entry(0x62ed70,0,[returned])
                stop=0x946214 if returned else 0x62ed99
                before,after,status,_=m.run(0x62ed70,stop,STATUS_CALLS)
                changes=[]
                if returned:
                    changes=[(0xb63d10,1,1),(0xb63d08,2,40),(0xb63d0a,2,1972),(0xb63d0c,4,1),(0,4,SP-540)]
                    need(m.word(m.uc.reg_read(REGS['esp']))==0,'exit-list base argument is not loader zero')
                    need(status['calls']==[[hx(a),hx(b)] for a,b in
                         ((0x62edfc,0x62c680),(0x62c6c8,0x54a110),(0x62c6d2,0x94627a),(0x94627e,0x94620d))],
                         'normal status call order changed')
                    status.update(stop_reason='before 00946214 -> 0094bef1 with exit-list base 00de4638=0',
                                  unsupported_argument=0,lookup_global=0,record_argument=returned)
                else:
                    out=[m.word(m.uc.reg_read(REGS['esp'])+4*k) for k in range(5)]
                    need(out==[0x9e7f28,0,0,SP-256,SP-512],'null diagnostic argument frame changed')
                    need(status['calls']==[],'null diagnostic unexpectedly called a helper')
                    status.update(stop_reason='before 0062ed99 -> 00944cff; null record diagnostic preserved',
                                  diagnostic_arguments=out,lookup_global=0,record_argument=0)
                expected_data(before,after,changes)
                status['function_returned']=False;case['status']=status;cases.append(case)
    constructors=[]
    for mode in ('new','load_argument'):
        for seed in range(4):
            m=Machine(pe,decoded,seed);receiver=0x290000+seed*0x40
            supplied=0 if mode=='new' else 0x2a0000+seed*0x100
            m.entry(0x62a680,receiver,[supplied])
            before,after,row,_=m.run(0x62a680,0x62a6b1,set())
            need(m.uc.reg_read(REGS['ebp'])==receiver,'constructor receiver save changed')
            outgoing=[m.word(m.uc.reg_read(REGS['esp'])+4*k) for k in range(2)]
            need(outgoing==[200,SP-0x67c],'drive-query argument frame changed')
            expected_data(before,after,[(0,4,SP-12)])
            row.update(mode=mode,seed=seed,receiver=receiver,entry_argument=supplied,arguments=outgoing,
                       stop_reason='before IAT009670f8 GetLogicalDriveStringsA; unresolved on-disk imports never called',
                       function_returned=False,lookup_global=m.word(0xb63d28))
            need(row['lookup_global']==0,'constructor published a fabricated global')
            constructors.append(row)
    return {'unit':'R31-B','specimen_sha256':SPECIMEN,'synthetic_only':True,
      'pipeline_scope':'separate original function entries consume actual returned lookup pointer; no enclosing game caller or live initialization claim',
      'cases':cases,'constructor_frontiers':constructors,
      'coverage':{'lookup_returns':len(cases),'nonnull_returns':80,'null_attribute_returns':80,
        'placement_frontiers':80,'normal_status_frontiers':80,'null_diagnostic_frontiers':80,'constructor_os_frontiers':8,
        'instruction_steps':sum(c['lookup']['instruction_steps']+c['status']['instruction_steps']+
           (c['placement']['instruction_steps'] if 'placement' in c else 0) for c in cases)+
           sum(c['instruction_steps'] for c in constructors)}}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','state','staff','focused','support','exports25','output'):
        p.add_argument(name,type=Path)
    return p


def generate(a):
    pe,decoded,_,sites=extract(a)
    return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a)
    a.output.write_bytes(pack(result))
    print(json.dumps(result['oracle']['coverage']))

#!/usr/bin/env python3
"""R35-C: selector entry initialization through its first Windows import."""
import argparse
import json
from pathlib import Path
import struct
import capstone
import unicorn
from unicorn import x86_const as x86
import extract_action33_lifecycle_31 as life
import extract_action33_owner_33 as owner
import extract_action33_slot_32 as slot

BASELINE='eabc39b443d18ca59c88c211c65b5ea5d089ed52'
SCOPE='original selector entry to pending HeapSize import; no selection, RNG, fixture or prepare-match execution'
PINS={'focused':owner.OWNER_MANIFEST,'slot':slot.SLOT_MANIFEST,'support':life.MANIFESTS['support'],
      'state':life.MANIFESTS['state']}
# None denotes PE-only decoding, explicitly distinct from native operand checks.
RANGES={0x84be20:(0x84c4fc,'focused',0x84be20),
        0x9463af:(0x946419,'slot',0x9463af),0x946419:(0x946431,'slot',0x946419),
        0x94627a:(0x94628c,'support',0x94627a),0x94620d:(0x946219,'support',0x94620d),
        0x54a110:(0x54a125,'support',0x54a110),
        0x453c30:(0x453c4e,None,None),0x453c50:(0x453c5f,None,None),
        0x94bef1:(0x94bf52,None,None),
        0x5cdac3:(0x5cdace,None,None),0x54cfb0:(0x54cfde,None,None),
        0x829dfc:(0x829e33,'state',0x828110),0x82cb18:(0x82cb4d,'state',0x82a9c0),
        0x830464:(0x830484,'state',0x82ff40)}
REGIONS={'stack':(0x300000,0x10000),'seh':(0,0x1000),
         'selector_globals':(0xdd7000,0x2000),'crt_globals':(0xde4000,0x1000)}
SP=0x308000
ARGS={0x84be20:0,0x9463af:5,0x453c30:0,0x453c50:0,0x54a110:0,0x946419:0,
      0x94627a:1,0x94620d:1,0x94bef1:1}
CALLS={(0x5cdac9,0x84be20),(0x84be6f,0x9463af),(0x9463ea,0x453c30),
       (0x453c45,0x9463af),(0x9463ea,0x453c50),(0x453c56,0x54a110),
       (0x946403,0x946419),(0x84be79,0x94627a),(0x94627e,0x94620d),(0x946214,0x94bef1)}


def heap_import(pe):
    nt=struct.unpack_from('<I',pe,0x3c)[0];base,_=life.pe_sections(pe)
    descriptor=life.offset(pe,base+struct.unpack_from('<I',pe,nt+24+104)[0],20)
    def string(rva):
        at=life.offset(pe,base+rva,1)
        return pe[at:pe.index(b'\0',at)].decode('ascii')
    while True:
        original,_,_,name,first=struct.unpack_from('<IIIII',pe,descriptor)
        life.need(name!=0,'missing HeapSize import')
        for index in range(4096):
            value=struct.unpack_from('<I',pe,life.offset(pe,base+(original or first)+4*index,4))[0]
            if not value:break
            if base+first+4*index==0x9670dc:
                life.need(not value&0x80000000,'unexpected ordinal import')
                result={'iat':'009670dc','dll':string(name),'symbol':string(value+2)}
                life.need(result=={'iat':'009670dc','dll':'KERNEL32.dll','symbol':'HeapSize'},'unexpected heap import')
                return result
        descriptor+=20


def extract(a):
    pe=a.binary.read_bytes();life.need(len(pe)==7192576 and life.sha(pe)==life.SPECIMEN,'pinned specimen mismatch')
    life.need(capstone.__version__=='5.0.7','requires Capstone 5.0.7')
    native={};hashes={}
    for group,pin in PINS.items():
        folder=getattr(a,group);raw=(folder/'manifest.json').read_bytes()
        life.need(life.sha(raw)==pin,'manifest mismatch '+group)
        manifest=json.loads(raw);life.need(manifest['specimen_sha256']==life.SPECIMEN,'native specimen mismatch')
        archive=manifest.get('source_checkpoint_archive_sha256',manifest.get('source_archive_sha256'))
        life.need(archive==life.ARCHIVES['state' if group=='state' else 'focused'],'native archive mismatch')
        hashes[group]={}
        for name,meta in manifest['files'].items():
            raw=(folder/name).read_bytes()
            life.need(len(raw)==meta['bytes'] and life.sha(raw)==meta['sha256'],'native file mismatch '+name)
            hashes[group][name]=life.sha(raw)
            if name.endswith('.asm'):native[group,int(name[:-4],16)]=life.rows(raw)
    life.need((a.focused/'0084be20.refs').read_text().splitlines()==['005cdac9 UNCONDITIONAL_CALL caller=005cccd0'],'selector refs mismatch')
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    decoded={};ranges=[]
    for start,(end,group,parent) in RANGES.items():
        off=life.offset(pe,start,end-start);body=pe[off:off+end-start];seq=list(md.disasm(body,start))
        life.need(sum(i.size for i in seq)==len(body),'incomplete decoded range '+life.hx(start))
        if group:life.compare(seq,native[group,parent])
        decoded.update((i.address,i) for i in seq)
        ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(end),'file_offset':life.hx(off),
                       'bytes':len(body),'sha256':life.sha(body),'instructions':len(seq),
                       'validation':'PE/native operands' if group else 'pinned PE decoding only'})
    # Full-width global loader facts are checked against the PE's virtual tail.
    base,sections=life.pe_sections(pe)
    for va in (0xdd7160,0xdd7287,0xdd7ee4,0xde4400,0xde4404,0xde4634,0xde4638):
        section=next(s for s in sections if base+s[2]<=va<base+s[2]+s[1])
        life.need(va-base-section[2]>=section[3],'global unexpectedly raw backed')
    return pe,decoded,{'unit':'R35-C','baseline_commit':BASELINE,'specimen_sha256':life.SPECIMEN,
        'scope':SCOPE,'manifest_sha256':PINS,'export_hashes':hashes,'ranges':ranges,
        'direct_caller':{'site':'005cdac9','parent':'005cccd0','receiver_load':'005cdac3','global':'00dd7ee4'},
        'zero_tail_globals':['00dd7160','00dd7287','00dd7ee4','00de4400','00de4404','00de4634','00de4638'],
        'heap_import':heap_import(pe)}


def produce(pe,decoded):
    life.need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    cases=[]
    for seed in range(4):
        for entry in (0x84be20,0x5cdac3):
            uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32)
            for page in sorted({address&~0xfff for address in decoded}):uc.mem_map(page,0x1000)
            for start,(end,_,_) in RANGES.items():uc.mem_write(start,pe[life.offset(pe,start,end-start):life.offset(pe,start,end-start)+end-start])
            for name,(base,size) in REGIONS.items():
                uc.mem_map(base,size);uc.mem_write(base,bytes((k*13+seed*17)&255 for k in range(size)) if name=='stack' else bytes(size))
            def put(address,value):uc.mem_write(address,struct.pack('<I',value&0xffffffff))
            def word(address):return struct.unpack('<I',uc.mem_read(address,4))[0]
            put(0,0x13579bdf);put(SP,0x700000)
            initial=dict(life.SCRATCH,ecx=0,esp=SP,eip=entry)
            for name,value in initial.items():uc.reg_write(life.REGS[name],value)
            uc.reg_write(x86.UC_X86_REG_EFLAGS,0x202)
            before={n:bytes(uc.mem_read(b,s)) for n,(b,s) in REGIONS.items()}
            trace=[];events=[];frames=[];current=[0]
            def code(machine,address,size,_):
                life.need(address in decoded,'unadmitted instruction');current[0]=address
                trace.append(life.hx(address));life.need(len(trace)<=4000,'instruction budget exceeded')
                ins=decoded[address]
                if ins.mnemonic=='call':
                    if ins.operands[0].type==capstone.x86.X86_OP_IMM:target=ins.operands[0].imm
                    else:
                        life.need(address==0x9463ea and ins.op_str=='dword ptr [ebp + 0x14]','unadmitted indirect call')
                        target=word(machine.reg_read(life.REGS['ebp'])+0x14)
                    life.need((address,target) in CALLS,'unsupported call '+life.hx(address))
                    sp=machine.reg_read(life.REGS['esp'])
                    frames.append({'site':life.hx(address),'target':life.hx(target),'ecx':machine.reg_read(life.REGS['ecx']),
                                   'arguments':[word(sp+4*k) for k in range(ARGS[target])]})
            def memory(machine,kind,address,size,value,_):
                life.need(any(b<=address and address+size<=b+s for b,s in REGIONS.values()),'unadmitted memory '+life.hx(address))
                events.append([life.hx(current[0]),'write' if kind==unicorn.UC_MEM_WRITE else 'read',life.hx(address),size])
            uc.hook_add(unicorn.UC_HOOK_CODE,code);uc.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)
            uc.emu_start(entry,0x94bf49,count=4000)
            life.need(uc.reg_read(life.REGS['eip'])==0x94bf49,'failed to reach HeapSize stop')
            after={n:bytes(uc.mem_read(b,s)) for n,(b,s) in REGIONS.items()}
            expected=bytearray(before['selector_globals']);expected[0x160]=1
            dates=[]
            for object_index in range(2):
                for index in range(20):
                    address=0xdd7287+object_index*0x625+0x71+index*0x49+0x14
                    dates.append(address)
                    at=address-0xdd7000;expected[at:at+8]=struct.pack('<HHI',40,1972,1)
            life.need(after['selector_globals']==bytes(expected),'complete selector globals mismatch')
            life.need(after['crt_globals']==before['crt_globals'],'CRT globals changed before boundary')
            seh=bytearray(before['seh']);seh[:4]=struct.pack('<I',SP-(16 if entry==0x5cdac3 else 12))
            life.need(after['seh']==bytes(seh),'pending selector SEH mismatch')
            callbacks=[f for f in frames if f['target']=='00453c50']
            life.need([f['ecx']+0x14 for f in callbacks]==dates,'callback order mismatch')
            life.need(len([f for f in frames if f['target']=='00453c30'])==2,'outer constructor count mismatch')
            date_writes=[event for event in events if event[0] in ('0054a112','0054a117','0054a11d')]
            life.need(date_writes==[[site,'write',life.hx(address+offset),width] for address in dates
                      for site,offset,width in (('0054a112',0,2),('0054a117',2,2),('0054a11d',4,4))],
                      'ordered date write widths mismatch')
            sp=uc.reg_read(life.REGS['esp'])
            life.need([word(sp+4*k) for k in range(3)]==[0,0,0] and word(0xde4638)==0,'next heap arguments mismatch')
            life.need(all(int(address,16)<0x84be81 or int(address,16)>0x84c4fb for address in trace),'selection unexpectedly executed')
            cases.append({'seed':seed,'entry':life.hx(entry),'selector_function_entry_executed':True,
                'caller_interior_window':entry==0x5cdac3,'receiver':0,'stop':'0094bf49',
                'instruction_steps':len(trace),'trace_sha256':life.sha(life.compact(trace)),
                'events_sha256':life.sha(life.compact(events)),'memory_events':len(events),'call_frames':frames,
                'produced_date_addresses':dates,'date_writes':date_writes,'static_flag':1,'receiver_global':word(0xdd7ee4),
                'next_call':{'site':'0094bf49','iat':'009670dc','dll':'KERNEL32.dll','symbol':'HeapSize',
                             'arguments':[word(sp+4*k) for k in range(3)],'executed':False},
                'before_memory_sha256':{n:life.sha(v) for n,v in before.items()},
                'after_memory_sha256':{n:life.sha(v) for n,v in after.items()},
                'final_registers':{n:uc.reg_read(r) for n,r in life.REGS.items()},
                'rng_calls':0,'fixture_produced':False,'function_returned':False})
    return {'unit':'R35-C','scope':SCOPE,'specimen_sha256':life.SPECIMEN,'synthetic_harness':True,
        'cases':cases,'coverage':{'selector_entries':8,'caller_interior_windows':4,
        'produced_date_initializers':320,'instruction_steps':sum(c['instruction_steps'] for c in cases)}}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','focused','slot','support','state','output'):p.add_argument(name,type=Path)
    return p


def generate(a):
    pe,decoded,sites=extract(a)
    return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.write_bytes(life.pack(result))
    print(json.dumps(result['oracle']['coverage']))

#!/usr/bin/env python3
"""R36-C: original selector constructor and caller allocation OS frontiers."""
import argparse
import json
from pathlib import Path
import struct
import capstone
import unicorn
from unicorn import x86_const as x86
import extract_action33_lifecycle_31 as life

BASELINE='7cd9b45c567654aac3aca99080dea80d03652785'
SCOPE='separate constructor entries, original flag-store window and caller allocation interiors; no initialized receiver, rows or selector join'
PINS={'native':'2191fbb3b4e60caf51ab80f614588ecd478aab6220f9de0ddd3bbabc02d1612d','state':life.MANIFESTS['state']}
RANGES={0x84b940:(0x84be09,'native',0x84b940),0x84be10:(0x84be1f,'native',0x84be10),
        0x84c510:(0x84c673,'native',0x84c510),0x81ba8d:(0x81ba97,'native',0x81b890),
        0x829dfc:(0x829e33,'state',0x828110),0x82cb18:(0x82cb4d,'state',0x82a9c0),
        0x830464:(0x830484,'state',0x82ff40),0x5d5d58:(0x5d5da1,None,None),
        0x944cf1:(0x944cff,None,None),0x944e46:(0x944e58,None,None),
        0x944e58:(0x944e84,None,None),0x944e84:(0x944ef8,None,None)}
REGIONS={'receiver':(0x200000,0x1000),'stack':(0x300000,0x10000),
         'database_globals':(0xae2000,0x1000),'selector_globals':(0xdd7000,0x2000),
         'crt_globals':(0xde3000,0x2000)}
SP=0x308000
CALLER_ENTRIES=(0x829dfc,0x82cb18,0x5d5d58)
ARGS={0x944cf1:1,0x944e46:1,0x944e58:2,0x944e84:1}
CALLS={(0x829dfe,0x944cf1),(0x82cb1a,0x944cf1),(0x5d5d74,0x944cf1),
       (0x944cf7,0x944e58),(0x944e50,0x944e58),(0x944e63,0x944e84),(0x84ba81,0x944e46)}


def imports(pe):
    expected={0x9670f8:'GetLogicalDriveStringsA',0x967100:'GetDriveTypeA',0x967154:'HeapAlloc'}
    nt=struct.unpack_from('<I',pe,0x3c)[0];base,_=life.pe_sections(pe)
    descriptor=life.offset(pe,base+struct.unpack_from('<I',pe,nt+24+104)[0],20);result={}
    def string(rva):
        at=life.offset(pe,base+rva,1)
        return pe[at:pe.index(b'\0',at)].decode('ascii')
    while True:
        original,_,_,name,first=struct.unpack_from('<IIIII',pe,descriptor)
        if not name:break
        for index in range(4096):
            value=struct.unpack_from('<I',pe,life.offset(pe,base+(original or first)+4*index,4))[0]
            if not value:break
            iat=base+first+4*index
            if iat in expected:
                life.need(not value&0x80000000,'unexpected ordinal import')
                result[life.hx(iat)]={'dll':string(name),'symbol':string(value+2)}
        descriptor+=20
    life.need(result=={life.hx(iat):{'dll':'KERNEL32.dll','symbol':name} for iat,name in expected.items()},'unexpected imports')
    return result


def extract(a):
    pe=a.binary.read_bytes();life.need(len(pe)==7192576 and life.sha(pe)==life.SPECIMEN,'pinned specimen mismatch')
    life.need(capstone.__version__=='5.0.7','requires Capstone 5.0.7')
    native={};hashes={};sources={}
    for group,pin in PINS.items():
        folder=getattr(a,group);raw=(folder/'manifest.json').read_bytes()
        life.need(life.sha(raw)==pin,'manifest mismatch '+group)
        manifest=json.loads(raw);life.need(manifest['specimen_sha256']==life.SPECIMEN,'native specimen mismatch')
        if group=='state':life.need(manifest['source_archive_sha256']==life.ARCHIVES['state'],'native archive mismatch')
        else:life.need(manifest['source']=='checkpoint-29 disposable read-only Ghidra 12.1.4','native source mismatch')
        hashes[group]={};sources[group]={k:v for k,v in manifest.items() if k!='files'}
        for name,meta in manifest['files'].items():
            raw=(folder/name).read_bytes();digest=meta if isinstance(meta,str) else meta['sha256']
            life.need(life.sha(raw)==digest and (isinstance(meta,str) or len(raw)==meta['bytes']),'native file mismatch '+name)
            hashes[group][name]=life.sha(raw)
            if name.endswith('.asm'):native[group,int(name[:-4],16)]=life.rows(raw)
    life.need(set((a.native/'0084b940.refs').read_text().splitlines())=={
        '005d5d93 UNCONDITIONAL_CALL caller=005d5ae0','00829e1c UNCONDITIONAL_CALL caller=00828110',
        '0082cb35 UNCONDITIONAL_CALL caller=0082a9c0'},'constructor refs mismatch')
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True;decoded={};ranges=[]
    for start,(end,group,parent) in RANGES.items():
        off=life.offset(pe,start,end-start);body=pe[off:off+end-start];seq=list(md.disasm(body,start))
        life.need(sum(i.size for i in seq)==len(body),'incomplete decoded range '+life.hx(start))
        if group:life.compare(seq,native[group,parent])
        decoded.update((i.address,i) for i in seq)
        ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(end),'file_offset':life.hx(off),
                       'bytes':len(body),'sha256':life.sha(body),'instructions':len(seq),
                       'validation':'PE/native operands' if group else 'pinned PE decoding only'})
    globals_=(0xae235c,0xdd7118,0xdd7ee4,0xde3008,0xde4400,0xde4404)
    base,sections=life.pe_sections(pe)
    for va in globals_:
        section=next(s for s in sections if base+s[2]<=va<base+s[2]+s[1])
        life.need(va-base-section[2]>=section[3],'global unexpectedly raw backed')
    return pe,decoded,{'unit':'R36-C','baseline_commit':BASELINE,'specimen_sha256':life.SPECIMEN,
        'scope':SCOPE,'manifest_sha256':PINS,'native_sources':sources,'export_hashes':hashes,'ranges':ranges,
        'imports':imports(pe),'zero_tail_globals':[life.hx(va) for va in globals_]}


class Machine:
    def __init__(self,pe,decoded,seed):
        self.uc=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_32);self.decoded=decoded
        for page in sorted({address&~0xfff for address in decoded}):self.uc.mem_map(page,0x1000)
        for start,(end,_,_) in RANGES.items():self.uc.mem_write(start,pe[life.offset(pe,start,end-start):life.offset(pe,start,end-start)+end-start])
        for name,(base,size) in REGIONS.items():
            self.uc.mem_map(base,size)
            self.uc.mem_write(base,bytes((k*13+seed*17)&255 for k in range(size)) if name in ('stack','receiver') else bytes(size))

    def put(self,address,value):self.uc.mem_write(address,struct.pack('<I',value&0xffffffff))
    def word(self,address):return struct.unpack('<I',self.uc.mem_read(address,4))[0]
    def snapshots(self):return {n:bytes(self.uc.mem_read(b,s)) for n,(b,s) in REGIONS.items()}

    def entry(self,entry,args=()):
        initial=dict(life.SCRATCH,ecx=0x200000,esp=SP,eip=entry)
        for name,value in initial.items():self.uc.reg_write(life.REGS[name],value)
        self.uc.reg_write(x86.UC_X86_REG_EFLAGS,0x202)
        for index,value in enumerate((0x700000,*args)):self.put(SP+4*index,value)
        return initial

    def run(self,entry,stop,flag_write=False):
        trace=[];events=[];frames=[];current=[0];uc=self.uc
        def code(machine,address,size,_):
            life.need(address in self.decoded,'unadmitted instruction');current[0]=address
            trace.append(life.hx(address));life.need(len(trace)<=256,'instruction budget exceeded')
            ins=self.decoded[address]
            if ins.mnemonic=='call':
                life.need(ins.operands[0].type==capstone.x86.X86_OP_IMM,'executed unresolved import')
                target=ins.operands[0].imm;life.need((address,target) in CALLS,'unsupported call '+life.hx(address))
                sp=machine.reg_read(life.REGS['esp'])
                frames.append({'site':life.hx(address),'target':life.hx(target),'ecx':machine.reg_read(life.REGS['ecx']),
                    'arguments':[self.word(sp+4*k) for k in range(ARGS[target])]})
        def memory(machine,kind,address,size,value,_):
            life.need(any(b<=address and address+size<=b+s for b,s in REGIONS.values()),'unadmitted memory '+life.hx(address))
            events.append([life.hx(current[0]),'write' if kind==unicorn.UC_MEM_WRITE else 'read',life.hx(address),size])
        hooks=[uc.hook_add(unicorn.UC_HOOK_CODE,code),uc.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        before=self.snapshots()
        try:uc.emu_start(entry,stop,count=256)
        finally:
            for hook in hooks:uc.hook_del(hook)
        life.need(uc.reg_read(life.REGS['eip'])==stop,'failed to reach stop')
        after=self.snapshots();expected={n:bytearray(v) for n,v in before.items()}
        if flag_write:expected['selector_globals'][0x118:0x11c]=struct.pack('<I',1)
        for name in REGIONS:
            if name!='stack':life.need(after[name]==bytes(expected[name]),'complete nonstack mismatch '+name)
        life.need(not any(0x200000<=int(event[2],16)<0x201000 for event in events),'receiver accessed before OS stop')
        return {'entry':life.hx(entry),'stop':life.hx(stop),'instruction_steps':len(trace),
            'trace_sha256':life.sha(life.compact(trace)),'events_sha256':life.sha(life.compact(events)),
            'memory_events':events,'call_frames':frames,'final_registers':{n:uc.reg_read(r) for n,r in life.REGS.items()},
            'before_memory_sha256':{n:life.sha(v) for n,v in before.items()},
            'after_memory_sha256':{n:life.sha(v) for n,v in after.items()}},events


def produce(pe,decoded):
    life.need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4');cases=[]
    for seed in range(8):
        for kind,entry,arg in [('constructor_drive',0x84b940,0),('constructor_drive',0x84b940,0x220000),
            *[('caller_allocation',entry,None) for entry in CALLER_ENTRIES],('flag_then_constructor',0x84b940,0)]:
            m=Machine(pe,decoded,seed);producer=None
            if kind=='flag_then_constructor':
                m.entry(0x81ba8d);producer,events=m.run(0x81ba8d,0x81ba97,True)
                life.need(events==[['0081ba8d','write','00dd7118',4]],'original flag write mismatch')
                life.need(m.word(0xdd7118)==1,'original flag value mismatch')
            m.entry(entry,[] if arg is None else [arg]);stop=0x84b970 if kind=='constructor_drive' else 0x944ef0
            result,events=m.run(entry,stop);sp=m.uc.reg_read(life.REGS['esp'])
            arguments=[m.word(sp+4*k) for k in range(2 if stop==0x84b970 else 3)]
            expected=[200,SP-0x2e0] if stop==0x84b970 else [0,0,16]
            life.need(arguments==expected,'outgoing OS arguments mismatch')
            if kind=='constructor_drive':
                life.need(not any(event[1]=='read' and event[2]==life.hx(SP+4) for event in events),'constructor argument read before drive query')
                life.need(result['call_frames']==[],'call before drive query')
            else:
                request=0 if kind=='flag_then_constructor' else 8
                life.need(result['call_frames'][0]['arguments']==[request],'allocation request mismatch')
                life.need(result['call_frames'][-1]['arguments']==[request],'allocator leaf request mismatch')
            result.update(next_call={'iat':'009670f8' if stop==0x84b970 else '00967154',
                'symbol':'GetLogicalDriveStringsA' if stop==0x84b970 else 'HeapAlloc','arguments':arguments,'executed':False},
                receiver_global=m.word(0xdd7ee4),flag_value=m.word(0xdd7118),constructor_returned=False,receiver_written=False)
            life.need(m.word(0xdd7ee4)==0,'receiver global unexpectedly published')
            cases.append({'seed':seed,'kind':kind,'constructor_argument':arg,'flag_producer':producer,'stage':result})
    return {'unit':'R36-C','scope':SCOPE,'specimen_sha256':life.SPECIMEN,'synthetic_harness':True,'cases':cases,
        'coverage':{'constructor_drive_entries':16,'caller_allocation_interiors':24,'flag_store_windows':8,
            'separate_flagged_constructor_entries':8,'receiver_returns':0,'row_writes':0,
            'instruction_steps':sum(c['stage']['instruction_steps']+(c['flag_producer']['instruction_steps'] if c['flag_producer'] else 0) for c in cases)}}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','native','state','output'):p.add_argument(name,type=Path)
    return p


def generate(a):
    pe,decoded,sites=extract(a)
    return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.write_bytes(life.pack(result));print(json.dumps(result['oracle']['coverage']))

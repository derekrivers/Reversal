#!/usr/bin/env python3
"""R39-B: genuine slot-reference producer and bounded CRT consumer continuation."""
import argparse
import gzip
import json
from pathlib import Path
import struct

import capstone
from unicorn import x86_const as x86
import extract_action33_lifecycle_31 as life
import extract_action33_slot_32 as slot

BASELINE='58f3033'
PRIOR='8c0ed7d1f2d662ca7d7bc597373371b16f136ea86ec9d080f366a61cfefdcded'
# Complete local CRT helper, startup producers, and the two lookup storage producers.
EXTRA={0x94bef1:(0x94bf52,0x94bef1),
       0x948aeb:(0x948b48,0x948aeb),0x94628c:(0x9462bb,0x94628c),
       0x62cf70:(0x62d140,0x62cf70),0x62ab00:(0x62b2c9,0x62ab00)}
# These operands are authored checks, independently of the whole-specimen hash.
OPERANDS={0x94bef6:'mov eax, dword ptr [0xde4404]',0x94beff:'jne 0x94bf1a',
 0x94bf1a:'cmp eax, 2',0x94bf1d:'jne 0x94bf3e',0x94bf3e:'push dword ptr [ebp + 8]',
 0x94bf41:'push 0',0x94bf43:'push dword ptr [0xde4400]',0x94bf49:'call dword ptr [0x9670dc]',
 0x948afc:'call dword ptr [0x967110]',0x948b04:'mov dword ptr [0xde4400], eax',
 0x948b13:'mov dword ptr [0xde4404], eax',0x946291:'call 0x944e46',
 0x946299:'mov dword ptr [0xde4638], eax',0x9462b5:'mov dword ptr [0xde4634], eax',
 0x62cf76:'mov eax, dword ptr [0xae2364]',0x62cf83:'shl ecx, 5',0x62cf86:'sub ecx, eax',
 0x62cf91:'call 0x944e46',0x62cf9b:'mov dword ptr [ebp], eax',
 0x62d049:'mov dword ptr [esi + 0xe], eax',0x62d0f8:'add esi, 0x1f',
 0x62abf0:'mov dword ptr [esi], eax',0x62ad16:'mov dword ptr [esi + 4], ecx'}
COMMON='entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256'.split()


def imports(pe):
    nt=struct.unpack_from('<I',pe,0x3c)[0];base,_=life.pe_sections(pe)
    pos=life.offset(pe,base+struct.unpack_from('<I',pe,nt+128)[0],20);result={}
    def string(rva):
        off=life.offset(pe,base+rva,1)
        return pe[off:pe.index(b'\0',off)].decode('ascii')
    while True:
        original,_,_,name,first=struct.unpack_from('<IIIII',pe,pos)
        if not name: break
        index=0
        while True:
            value=struct.unpack_from('<I',pe,life.offset(pe,base+(original or first)+4*index,4))[0]
            if not value: break
            address=base+first+4*index
            if address in (0x9670dc,0x967110,0x967114):
                life.need(not value&0x80000000,'unexpected import ordinal')
                result[life.hx(address)]={'dll':string(name),'symbol':string(value+2)}
            index+=1
        pos+=20
    life.need(result=={'009670dc':{'dll':'KERNEL32.dll','symbol':'HeapSize'},
                      '00967110':{'dll':'KERNEL32.dll','symbol':'HeapCreate'},
                      '00967114':{'dll':'KERNEL32.dll','symbol':'HeapDestroy'}},'CRT import identity mismatch')
    return result


def extract(a):
    pe,decoded,native,sites=slot.extract(a)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[]
    for start,(end,owner) in EXTRA.items():
        off=life.offset(pe,start,end-start);body=pe[off:off+end-start];seq=list(md.disasm(body,start))
        life.need(sum(i.size for i in seq)==len(body),'incomplete R39 range')
        native_match=owner in native
        if native_match: life.compare(seq,native[owner])
        decoded.update((i.address,i) for i in seq)
        ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(end),'file_offset':life.hx(off),
                       'bytes':len(body),'sha256':life.sha(body),'instructions':len(seq),
                       'all_native_operands_match':native_match,
                       'source':'native export and pinned PE' if native_match else 'pinned PE only; no focused native export'})
    for address,expected in OPERANDS.items():
        life.need(address in decoded and decoded[address].mnemonic+' '+decoded[address].op_str==expected,
                  'R39 authored operand mismatch '+life.hx(address))
    life.RANGES.update({start:end-start for start,(end,_) in EXTRA.items()})
    # The CRT state really is loader-zero, with no file-backed initial value.
    base,sections=life.pe_sections(pe)
    for address in (0xde4400,0xde4404,0xde4634,0xde4638):
        section=next(s for s in sections if base+s[2]<=address<base+s[2]+s[1])
        life.need(address-base-section[2]>=section[3],'CRT global unexpectedly file backed')
    sites.update(unit='R39-B',baseline_commit=BASELINE,extra_ranges=ranges,crt_imports=imports(pe),
                 authored_operand_sites=[life.hx(a) for a in OPERANDS],
                 scope='static producer contracts plus separate synthetic original entries; no resolver or initialized object')
    return pe,decoded,sites


def cpu(m):
    return dict(m.registers(),eflags=m.uc.reg_read(x86.UC_X86_REG_EFLAGS),
                fpcw=m.uc.reg_read(x86.UC_X86_REG_FPCW),fpsw=m.uc.reg_read(x86.UC_X86_REG_FPSW),
                fptag=m.uc.reg_read(x86.UC_X86_REG_FPTAG))


def produce(pe,decoded):
    prior_raw=Path('evidence/action33-slot-32-oracle.bin').read_bytes()
    life.need(life.sha(prior_raw)==PRIOR,'prior R32 oracle mismatch')
    prior=json.loads(gzip.decompress(prior_raw))['oracle'];cases=[]
    life.ARG_COUNTS[0x94bef1]=1
    for n,old in enumerate(prior['cases']):
        club,index=divmod(n,20);m=life.Machine(pe,decoded,club)
        selected=0x280000+0x1be*index;staff_id=(club*11+index)%32
        staff=0x230000+0x6e*staff_id;attribute=0x240000+0x46*staff_id
        stages={}
        def run(name,entry,stop,calls):
            before,after,record,events=m.run(entry,stop,calls)
            life.need(record=={k:old[name][k] for k in COMMON},'R32 prefix continuity mismatch '+name)
            stages[name]=record
            return before,after,events
        m.entry(0x6eada0,selected,[])
        run('initializer',0x6eada0,life.STOP,set())
        cell=0x210000+0x91*club+2+4*index
        for address,value in ((0x200601,0x210000),(0x220000,club),(0x2200cf,0),
            (0xae2350,1),(0xae235c,8),(0xae2364,64),(0xae23bc,0x230000),
            (cell,staff_id),(staff,staff_id),(staff+0x61,attribute)):
            m.set32(address,value)
        m.uc.mem_write(attribute+0x45,bytes([40+club]))
        m.entry(0x8968f0,0x200000,[0x220000,0xa5a50000|index,0])
        run('lookup',0x8968f0,life.STOP,life.LOOKUP_CALLS)
        returned=m.uc.reg_read(life.REGS['eax'])
        life.need(returned==staff,'original lookup return mismatch')
        m.set32(0x260023,0x280000);m.set32(0x260012,0x250000)
        m.uc.mem_write(0x260018,bytes([club]));extra=0x89abcd80|club
        m.entry(0x6e0d00,0x260000,[0xa5a50000|index,returned,extra])
        run('placement',0x6e0d00,0x6eaf8f,{(0x6e0dde,0x6eaea0)})
        produced=m.word(selected+0x69)
        life.need(produced==returned and m.word(selected+0x6d)==attribute,'original slot reference mismatch')
        # A separate synthetic entry consumes the original slot store. This is not resolver continuation.
        m.entry(0x62ed70,m.word(0xb63d28),[produced])
        run('status',0x62ed70,0x946214,life.STATUS_CALLS)
        initial=cpu(m)
        before,after,continuation,events=m.run(0x946214,0x94bf49,{(0x946214,0x94bef1)})
        life.expected_data(before,after,[])
        # Independently reconstruct all eight original stack writes in this window.
        expected=bytearray(before['stack']);p=initial['esp'];stack_base=life.DATA_REGIONS['stack'][0]
        for delta,value in ((-4,0x946219),(-8,initial['ebp']),(-12,initial['ecx']),
                            (-16,initial['ecx']),(-20,initial['esi']),(-24,0),(-28,0),(-32,0)):
            struct.pack_into('<I',expected,p+delta-stack_base,value)
        life.need(bytes(expected)==after['stack'],'complete continuation stack mismatch')
        expected_events=[['00946214','write',life.hx(p-4),4],['0094bef1','write',life.hx(p-8),4],
          ['0094bef4','write',life.hx(p-12),4],['0094bef5','write',life.hx(p-16),4],
          ['0094bef6','read','00de4404',4],['0094befb','write',life.hx(p-20),4],
          ['0094bf3e','read',life.hx(p),4],['0094bf3e','write',life.hx(p-24),4],
          ['0094bf41','write',life.hx(p-28),4],['0094bf43','read','00de4400',4],
          ['0094bf43','write',life.hx(p-32),4]]
        life.need(events==expected_events,'continuation ordered operand/source mismatch')
        expected_cpu=dict(initial,eax=0,ebp=p-8,esp=p-32,eip=0x94bf49,eflags=0x293)
        life.need(cpu(m)==expected_cpu,'continuation complete CPU mismatch')
        life.need(initial['eip']==0x946214 and m.word(0xb63d28)==0,'lookup initialization invented')
        life.need([m.word(0xde4400),m.word(0xde4404),m.word(0xde4638),m.word(0xde4634)]==[0]*4,
                  'CRT initialization invented')
        args=[m.word(m.uc.reg_read(life.REGS['esp'])+4*k) for k in range(3)]
        life.need(args==[0,0,0],'HeapSize original argument provenance mismatch')
        life.need(continuation['call_frames']==[{'site':'00946214','target':'0094bef1',
                  'ecx':initial['ecx'],'arguments':[0]}],'CRT consumer call frame mismatch')
        life.need(continuation['before_memory_sha256']==stages['status']['after_memory_sha256'],
                  'status continuation memory discontinuity')
        cases.append({'club_id':club,'index':index,'original_lookup_result':returned,
                      'slot':selected,'slot_record':produced,'prefix_sha256':life.sha(life.compact(stages)),
                      'prefix_instruction_steps':sum(s['instruction_steps'] for s in stages.values()),
                      'initial_cpu':initial,'final_cpu':cpu(m),'continuation':continuation,
                      'events':events,'heap_size_arguments':args,'lookup_global':m.word(0xb63d28)})
    return {'unit':'R39-B','specimen_sha256':life.SPECIMEN,'prior_oracle_sha256':PRIOR,
            'synthetic_separate_entries':True,'resolver_entered':False,'effect_returned':False,
            'frontier':{'site':'0094bf49','iat':'009670dc','symbol':'KERNEL32.dll!HeapSize',
                        'reason':'CRT heap handle, mode and exit-list storage not initialized'},
            'cases':cases,'coverage':{'cases':len(cases),'prefix_instruction_steps':sum(c['prefix_instruction_steps'] for c in cases),
                         'new_instruction_steps':sum(c['continuation']['instruction_steps'] for c in cases),
                         'new_memory_events':sum(c['continuation']['ordered_memory_events'] for c in cases)}}


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','state','staff','focused','support','exports25','slot','output'):
        p.add_argument(name,type=Path)
    return p


def generate(a):
    pe,decoded,sites=extract(a)
    return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.write_bytes(life.pack(result))
    print(json.dumps(result['oracle']['coverage']))

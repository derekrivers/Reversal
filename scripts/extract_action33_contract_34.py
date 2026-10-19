#!/usr/bin/env python3
"""R34-B: bounded original placement call and contract-manager OS frontier."""
import argparse
import json
from pathlib import Path

import capstone
import unicorn.x86_const as x86

import extract_action33_owner_33 as owner
import extract_action33_lifecycle_31 as life

BASELINE='4ee3cd0304ac34d2ed0ac09b5f97c06afc67e7f6'
CONTRACT_EXPORT='72a20b7d73d5212bec8fe024efff7292fcf30833220739151f0db2de33c14476'
EXTRA={0x4cf5f0:0x4cf62b-0x4cf5f0,0x4c7040:0x4c7073-0x4c7040}
STATIC={0x8297ca:(0x82980e,0x828110),0x82c7ba:(0x82c7ef,0x82a9c0),
        0x83036c:(0x83038c,0x82ff40)}
SCOPE=('R33-B original-produced synthetic placement state enters the actual contract call '
       'through pre-004cf62b; independent constructor entry stops before GetLogicalDriveStringsA; '
       'no receiver initialization, row lookup, enclosing setup caller, or live lifecycle')


def extract(a):
    pe,decoded,sites=owner.extract(a)
    native_contract=a.contract_export.read_bytes()
    life.need(life.sha(native_contract)==CONTRACT_EXPORT,'contract export mismatch')
    contract_rows=life.rows(native_contract)
    state_rows={start:life.rows((a.state/(life.hx(start)+'.asm')).read_bytes())
                for _,(_,start) in STATIC.items()}
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[]
    for start,(end,parent) in STATIC.items():
        length=end-start;off=life.offset(pe,start,length)
        raw=pe[off:off+length];seq=list(md.disasm(raw,start))
        life.need(sum(i.size for i in seq)==length,'incomplete setup/teardown range')
        life.compare(seq,state_rows[parent])
        ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(end),
                       'file_offset':life.hx(off),'bytes':length,'sha256':life.sha(raw),
                       'instructions':len(seq),'all_native_operands_match':True,'executed':False})
    for start,length in EXTRA.items():
        off=life.offset(pe,start,length);raw=pe[off:off+length]
        seq=list(md.disasm(raw,start))
        life.need(sum(i.size for i in seq)==length,'incomplete contract range')
        if start==0x4cf5f0:life.compare(seq,contract_rows)
        decoded.update((i.address,i) for i in seq)
        life.RANGES[start]=length
        ranges.append({'entry':life.hx(start),'end_exclusive':life.hx(start+length),
                       'file_offset':life.hx(off),'bytes':length,'sha256':life.sha(raw),
                       'instructions':len(seq),'all_native_operands_match':start==0x4cf5f0,
                       'executed':True})
    # The selected constructor prefix is compared with original PE bytes only:
    # checkpoint exports do not contain a function listing for 004c7040.
    life.need(decoded[0x4c706e].mnemonic=='push' and
              decoded[0x4c706e].op_str=='0xc8','constructor OS buffer length changed')
    call=list(md.disasm(pe[life.offset(pe,0x4c7073,6):life.offset(pe,0x4c7073,6)+6],
                        0x4c7073))
    life.need(len(call)==1 and call[0].size==6 and call[0].mnemonic=='call' and
              call[0].op_str=='dword ptr [0x9670f8]',
              'constructor indirect OS call changed')
    life.ARG_COUNTS[0x4cf5f0]=2
    sites.update(unit='R34-B',baseline_commit=BASELINE,scope=SCOPE,
                 contract_export_sha256=CONTRACT_EXPORT,
                 selected_ranges=ranges,
                 receiver_producers={'setup_legacy':'008297fc after 00944cf1 and 004c7040; 00829809 -> 004c7560',
                                     'setup_load':'0082c7ea after 00944cf1 and 004c7040',
                                     'teardown':'0083036c read; 004c74f0 and free; 00830386 clear'},
                 constructor_os_import=sites['constructor_imports']['009670f8'])
    return pe,decoded,sites


def clone(m,pe,decoded):
    out=life.Machine(pe,decoded,0)
    snapshot=m.snapshots()
    for name,(start,_) in life.DATA_REGIONS.items():out.uc.mem_write(start,snapshot[name])
    for name,value in m.registers().items():out.uc.reg_write(life.REGS[name],value)
    out.uc.reg_write(x86.UC_X86_REG_EFLAGS,m.uc.reg_read(x86.UC_X86_REG_EFLAGS))
    return out


def produce(pe,decoded):
    cases=[];original_run=life.Machine.run
    def capture(machine,entry,stop,allowed_calls):
        result=original_run(machine,entry,stop,allowed_calls)
        if entry==0x6e0d00 and stop==0x6eafa0:
            before_state=machine.registers()
            life.need(before_state['ecx']==machine.word(0xae1050)==0,
                      'receiver global no longer loader-zero')
            life.need(machine.word(0xae2d0c)==0,'auxiliary table was invented')
            caller_esp=before_state['esp']
            arguments=[machine.word(caller_esp+4*k) for k in range(2)]
            branch=clone(machine,pe,decoded)
            before,after,row,events=original_run(branch,0x6eafa0,0x4cf62b,{(0x6eafa0,0x4cf5f0)})
            life.expected_data(before,after,[])
            owner.stack_changes(before,after,[(caller_esp-4,4,0x6eafa5),
                 (caller_esp-8,4,before_state['ebx']),
                 (caller_esp-12,4,before_state['ebp']),
                 (caller_esp-16,4,before_state['esi']),
                 (caller_esp-20,4,before_state['edi'])])
            life.need(row['call_frames']==[{'site':'006eafa0','target':'004cf5f0',
                 'ecx':0,'arguments':arguments}],'contract call ABI changed')
            life.need(branch.word(0xae1050)==0 and branch.word(0xae2d0c)==0,
                      'contract globals changed in bounded prefix')
            life.need(branch.registers()['edx']==(machine.word(arguments[0])*0x4f)&0xffffffff,
                      'source-ID auxiliary stride changed')
            image_base,_=life.pe_sections(pe)
            life.need(branch.registers()['edx']<image_base,
                      'next auxiliary read unexpectedly points into PE image')
            life.need(branch.registers()['eax']==0,'auxiliary base is not loader-zero')
            life.need(branch.word(caller_esp-4)==0x6eafa5,'call return address changed')
            life.need(before['owner_globals']==after['owner_globals'] and
                      before['database_globals']==after['database_globals'],
                      'contract prefix unexpectedly wrote globals')
            cases.append({'club_id':machine.uc.mem_read(0x260018,1)[0],
                'staff':arguments[0],'club_pointer':arguments[1],
                'source_id':machine.word(arguments[0]),'entry_receiver':before_state['ecx'],
                'receiver_global':machine.word(0xae1050),'auxiliary_base':machine.word(0xae2d0c),
                'next_read_address':branch.registers()['edx'],
                'next_read_instruction':'004cf62b','next_read_executed':False,
                'next_read_is_loader_backed':False,'continuation':row,
                'observed_reads':[e for e in events if e[1]=='read'],
                'function_returned':False})
        return result
    life.Machine.run=capture
    try:
        upstream=owner.produce(pe,decoded)
    finally:life.Machine.run=original_run
    life.need(len(cases)==80 and upstream['coverage']['placement_frontiers']==80,
              'R33-B predecessor coverage changed')
    constructors=[]
    for seed in range(8):
        m=life.Machine(pe,decoded,seed);receiver=0x290000+seed*0x40
        m.entry(0x4c7040,receiver,[0])
        before,after,row,events=original_run(m,0x4c7040,0x4c7073,set())
        life.need(all(before[k]==after[k] for k in before if k not in ('stack','seh')),
                  'constructor prefix wrote nonstack storage')
        life.need(m.word(0xae1050)==0 and m.registers()['esi']==receiver,
                  'constructor unexpectedly published receiver')
        sp=m.registers()['esp']
        life.need(m.word(sp)==0xc8 and 0x300000<=m.word(sp+4)<0x310000,
                  'OS call arguments changed')
        life.need(events[-1]==['004c706e','write',life.hx(sp),4],
                  'OS call argument event changed')
        constructors.append({'seed':seed,'receiver':receiver,'entry_argument':0,
             'global_after':m.word(0xae1050),'os_call':'004c7073 -> IAT009670f8',
             'os_arguments':[m.word(sp),m.word(sp+4)],'os_call_executed':False,
             'constructor_returned':False,'frontier':row})
    return {'unit':'R34-B','specimen_sha256':life.SPECIMEN,'synthetic_only':True,
       'scope':SCOPE,'placement_calls':cases,'constructor_frontiers':constructors,
       'coverage':{'placement_call_prefixes':len(cases),'constructor_os_frontiers':len(constructors),
                   'instruction_steps':sum(x['continuation']['instruction_steps'] for x in cases)+
                         sum(x['frontier']['instruction_steps'] for x in constructors),
                   'next_unresolved':'004cf62b reads auxiliary base 00ae2d0c=0; '
                                      '004c7073 indirect GetLogicalDriveStringsA blocks receiver constructor'}}


def parser():
    p=owner.parser()
    p.add_argument('contract_export',type=Path)
    return p


def generate(a):
    pe,decoded,sites=extract(a)
    return {'sites':sites,'oracle':produce(pe,decoded)}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a)
    a.output.write_bytes(life.pack(result))
    print(json.dumps(result['oracle']['coverage']))

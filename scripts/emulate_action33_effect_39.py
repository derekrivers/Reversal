#!/usr/bin/env python3
"""R39-A: unchanged R38-A original-entry state through the null lookup frontier."""
import gzip
import hashlib
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_keeper_38 as prior
import extract_action33_effect_30 as effect
from extract_action33_prefix_30 import rows, compare

p,g=prior.p,prior.g
START,STOP,DIAGNOSTIC,LOOKUP=0x7024b4,0x62ed99,0x702332,0xb63d28
NEW_RANGES=effect.RANGES
RANGES=(*prior.RANGES,*NEW_RANGES)
BOUNDARIES=(*prior.BOUNDARIES,(STOP,STOP+5))
STOPS={DIAGNOSTIC:(0x944cff,5),STOP:(0x944cff,5)}
REGIONS={**prior.REGIONS,p.hx(LOOKUP):(LOOKUP,4)}
CALLS={**prior.CALLS,START:(0x6cfe10,5),0x6cfec2:(0x62ed70,1),
 **{a:(0x90cfc0,1) for a in (0x6cfe35,0x6cfe3b,0x6cfe50,0x6cfe5e,0x6cfe64,
                            0x6cfe74,0x6cfe7a,0x6cfe8c,0x6cfe9a,0x6cfea0)}}
DEPENDENCIES={
 'scripts/emulate_action33_keeper_38.py':'f270b77b692bbafe37f81a438915d2218dbe06dcc9936237828081125b37d9b3',
 'reconstruction/action33-keeper-38.ts':'899f1be877c9007f8d4994f9bc262d074e6e9a4998e6cc2da0e7b46e99c90f86',
 'scripts/extract_action33_effect_30.py':'d8ee2839f4fa1459d9ad061c3f3fd6e5a3993e3ffc828e76faad8c6396267f00',
 'evidence/action33-keeper-38-oracle.bin':'d5e9ed42bae44b49a0c21dc21b6e7e045f7eb724b2b2a3f9770eddecf703a53d',
 'evidence/action33-effect-30-oracle.bin':'ddf4a92864ef02dd7027d9311e5e615b7b0c75a2625eb9cb87dd6e915bc21472',
}


def schedule():return prior.schedule()


def extract(a):
    data,ins,previous=prior.extract(a)
    earlier=effect.extract(a.binary,a.exports09,a.exports10,a.runtime)
    native=rows(a.caller)
    native.update(rows(a.exports09/'006cfe10.asm'));native.update(rows(a.exports10/'0062ed70.asm'))
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[]
    for start,end in (*NEW_RANGES,(STOP,STOP+5)):
        off=p.pe_offset(data,start,end-start);raw=data[off:off+end-start]
        decoded={i.address:i for i in md.disasm(raw,start)}
        p.need(sum(i.size for i in decoded.values())==len(raw),'incomplete new range')
        compare(decoded,native);ins.update(decoded)
        ranges.append({'start':p.hx(start),'end_exclusive':p.hx(end),'file_offset':p.hx(off),
          'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(decoded),'admitted_to_execute':(start,end) in NEW_RANGES})
    p.need(ins[START].op_str=='0x6cfe10' and ins[STOP].op_str=='0x944cff','effect boundary changed')
    return data,ins,{'specimen_sha256':p.EXPECTED,'dependency_hashes':DEPENDENCIES,
      'new_ranges':ranges,'native_export_sha256':effect.HASHES,
      'prior_sites_sha256':p.sha(p.compact(previous)),'r30b_sites_sha256':p.sha(p.compact(earlier)),
      'lookup_global_has_raw_PE_backing':False,
      'next_calls':{p.hx(k):p.hx(v[0]) for k,v in STOPS.items()},
      'first_missing_input':'006cfeb8 reads null shooter+69; 00b63d28 also remains zero',
      'first_unsupported_call':'0062ed99 -> 00944cff'}


def generate(a,mutation=None,observe=None):
    root=Path(__file__).resolve().parents[1]
    for name,digest in DEPENDENCIES.items():p.need(p.sha((root/name).read_bytes())==digest,'dependency digest mismatch '+name)
    reference=json.loads(gzip.decompress((root/'evidence/action33-keeper-38-oracle.bin').read_bytes()))
    p.need(unicorn.__version__=='2.1.4','Unicorn version mismatch')
    data,ins,sites=extract(a)
    machine=p.Oracle(data,code_ranges=RANGES+BOUNDARIES);u=machine.uc
    u.mem_map(p.MATCH,0x10000);u.mem_map(p.POSITIONS,0x1000)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes()
    prior.prior.prior.prior.validate_table(table);u.mem_write(p.TABLE,table)
    result=[]
    for number,c in enumerate(schedule()):
        prior.prior.prior.prior.prior.prior.seed(machine,c)
        p.need(machine.get(LOOKUP)==0,'lookup global must remain original zero-mapped state')
        before=g.state(machine);trace,events,calls,pending=[],[],[],[]
        state_hash=hashlib.sha256();state_count=0;checkpoint=None;pc=0
        prefix_hash=hashlib.sha256();prefix_count=0;prefix_started=False
        old=next(row for row in reference['cases'] if row['case']==c)
        def code(m,address,size,unused):
            nonlocal pc,checkpoint,state_count,prefix_started,prefix_count
            if address==START and mutation=='prefix-register':u.reg_write(x.UC_X86_REG_EBP,u.reg_read(x.UC_X86_REG_EBP)^1)
            if pending and pending[-1][0]==address:
                _,index=pending.pop();calls[index]['after']=g.state(machine)
            if address in (START,DIAGNOSTIC):
                checkpoint={'state':g.state(machine),'trace_length':len(trace),'event_length':len(events),'call_length':len(calls),
                  'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in prior.REGIONS.items()}}
                p.need(checkpoint['state']==old['after'] and checkpoint['memory_sha256']==old['memory_sha256'] and
                  trace==old['instruction_trace'] and events==old['events'] and calls==old['calls'] and
                  prefix_hash.hexdigest()==old['suffix_state_sha256'] and prefix_count==old['suffix_states'],
                  'R38-A original prefix mismatch')
                if address==START:
                    sp=u.reg_read(x.UC_X86_REG_ESP);shooter=u.reg_read(x.UC_X86_REG_ESI)
                    p.need(list(struct.unpack('<5I',u.mem_read(sp,20)))==old['boundary']['arguments'],'effect arguments changed')
                    p.need(machine.get(shooter+0x69)==0 and machine.get(LOOKUP)==0,'effect inputs were repaired')
            # Test-only mutations occur after the preserved checkpoint comparison.
            if address==0x6cfeb8 and mutation=='participant':machine.put(u.reg_read(x.UC_X86_REG_ESI)+0x69,p.MATCH)
            if address==0x6cfebb and mutation=='lookup':machine.put(LOOKUP,p.MATCH)
            if address==0x6cfe10 and mutation=='argument-high':machine.put(u.reg_read(x.UC_X86_REG_ESP)+16,0)
            if address==0x6cfe40 and mutation=='rng-cell':machine.put(p.OFFSET,machine.get(p.OFFSET)^1)
            if address==0x6cfe48 and mutation=='selector-byte':u.reg_write(x.UC_X86_REG_EBX,u.reg_read(x.UC_X86_REG_EBX)^1)
            if address==0x62ed85 and mutation=='lookup-stack':u.reg_write(x.UC_X86_REG_ESP,u.reg_read(x.UC_X86_REG_ESP)+4)
            if address==STOP and mutation=='flags':u.reg_write(x.UC_X86_REG_EFLAGS,u.reg_read(x.UC_X86_REG_EFLAGS)^1)
            if address in STOPS:
                p.need(mutation!='execute-stop','diagnostic stop must not execute')
                u.emu_stop();return
            if address==prior.START:prefix_started=True
            if prefix_started and checkpoint is None:
                prefix_hash.update(p.compact({'pc':p.hx(address),'state':g.state(machine)})+b'\n');prefix_count+=1
            if address in prior.prior.prior.RESERVE_STOPS:raise ValueError('unsupported reserve branch '+p.hx(address))
            if address==0x90d02d:raise ValueError('unsupported large RNG branch')
            pc=address
            p.need(address in ins and any(lo<=address<hi for lo,hi in RANGES),'unadmitted instruction '+p.hx(address))
            if checkpoint is not None:
                snapshot={'pc':p.hx(address),'state':g.state(machine)}
                state_hash.update(p.compact(snapshot)+b'\n');state_count+=1
                if observe is not None:observe(snapshot)
            trace.append(p.hx(address))
            if address in CALLS:
                target,argc=CALLS[address]
                args=list(struct.unpack('<'+'I'*argc,u.mem_read(u.reg_read(x.UC_X86_REG_ESP),argc*4))) if argc else []
                calls.append({'site':p.hx(address),'target':p.hx(target),'before':g.state(machine),'arguments':args,'after':None})
                pending.append((address+size,len(calls)-1))
        def memory(m,kind,address,size,value,unused):
            p.need(any(base<=address and address+size<=base+n for base,n in REGIONS.values()),'unadmitted data access '+p.hx(address))
            write=kind==unicorn.UC_MEM_WRITE
            immutable=(*prior.prior.prior.prior.prior.prior.STATIC,*prior.prior.prior.DISPATCH,*((a,8,v) for a,v in prior.CONSTANTS),(LOOKUP,4,0))
            p.need(not write or not any(base<=address<base+n for base,n,_ in immutable),'immutable data write')
            observed=value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            events.append([p.hx(pc),'write' if write else 'read',p.hx(address),size,f'{observed:016x}' if size==8 else observed])
        hooks=[u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(g.ENTRY,0x3000000,count=10000)
        finally:
            for hook in hooks:u.hook_del(hook)
        stop=u.reg_read(x.UC_X86_REG_EIP);p.need(stop in STOPS and checkpoint is not None,'next boundary not reached')
        expected_pending=[('007024b4','006cfe10'),('006cfec2','0062ed70')] if stop==STOP else []
        p.need([(calls[i]['site'],calls[i]['target']) for _,i in pending]==expected_pending,'pending calls changed')
        after=g.state(machine);selected=old['selected']
        target,argc=STOPS[stop];arguments=list(struct.unpack('<'+'I'*argc,u.mem_read(after['registers']['esp'],argc*4)))
        digests={k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}
        if selected:
            lookup=calls[pending[-1][1]]
            p.need(lookup['before']['registers']['ecx']==0 and lookup['arguments']==[0],'null lookup ABI changed')
            sp=checkpoint['state']['registers']['esp']
            p.need(list(struct.unpack('<5I',u.mem_read(sp,20)))==old['boundary']['arguments'],'effect argument frame overwritten')
            p.need(arguments==[0x9e7f28,0,0,0x2007824,0x2007724] and after['registers']['esp']==0x2007708,'diagnostic frame changed')
            p.need(all(digests[k]==v for k,v in checkpoint['memory_sha256'].items() if k not in ('stack',p.hx(p.CURSOR),p.hx(p.OFFSET),p.hx(p.SEED))),
              'effect changed nonstack/non-RNG region')
            p.need(after['fpcw']==checkpoint['state']['fpcw'] and after['fpsw']==checkpoint['state']['fpsw'] and
              after['fptag']==65535 and not after['active_x87'],'effect x87 state changed')
        rng=[row for row in calls if row['target']=='0090cfc0']
        result.append({'id':number,'case':c,'before':before,'checkpoint':checkpoint,'after':after,'stop':p.hx(stop),
          'boundary':{'target':p.hx(target),'arguments':arguments},'selected':selected,'calls':calls,'rng':rng,'events':events,'instruction_trace':trace,
          'suffix_state_sha256':state_hash.hexdigest(),'suffix_states':state_count,'pending_calls':[i for _,i in pending],
          'effect_returned':False,'memory_sha256':digests})
    suffix_calls=[call for r in result for call in r['calls'][r['checkpoint']['call_length']:]]
    suffix_rng=[call for call in suffix_calls if call['target']=='0090cfc0']
    coverage={'cases':len(result),'lookup_diagnostic_boundaries':sum(r['stop']==p.hx(STOP) for r in result),
      'keeper_diagnostic_boundaries':sum(r['stop']==p.hx(DIAGNOSTIC) for r in result),'effect_returns':0,
      'instructions':sum(len(r['instruction_trace']) for r in result),'events':sum(len(r['events']) for r in result),
      'suffix_states':sum(r['suffix_states'] for r in result),'suffix_events':sum(len(r['events'])-r['checkpoint']['event_length'] for r in result),
      'rng_calls':sum(len(r['rng']) for r in result),'suffix_rng_calls':len(suffix_rng),
      'suffix_zero_bounds':sum(call['arguments']==[0] for call in suffix_rng),
      'crt_wrap_calls':sum(call['target']=='00946a04' for r in result for call in r['calls']),
      'suffix_crt_wrap_calls':sum(call['target']=='00946a04' for call in suffix_calls)}
    return {'unit':'R39-A','sites':sites,'cases':result,'coverage':coverage,
      'scope':'unchanged synthetic original-entry R38-A through null participant diagnostic; no effect/lookup/resolver return, outcome or live reachability; R30-B remains a separate 160-case original-only domain'}


def parser():
    result=prior.parser()
    for name in ('exports09','exports10'):result.add_argument('--'+name,type=Path,required=True)
    return result


if __name__=='__main__':
    args=parser().parse_args();result=generate(args)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(p.packed(result));print(json.dumps(result['coverage']))

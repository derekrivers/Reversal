#!/usr/bin/env python3
"""R36-A original-entry selector and caller, with original-produced R35-A state."""
import gzip
import hashlib
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_rng_35 as prior
from extract_action33_prefix_30 import rows, compare, verify_manifest, R29_MANIFEST

p,g=prior.p,prior.g
START,SELECTOR=prior.STOP,0x6ce110
STOPS={0x702332:(0x944cff,5),0x7023e3:(0x90cfc0,1)}
NEW_RANGES=((START,0x702332),(0x70238e,0x7023ad),(0x7023e1,0x7023e3),(SELECTOR,0x6ce304))
RANGES=(*prior.RANGES,*NEW_RANGES)
BOUNDARIES=(*prior.BOUNDARIES,*((a,a+5) for a in STOPS))
DISPATCH=((0x70a5c5,1,4),(0x70a5a4,4,0x7023e1))
RESERVE_STOPS=(0x6ce17e,0x6ce267,0x6ce1d6,0x6ce2bf)
REGIONS={**prior.REGIONS,**{p.hx(a):(a,n) for a,n,_ in DISPATCH}}
CALLS={**prior.CALLS,START:(SELECTOR,1)}
DEPENDENCIES={
 'scripts/emulate_action33_rng_35.py':'ff10fcdae0df059ab24033ea1ee46397ea6096a7e8fda5d910a4614d1db6c768',
 'reconstruction/action33-rng-35.ts':'19d5439eada0fdc3c816403ac32cc6efbdcc6d9c85406f10e1699286146d3b64',
 'evidence/action33-rng-35-oracle.bin':'edb057f22e3b5eec75ca0583a03f0b1c291e2ec96403cbf7efb61bf8d31f3a32',
 'evidence/action33-composition-30-oracle.bin':'e0bf9f5d089597868ae05642fc45e5628f0f268b16a210979f2d299445fb6063',
}


def schedule():return prior.schedule()


def extract(a):
    data,ins,previous=prior.extract(a)
    manifest=verify_manifest(a.r29,R29_MANIFEST)
    native=rows(a.caller);native.update(rows(a.r29/'006ce110.asm'))
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[]
    for start,end in (*NEW_RANGES,*((v,v+5) for v in STOPS)):
        off=p.pe_offset(data,start,end-start);raw=data[off:off+end-start]
        decoded={i.address:i for i in md.disasm(raw,start)}
        p.need(sum(i.size for i in decoded.values())==len(raw),'incomplete new range')
        compare(decoded,native);ins.update(decoded)
        ranges.append({'start':p.hx(start),'end_exclusive':p.hx(end),'file_offset':p.hx(off),
          'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(decoded),'admitted_to_execute':(start,end) in NEW_RANGES})
    constants=[]
    for va,n,value in DISPATCH:
        off=p.pe_offset(data,va,n);raw=data[off:off+n]
        p.need(int.from_bytes(raw,'little')==value,'action33 dispatch changed')
        constants.append({'va':p.hx(va),'file_offset':p.hx(off),'bytes':n,'value':value,'sha256':p.sha(raw)})
    p.need(ins[START].op_str=='0x6ce110','selector call changed')
    for stop,(target,_) in STOPS.items():p.need(ins[stop].op_str==hex(target),'next call changed')
    return data,ins,{'specimen_sha256':p.EXPECTED,'dependency_hashes':DEPENDENCIES,
      'selector_manifest_sha256':R29_MANIFEST,
      'selector_native_exports':{name:manifest['files'][name] for name in ('006ce110.asm','006ce110.c')},
      'new_ranges':ranges,'dispatch':constants,'next_calls':{p.hx(k):p.hx(v[0]) for k,v in STOPS.items()},
      'unsupported_selector_entries':[p.hx(v) for v in RESERVE_STOPS],
      'prior_sites_sha256':p.sha(p.compact(previous))}


def generate(a,mutation=None):
    root=Path(__file__).resolve().parents[1]
    for name,digest in DEPENDENCIES.items():p.need(p.sha((root/name).read_bytes())==digest,'dependency digest mismatch '+name)
    reference=json.loads(gzip.decompress((root/'evidence/action33-rng-35-oracle.bin').read_bytes()))
    composition=json.loads(gzip.decompress((root/'evidence/action33-composition-30-oracle.bin').read_bytes()))
    p.need(unicorn.__version__=='2.1.4','Unicorn version mismatch')
    data,ins,sites=extract(a)
    machine=p.Oracle(data,code_ranges=RANGES+BOUNDARIES);u=machine.uc
    u.mem_map(p.MATCH,0x10000);u.mem_map(p.POSITIONS,0x1000)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes();prior.validate_table(table);u.mem_write(p.TABLE,table)
    result=[]
    for number,c in enumerate(schedule()):
        prior.prior.prior.seed(machine,c)
        before=g.state(machine)
        trace,events,calls,pending,selector_events=[],[],[],[],[]
        state_hash=hashlib.sha256();state_count=0
        checkpoint=None;pc=0
        def code(m,address,size,unused):
            nonlocal pc,checkpoint,state_count
            if address==0x702311 and mutation=='return-esi':u.reg_write(x.UC_X86_REG_ESI,u.reg_read(x.UC_X86_REG_ESI)^1)
            if address==0x702311 and mutation=='rng-cell':machine.put(p.OFFSET,machine.get(p.OFFSET)^1)
            if address==0x702311 and mutation=='return-esp':u.reg_write(x.UC_X86_REG_ESP,u.reg_read(x.UC_X86_REG_ESP)+4)
            if pending and pending[-1][0]==address:
                _,index=pending.pop();calls[index]['after']=g.state(machine)
                call=calls[index]
                if call['target']==p.hx(SELECTOR):
                    for register in ('ebx','ebp','esi','edi','ecx'):
                        p.need(call['before']['registers'][register]==call['after']['registers'][register],'selector preserved register changed '+register)
                    p.need(call['after']['registers']['esp']==call['before']['registers']['esp']+4,'selector RET 4 ABI mismatch')
            if address==START:
                checkpoint={'state':g.state(machine),'trace_length':len(trace),'event_length':len(events),'call_length':len(calls),
                  'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in prior.REGIONS.items()}}
                if mutation=='reserve':u.mem_write(p.MATCH+0x4796+0x1a,b'\x00');u.mem_write(p.MATCH+0xf59e,b'\x00'*4)
            if address in STOPS:u.emu_stop();return
            if address in RESERVE_STOPS:raise ValueError('unsupported reserve branch '+p.hx(address))
            if address==0x7023a0 and mutation=='dispatch':u.mem_write(0x70a5c5,b'\x03')
            pc=address
            p.need(address in ins and any(lo<=address<hi for lo,hi in RANGES),'unadmitted instruction '+p.hx(address))
            if checkpoint is not None:
                state_hash.update(p.compact({'pc':p.hx(address),'state':g.state(machine)})+b'\n');state_count+=1
            trace.append(p.hx(address))
            if address in CALLS:
                target,argc=CALLS[address]
                args=list(struct.unpack('<'+'I'*argc,u.mem_read(u.reg_read(x.UC_X86_REG_ESP),argc*4))) if argc else []
                calls.append({'site':p.hx(address),'target':p.hx(target),'before':g.state(machine),'arguments':args,'after':None})
                pending.append((address+size,len(calls)-1))
        def memory(m,kind,address,size,value,unused):
            p.need(any(base<=address and address+size<=base+n for base,n in REGIONS.values()),'unadmitted data access '+p.hx(address))
            write=kind==unicorn.UC_MEM_WRITE
            immutable=(*prior.prior.prior.STATIC,*DISPATCH)
            p.need(not write or not any(base<=address<base+n for base,n,_ in immutable),'immutable data write')
            observed=value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            event=[p.hx(pc),'write' if write else 'read',p.hx(address),size,f'{observed:016x}' if size==8 else observed]
            events.append(event)
            if SELECTOR<=pc<0x6ce304 and not p.STACK<=address<p.STACK+0x10000:selector_events.append(event[1:])
        hooks=[u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(g.ENTRY,0x3000000,count=6000)
        finally:
            for hook in hooks:u.hook_del(hook)
        stop=u.reg_read(x.UC_X86_REG_EIP);p.need(stop in STOPS and not pending,'next boundary not reached')
        p.need(checkpoint is not None,'R35-A checkpoint missing')
        old=next(row for row in reference['cases'] if row['case']==c)
        p.need(checkpoint['state']==old['after'] and checkpoint['memory_sha256']==old['memory_sha256'] and
          trace[:checkpoint['trace_length']]==old['instruction_trace'] and events[:checkpoint['event_length']]==old['events'] and
          calls[:checkpoint['call_length']]==old['calls'],'R35-A original prefix mismatch')
        after=g.state(machine);call=calls[-1]
        p.need(call['site']==p.hx(START) and call['target']==p.hx(SELECTOR),'selector call missing')
        for register in ('ebx','ebp','esi','edi','ecx'):
            p.need(call['before']['registers'][register]==call['after']['registers'][register],'selector preserved register changed '+register)
        p.need(call['after']['registers']['esp']==call['before']['registers']['esp']+4,'selector RET 4 ABI mismatch')
        p.need(after['registers']['esi']==call['before']['registers']['esi'],'caller shooter register changed')
        p.need(after['rng']==before['rng'] and after['rng_cells']==before['rng_cells'],'selector advanced RNG')
        for address,n,value in DISPATCH:p.need(int.from_bytes(u.mem_read(address,n),'little')==value,'dispatch data changed')
        selected=call['after']['registers']['eax']
        p.need((selected==0)==(stop==0x702332),'wrong null/nonnull caller path')
        baseline=c['mode']=='baseline'
        if baseline:
            expected=composition['cases'][c['source_case']]
            p.need(selector_events==expected['selector_memory'] and selected==expected['result']['keeper'],'R30-C selector projection mismatch')
        target,argc=STOPS[stop]
        arguments=list(struct.unpack('<'+'I'*argc,u.mem_read(after['registers']['esp'],argc*4)))
        if stop==0x7023e3:p.need(arguments==[2],'variant bound mismatch')
        result.append({'id':number,'case':c,'before':before,'checkpoint':checkpoint,'after':after,'stop':p.hx(stop),
          'boundary':{'target':p.hx(target),'arguments':arguments},'selected':selected,'calls':calls,
          'rng':[row for row in calls if row['target']=='0090cfc0'],'events':events,'instruction_trace':trace,
          'suffix_state_sha256':state_hash.hexdigest(),'suffix_states':state_count,'selector_events':selector_events,
          'r30c_selector_projection':baseline,'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}})
    coverage={'cases':len(result),'nonnull':sum(r['selected']!=0 for r in result),'null':sum(r['selected']==0 for r in result),
      'instructions':sum(len(r['instruction_trace']) for r in result),'events':sum(len(r['events']) for r in result),
      'suffix_states':sum(r['suffix_states'] for r in result),'rng_calls':sum(len(r['rng']) for r in result),
      'selector_events':sum(len(r['selector_events']) for r in result),'r30c_selector_projections':sum(r['r30c_selector_projection'] for r in result),
      'selector_instruction_starts':len({pc for r in result for pc in r['instruction_trace'] if SELECTOR<=int(pc,16)<0x6ce304})}
    return {'unit':'R36-A','sites':sites,'cases':result,'coverage':coverage,
      'scope':'synthetic original entry through selector to pre-variant RNG or diagnostic; full represented-state prefix, no outcome or R30-C full-state join'}


def parser():
    ap=prior.parser();ap.add_argument('--r29',type=Path,required=True);return ap


if __name__=='__main__':
    args=parser().parse_args();result=generate(args)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(p.packed(result));print(json.dumps(result['coverage']))

#!/usr/bin/env python3
"""R37-B: original-produced selector state through variant RNG to keeper call."""
import gzip
import hashlib
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_selector_36 as prior
from extract_action33_prefix_30 import rows, compare

p,g=prior.p,prior.g
START,STOP,DIAGNOSTIC=0x7023e3,0x702416,0x702332
CRT=0x946a04
NEW_RANGES=((START,STOP),(0x90cfcf,0x90d02d),(CRT,0x946a22))
RANGES=(*prior.RANGES,*NEW_RANGES)
BOUNDARIES=(*prior.BOUNDARIES,(STOP,STOP+5),(0x90d02d,0x90d02e))
STOPS={DIAGNOSTIC:(0x944cff,5),STOP:(0x700420,6)}
REGIONS={**prior.REGIONS,**{p.hx(a):(a,4) for a in g.CELLS}}
CALLS={**prior.CALLS,START:(0x90cfc0,1),0x90cff1:(CRT,0)}
DEPENDENCIES={
 'scripts/emulate_action33_selector_36.py':'090bc711600d7e82c817ffdbe222f1cc5361f8b18cc9549cbec435bf4bffcad2',
 'reconstruction/action33-selector-36.ts':'5fc060d43ea27eb51375bf3874ed560ef452e1368b0c711ba8c40d6aae707908',
 'evidence/action33-selector-36-oracle.bin':'f019948252ce992d2fd43d5ddf9a51b0646c3fb8fe1837ca4ef009f4dd63d3ce',
 'evidence/action33-composition-30-oracle.bin':'e0bf9f5d089597868ae05642fc45e5628f0f268b16a210979f2d299445fb6063',
}


def schedule():return prior.schedule()


def extract(a):
    data,ins,previous=prior.extract(a)
    native=rows(a.caller)
    for name in ('0090cfc0','00946a04'):native.update(rows(a.runtime/(name+'.asm')))
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[]
    for start,end in (*NEW_RANGES,(STOP,STOP+5),(0x90d02d,0x90d02e)):
        off=p.pe_offset(data,start,end-start);raw=data[off:off+end-start]
        decoded={i.address:i for i in md.disasm(raw,start)}
        p.need(sum(i.size for i in decoded.values())==len(raw),'incomplete new range')
        compare(decoded,native);ins.update(decoded)
        ranges.append({'start':p.hx(start),'end_exclusive':p.hx(end),'file_offset':p.hx(off),
          'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(decoded),'admitted_to_execute':(start,end) in NEW_RANGES})
    p.need(ins[START].op_str=='0x90cfc0' and ins[STOP].op_str=='0x700420','call boundary changed')
    p.need(ins[0x90d02c].mnemonic=='ret' and not ins[0x90d02c].op_str,'variant RNG return ABI changed')
    return data,ins,{'specimen_sha256':p.EXPECTED,'dependency_hashes':DEPENDENCIES,
      'new_ranges':ranges,'prior_sites_sha256':p.sha(p.compact(previous)),
      'next_calls':{p.hx(k):p.hx(v[0]) for k,v in STOPS.items()},
      'full_r30c_join':False,'first_machine_state_gap':'00702416 -> 00700420'}


def generate(a,mutation=None,observe=None):
    root=Path(__file__).resolve().parents[1]
    for name,digest in DEPENDENCIES.items():p.need(p.sha((root/name).read_bytes())==digest,'dependency digest mismatch '+name)
    reference=json.loads(gzip.decompress((root/'evidence/action33-selector-36-oracle.bin').read_bytes()))
    composition=json.loads(gzip.decompress((root/'evidence/action33-composition-30-oracle.bin').read_bytes()))
    p.need(unicorn.__version__=='2.1.4','Unicorn version mismatch')
    data,ins,sites=extract(a)
    machine=p.Oracle(data,code_ranges=RANGES+BOUNDARIES);u=machine.uc
    u.mem_map(p.MATCH,0x10000);u.mem_map(p.POSITIONS,0x1000)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes();prior.prior.validate_table(table);u.mem_write(p.TABLE,table)
    result=[]
    for number,c in enumerate(schedule()):
        prior.prior.prior.prior.seed(machine,c)
        before=g.state(machine)
        trace,events,calls,pending=[],[],[],[]
        state_hash=hashlib.sha256();state_count=0
        checkpoint=None;pc=0
        def code(m,address,size,unused):
            nonlocal pc,checkpoint,state_count
            if address==0x7023e8:
                if mutation=='return-esi':u.reg_write(x.UC_X86_REG_ESI,u.reg_read(x.UC_X86_REG_ESI)^1)
                if mutation=='return-esp':u.reg_write(x.UC_X86_REG_ESP,u.reg_read(x.UC_X86_REG_ESP)+4)
                if mutation=='return-value':u.reg_write(x.UC_X86_REG_EAX,u.reg_read(x.UC_X86_REG_EAX)^1)
                if mutation=='rng-cell':machine.put(p.OFFSET,machine.get(p.OFFSET)^1)
            if address==0x90cff6 and mutation=='crt-seed':machine.put(p.SEED,machine.get(p.SEED)^1)
            if pending and pending[-1][0]==address:
                _,index=pending.pop();calls[index]['after']=g.state(machine)
                call=calls[index]
                if call['site']==p.hx(START):
                    for register in ('ebx','ebp','esi','edi','ecx'):
                        p.need(call['before']['registers'][register]==call['after']['registers'][register],'variant preserved register changed '+register)
                    p.need(call['after']['registers']['esp']==call['before']['registers']['esp'],'variant plain RET ABI mismatch')
                    old=call['before']['rng'];wrapped=old['cursorIndex']==50999
                    seed=(old['crtState']*214013+2531011)&0xffffffff if wrapped else old['crtState']
                    offset=(seed>>16)&32767 if wrapped else old['offset']
                    cursor=0 if wrapped else old['cursorIndex']+1
                    expected={'cursorIndex':cursor,'offset':offset,'crtState':seed}
                    p.need(call['after']['rng']==expected,'variant RNG state mismatch')
                    value=(struct.unpack_from('<I',table,4*cursor)[0]+offset)&0xffffffff
                    value=value if value<0x80000000 else value-0x100000000
                    remainder=value-int(value/2)*2
                    p.need(call['after']['registers']['eax']==remainder&0xffffffff and call['after']['registers']['edx']==remainder&0xffffffff,'variant return value mismatch')
            if address in (START,DIAGNOSTIC):
                checkpoint={'state':g.state(machine),'trace_length':len(trace),'event_length':len(events),'call_length':len(calls),
                  'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in prior.REGIONS.items()}}
                if mutation=='bound':machine.put(u.reg_read(x.UC_X86_REG_ESP),3)
            if address in STOPS:u.emu_stop();return
            if address in prior.RESERVE_STOPS:raise ValueError('unsupported reserve branch '+p.hx(address))
            if address==0x90cfc8 and checkpoint is not None:p.need(u.reg_read(x.UC_X86_REG_ESI)==2,'variant bound must be 2')
            if address==0x90d02d:raise ValueError('unsupported large RNG branch')
            if address==0x7023eb and mutation=='caller-marker':u.reg_write(x.UC_X86_REG_EAX,u.reg_read(x.UC_X86_REG_EAX)^1)
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
            immutable=(*prior.prior.prior.prior.STATIC,*prior.DISPATCH)
            p.need(not write or not any(base<=address<base+n for base,n,_ in immutable),'immutable data write')
            observed=value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            events.append([p.hx(pc),'write' if write else 'read',p.hx(address),size,f'{observed:016x}' if size==8 else observed])
        hooks=[u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(g.ENTRY,0x3000000,count=6500)
        finally:
            for hook in hooks:u.hook_del(hook)
        stop=u.reg_read(x.UC_X86_REG_EIP);p.need(stop in STOPS and not pending,'next boundary not reached')
        p.need(checkpoint is not None,'R36-A checkpoint missing')
        old=next(row for row in reference['cases'] if row['case']==c)
        p.need(checkpoint['state']==old['after'] and checkpoint['memory_sha256']==old['memory_sha256'] and
          trace[:checkpoint['trace_length']]==old['instruction_trace'] and events[:checkpoint['event_length']]==old['events'] and
          calls[:checkpoint['call_length']]==old['calls'],'R36-A original prefix mismatch')
        after=g.state(machine);selected=old['selected'];projection=None
        target,argc=STOPS[stop];arguments=list(struct.unpack('<'+'I'*argc,u.mem_read(after['registers']['esp'],argc*4)))
        variant=next((row for row in calls if row['site']==p.hx(START)),None)
        if stop==STOP:
            p.need(variant is not None and arguments[2]&255==variant['after']['registers']['eax']&255,'caller variant marker mismatch')
            p.need(after['registers']['ecx']==selected,'keeper receiver mismatch')
        if c['mode']=='baseline':
            expected=composition['cases'][c['source_case']]
            projection={'site':p.hx(START),'bound':2,'value':variant['after']['registers']['eax'],
              'initial':variant['before']['rng'],'final':variant['after']['rng']}
            p.need(projection==expected['draws'][0],'R30-C variant projection mismatch')
        result.append({'id':number,'case':c,'before':before,'checkpoint':checkpoint,'after':after,'stop':p.hx(stop),
          'boundary':{'target':p.hx(target),'arguments':arguments},'selected':selected,'calls':calls,
          'rng':[row for row in calls if row['target']=='0090cfc0'],'events':events,'instruction_trace':trace,
          'suffix_state_sha256':state_hash.hexdigest(),'suffix_states':state_count,'r30c_variant_projection':projection,
          'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}})
    coverage={'cases':len(result),'keeper_boundaries':sum(r['stop']==p.hx(STOP) for r in result),
      'diagnostic_boundaries':sum(r['stop']==p.hx(DIAGNOSTIC) for r in result),
      'instructions':sum(len(r['instruction_trace']) for r in result),'events':sum(len(r['events']) for r in result),
      'suffix_states':sum(r['suffix_states'] for r in result),'rng_calls':sum(len(r['rng']) for r in result),
      'crt_wrap_calls':sum(c['target']==p.hx(CRT) for r in result for c in r['calls']),
      'r30c_variant_projections':sum(r['r30c_variant_projection'] is not None for r in result)}
    return {'unit':'R37-B','sites':sites,'cases':result,'coverage':coverage,
      'scope':'synthetic original entry through variant RNG to pre-keeper or diagnostic; no full R30-C machine-state join, keeper return or outcome'}


def parser():return prior.parser()


if __name__=='__main__':
    args=parser().parse_args();result=generate(args)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(p.packed(result));print(json.dumps(result['coverage']))

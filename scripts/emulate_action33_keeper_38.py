#!/usr/bin/env python3
"""R38-A: actual original-entry keeper invocation and caller to pre-effect.

No state/return is inserted at either the R37 checkpoint or the keeper call.
The public corpus contains synthetic operands, scalar constants and digests.
"""
import gzip
import hashlib
import json
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_variant_37 as prior
from extract_action33_prefix_30 import rows, compare, verify_manifest, FRESH_MANIFEST

p,g=prior.p,prior.g
START,STOP,DIAGNOSTIC=0x702416,0x7024b4,0x702332
NEW_RANGES=((START,0x702463),(0x702498,STOP),(0x700420,0x7004f1),
 (0x700a4f,0x700b9f),(0x6c38c0,0x6c38ea))
RANGES=(*prior.RANGES,*NEW_RANGES)
BOUNDARIES=(*prior.BOUNDARIES,(STOP,STOP+5))
STOPS={DIAGNOSTIC:(0x944cff,5),STOP:(0x6cfe10,5)}
CONSTANTS=((0x9688b0,10.0),(0x968950,2.0),(0x968e40,0.7),
 (0x968e80,0.3),(0x96d698,0.5714285714285714),(0x968ea8,20.0))
REGIONS={**prior.REGIONS,**{p.hx(a):(a,8) for a,_ in CONSTANTS}}
CALLS={**prior.CALLS,START:(0x700420,6),0x7004be:(0x6c38c0,1),
 **{a:(0x90cfc0,1) for a in (0x7004da,0x7004e2,0x700a7e,0x700aa8,0x700aeb,0x700af7,0x700b1e,0x700b45)},
 **{a:(0x945640,0) for a in (0x700a78,0x700aa2,0x700b18,0x700b3a,0x700b83)}}
DEPENDENCIES={
 'scripts/emulate_action33_variant_37.py':'9b054cc9685d22e85afcfa320cb609a608584bed2469f9497acff906b2318c26',
 'reconstruction/action33-variant-37.ts':'121fbd86934229c9f20640c9056324af7c82c432f89033730c3dce91e52d37ac',
 'evidence/action33-variant-37-oracle.bin':'e78aa4f325e9737245ea35b6078c113b9b60a599b2e0eace2c1738bd6160bf59',
 'evidence/action33-composition-30-oracle.bin':'e0bf9f5d089597868ae05642fc45e5628f0f268b16a210979f2d299445fb6063',
}


def schedule():return prior.schedule()


def extract(a):
    data,ins,previous=prior.extract(a)
    manifest=verify_manifest(a.fresh,FRESH_MANIFEST)
    native=rows(a.caller)
    native.update(rows(a.fresh/'00700420.asm'));native.update(rows(a.r29/'006c38c0.asm'))
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ranges=[]
    for start,end in (*NEW_RANGES,(STOP,STOP+5)):
        off=p.pe_offset(data,start,end-start);raw=data[off:off+end-start]
        decoded={i.address:i for i in md.disasm(raw,start)}
        p.need(sum(i.size for i in decoded.values())==len(raw),'incomplete new range')
        compare(decoded,native);ins.update(decoded)
        ranges.append({'start':p.hx(start),'end_exclusive':p.hx(end),'file_offset':p.hx(off),
          'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(decoded),'admitted_to_execute':(start,end) in NEW_RANGES})
    constants=[]
    for address,value in CONSTANTS:
        off=p.pe_offset(data,address,8);raw=data[off:off+8]
        p.need(struct.unpack('<d',raw)[0]==value,'keeper scalar changed')
        constants.append({'va':p.hx(address),'file_offset':p.hx(off),'bytes':8,'value':value,'sha256':p.sha(raw)})
    p.need(ins[START].op_str=='0x700420' and ins[STOP].op_str=='0x6cfe10','call boundary changed')
    p.need(all(ins[a].mnemonic=='ret' and ins[a].op_str=='0x18' for a in (0x700b8f,0x700b9c)),'keeper return ABI changed')
    return data,ins,{'specimen_sha256':p.EXPECTED,'dependency_hashes':DEPENDENCIES,
      'keeper_manifest_sha256':FRESH_MANIFEST,
      'keeper_native_exports':{n:manifest['files'][n] for n in ('00700420.asm','00700420.c')},
      'new_ranges':ranges,'constants':constants,'prior_sites_sha256':p.sha(p.compact(previous)),
      'next_calls':{p.hx(k):p.hx(v[0]) for k,v in STOPS.items()},'full_r30c_machine_join':False,
      'first_connected_machine_state_gap':'007024b4 -> 006cfe10'}


def generate(a,mutation=None,observe=None):
    root=Path(__file__).resolve().parents[1]
    for name,digest in DEPENDENCIES.items():p.need(p.sha((root/name).read_bytes())==digest,'dependency digest mismatch '+name)
    reference=json.loads(gzip.decompress((root/'evidence/action33-variant-37-oracle.bin').read_bytes()))
    composition=json.loads(gzip.decompress((root/'evidence/action33-composition-30-oracle.bin').read_bytes()))
    p.need(unicorn.__version__=='2.1.4','Unicorn version mismatch')
    data,ins,sites=extract(a)
    machine=p.Oracle(data,code_ranges=RANGES+BOUNDARIES);u=machine.uc
    u.mem_map(p.MATCH,0x10000);u.mem_map(p.POSITIONS,0x1000)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes()
    prior.prior.prior.validate_table(table);u.mem_write(p.TABLE,table)
    result=[]
    for number,c in enumerate(schedule()):
        prior.prior.prior.prior.prior.seed(machine,c)
        before=g.state(machine);trace,events,calls,pending=[],[],[],[]
        state_hash=hashlib.sha256();state_count=0;checkpoint=None;pc=0
        def code(m,address,size,unused):
            nonlocal pc,checkpoint,state_count
            if address==0x700431 and mutation=='output-pointer':u.reg_write(x.UC_X86_REG_EBP,u.reg_read(x.UC_X86_REG_EBP)+1)
            if address==0x700438 and mutation=='action':u.mem_write(u.reg_read(x.UC_X86_REG_ESP)+0x28,b'\xff')
            if address==0x70243f and mutation=='caller-marker':u.mem_write(u.reg_read(x.UC_X86_REG_ESP)+0x19,b'\x01')
            if address==0x70241b:
                if mutation=='return-esi':u.reg_write(x.UC_X86_REG_ESI,u.reg_read(x.UC_X86_REG_ESI)^1)
                if mutation=='return-esp':u.reg_write(x.UC_X86_REG_ESP,u.reg_read(x.UC_X86_REG_ESP)+4)
                if mutation=='return-value':u.reg_write(x.UC_X86_REG_EAX,u.reg_read(x.UC_X86_REG_EAX)^0x10000)
                if mutation=='rng-cell':machine.put(p.OFFSET,machine.get(p.OFFSET)^1)
                if mutation=='return-x87':u.reg_write(x.UC_X86_REG_FPSW,u.reg_read(x.UC_X86_REG_FPSW)^0x100)
            if pending and pending[-1][0]==address:
                _,index=pending.pop();calls[index]['after']=g.state(machine);call=calls[index]
                if call['site']==p.hx(START):
                    for register in ('ebx','ebp','esi','edi'):
                        p.need(call['before']['registers'][register]==call['after']['registers'][register],'keeper preserved register changed '+register)
                    p.need(call['after']['registers']['esp']==call['before']['registers']['esp']+24,'keeper RET 24 ABI mismatch')
                    p.need(call['before']['fpcw']==call['after']['fpcw'] and call['after']['fptag']==65535 and not call['after']['active_x87'],'keeper x87 return stack/control mismatch')
            if address in (START,DIAGNOSTIC):
                checkpoint={'state':g.state(machine),'trace_length':len(trace),'event_length':len(events),'call_length':len(calls),
                  'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in prior.REGIONS.items()}}
            if address in STOPS:u.emu_stop();return
            if address in prior.prior.RESERVE_STOPS:raise ValueError('unsupported reserve branch '+p.hx(address))
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
            immutable=(*prior.prior.prior.prior.prior.STATIC,*prior.prior.DISPATCH,*((a,8,v) for a,v in CONSTANTS))
            p.need(not write or not any(base<=address<base+n for base,n,_ in immutable),'immutable data write')
            observed=value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            events.append([p.hx(pc),'write' if write else 'read',p.hx(address),size,f'{observed:016x}' if size==8 else observed])
        hooks=[u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(g.ENTRY,0x3000000,count=10000)
        finally:
            for hook in hooks:u.hook_del(hook)
        stop=u.reg_read(x.UC_X86_REG_EIP);p.need(stop in STOPS and not pending,'next boundary not reached')
        p.need(checkpoint is not None,'R37-B checkpoint missing')
        old=next(row for row in reference['cases'] if row['case']==c)
        p.need(checkpoint['state']==old['after'] and checkpoint['memory_sha256']==old['memory_sha256'] and
          trace[:checkpoint['trace_length']]==old['instruction_trace'] and events[:checkpoint['event_length']]==old['events'] and
          calls[:checkpoint['call_length']]==old['calls'],'R37-B original prefix mismatch')
        after=g.state(machine);selected=old['selected'];projection=None
        target,argc=STOPS[stop];arguments=list(struct.unpack('<'+'I'*argc,u.mem_read(after['registers']['esp'],argc*4)))
        digests={k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}
        rng=[row for row in calls if row['target']=='0090cfc0']
        keeper=next((row for row in calls if row['site']==p.hx(START)),None)
        if c['mode']=='baseline':
            expected=composition['cases'][c['source_case']]
            frame=keeper['before']['registers']['esp']+24
            flag=lambda offset:int.from_bytes(u.mem_read(frame+offset,1),'little')
            word=keeper['after']['registers']['eax']&65535
            projected_result={'keeper':selected,'variant':keeper['arguments'][2]&255,'responseWord':word if word<32768 else word-65536,
              'positionFlag':flag(0x20),'fallbackFlag':flag(0x14),'marker260':flag(0x19),'marker375':flag(0x1a),
              'eligible':'007004d6' in trace,'path':'rejected' if '007004d6' not in trace else 'weighted' if '00700b03' in trace else 'redrawn' if '00700b41' in trace else 'retained',
              'outgoingArgumentDwords':arguments}
            projection={'draws':[{'site':r['site'],'bound':signed(r['arguments'][0]),'value':signed(r['after']['registers']['eax']),
              'initial':r['before']['rng'],'final':r['after']['rng']} for r in rng[1:]],'result':projected_result,
              'final_rng':after['rng'],'final_memory_sha256':{k:digests[k] for k in expected['final_memory_sha256']}}
            p.need(projection=={k:expected[k] for k in projection},'R30-C semantic projection mismatch')
        result.append({'id':number,'case':c,'before':before,'checkpoint':checkpoint,'after':after,'stop':p.hx(stop),
          'boundary':{'target':p.hx(target),'arguments':arguments},'selected':selected,'calls':calls,'rng':rng,'events':events,'instruction_trace':trace,
          'suffix_state_sha256':state_hash.hexdigest(),'suffix_states':state_count,'r30c_projection':projection,'memory_sha256':digests})
    coverage={'cases':len(result),'effect_boundaries':sum(r['stop']==p.hx(STOP) for r in result),
      'diagnostic_boundaries':sum(r['stop']==p.hx(DIAGNOSTIC) for r in result),
      'instructions':sum(len(r['instruction_trace']) for r in result),'events':sum(len(r['events']) for r in result),
      'suffix_states':sum(r['suffix_states'] for r in result),'rng_calls':sum(len(r['rng']) for r in result),
      'crt_wrap_calls':sum(c['target']==p.hx(prior.CRT) for r in result for c in r['calls']),
      'keeper_returns':sum(c['site']==p.hx(START) for r in result for c in r['calls']),
      'r30c_semantic_projections':sum(r['r30c_projection'] is not None for r in result)}
    return {'unit':'R38-A','sites':sites,'cases':result,'coverage':coverage,
      'scope':'synthetic original-entry keeper return and caller to pre-effect or diagnostic; no R30-C machine-state join, resolver return, outcome or live reachability'}


def signed(v):return (v+0x80000000)%0x100000000-0x80000000
def parser():return prior.parser()


if __name__=='__main__':
    args=parser().parse_args();result=generate(args)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_bytes(p.packed(result));print(json.dumps(result['coverage']))

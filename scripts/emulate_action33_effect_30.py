#!/usr/bin/env python3
"""Continue each actual R30-A machine to the first unadmitted diagnostic call.

The prefix runs again and must exactly match its retained record. There is no
register, memory, argument, RNG or control-word reset between the two phases.
"""
import gzip
import json
import math
from pathlib import Path
import struct

import unicorn
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_EIP,UC_X86_REG_FPCW,UC_X86_REG_FPSW,UC_X86_REG_FPTAG,UC_X86_REG_EFLAGS
import emulate_action33_prefix_30 as prefix
from extract_action33_effect_30 import (extract,instructions,parser,RANGES,PREFIX_ORACLE,PREFIX_SCRIPT)
from emulate_action33_prefix_30 import need,sha,compact,packed,hx

START,STOP=0x7024b4,0x62ed99
LOOKUP=0xb63d28
ARGC={0x6cfe10:5,0x62ed70:1,0x90cfc0:1,0x946a04:0}
REGIONS=((prefix.MATCH,0x10000),(prefix.POSITIONS,0x1000),(prefix.STACK,0x10000),
         (prefix.TABLE,prefix.TABLE_END-prefix.TABLE+4),(prefix.GRID,432))
NAMES=('match','positions','stack','random_table','grid')
CELLS=(prefix.CURSOR,prefix.OFFSET,prefix.LIMIT,prefix.SEED,LOOKUP)


def snapshot(oracle):
    uc=oracle.uc
    return {'registers':{name:uc.reg_read(r) for name,r in prefix.REGS.items()},
      'fpcw':uc.reg_read(UC_X86_REG_FPCW),'fpsw':uc.reg_read(UC_X86_REG_FPSW),
      'fptag':uc.reg_read(UC_X86_REG_FPTAG),'eflags':uc.reg_read(UC_X86_REG_EFLAGS),
      'rng':oracle.state(),'cells':{hx(a):int.from_bytes(uc.mem_read(a,4),'little') for a in CELLS},
      'memory_sha256':{name:sha(bytes(uc.mem_read(a,n))) for name,(a,n) in zip(NAMES,REGIONS)}}


def continue_case(oracle,insns,case,reference,private=None):
    uc=oracle.uc;before=snapshot(oracle);sp=before['registers']['esp'];shooter=before['registers']['esi']
    def word(a):return int.from_bytes(uc.mem_read(a,4),'little')
    args=[word(sp+k*4) for k in range(5)]
    need(args==[shooter,0x6d,0,0x4100000,0],'R30-A raw argument frame changed')
    need(before['rng']==reference['final_rng'],'prefix RNG not preserved')
    need(word(shooter+0x69)==0 and word(shooter+0x6d)==0,'unexpected supplied player/attribute pointers')
    need(word(LOOKUP)==0,'lookup global is not original zero-mapped image state')
    originals={name:bytes(uc.mem_read(a,n)) for name,(a,n) in zip(NAMES,REGIONS)}
    trace=[];events=[];external=[];calls=[];rng=[];pending=[];current=0
    def regs():return {name:uc.reg_read(r) for name,r in prefix.REGS.items()}
    def code(m,a,size,data):
        nonlocal current
        current=a;need(a in insns and insns[a].size==size,'unadmitted effect instruction '+hx(a))
        trace.append(a);need(len(trace)<=1000,'effect instruction budget')
        if pending and a==pending[-1]['return_pc']:
            call=pending.pop();call['after']=regs();call['fpcw_after']=uc.reg_read(UC_X86_REG_FPCW)
            need(call['after']['esp']==call['before']['esp'],'cdecl RNG/CRT stack mismatch')
            need(all(call['after'][k]==call['before'][k] for k in ('ebx','ebp','esi','edi')),'RNG/CRT saved-register mismatch')
            need(call['fpcw_before']==call['fpcw_after'],'RNG/CRT precision changed')
            if call['target']=='0090cfc0':
                call['rng_final']=oracle.state();v=call['after']['eax'];v=v if v<0x80000000 else v-0x100000000
                rng.append({'site':call['site'],'bound':call['args'][0],'value':v,'initial':call['rng_initial'],'final':call['rng_final']})
        ins=insns[a]
        if ins.mnemonic=='call':
            target=ins.operands[0].imm;need(target in ARGC,'unadmitted effect callee '+hx(target))
            stack=uc.reg_read(prefix.REGS['esp'])
            call={'site':hx(a),'target':hx(target),'return_pc':a+size,'before':regs(),
              'args':[word(stack+k*4) for k in range(ARGC[target])],
              'fpcw_before':uc.reg_read(UC_X86_REG_FPCW)}
            if target==0x90cfc0:call['rng_initial']=oracle.state()
            calls.append(call);pending.append(call)
    def memory(m,access,a,size,value,data):
        write=access==unicorn.UC_MEM_WRITE
        need(any(base<=a and a+size<=base+n for base,n in REGIONS) or
             any(cell<=a and a+size<=cell+4 for cell in CELLS),'unadmitted effect memory '+hx(a))
        observed=(value&((1<<(size*8))-1)) if write else int.from_bytes(uc.mem_read(a,size),'little')
        e=[hx(current),'write' if write else 'read',hx(a),size,observed];events.append(e)
        if not prefix.STACK<=a<prefix.STACK+0x10000:
            external.append(e)
            if write:need(a in (prefix.CURSOR,prefix.OFFSET,prefix.SEED) and size==4,'unexpected external write')
    hooks=[uc.hook_add(UC_HOOK_CODE,code),uc.hook_add(UC_HOOK_MEM_READ,memory),uc.hook_add(UC_HOOK_MEM_WRITE,memory)]
    try:uc.emu_start(START,STOP,count=1000)
    finally:
        for h in hooks:uc.hook_del(h)
    need(uc.reg_read(UC_X86_REG_EIP)==STOP,'did not reach diagnostic frontier')
    need([(c['site'],c['target']) for c in pending]==[('007024b4','006cfe10'),('006cfec2','0062ed70')],
         'unexpected unresolved calls at diagnostic frontier')
    need(calls[-1]['site']=='006cfec2' and calls[-1]['args']==[0] and calls[-1]['before']['ecx']==0,
         'null lookup call contract changed')
    after=snapshot(oracle)
    for name,(a,n) in zip(NAMES,REGIONS):
        if name!='stack':need(bytes(uc.mem_read(a,n))==originals[name],'nonstack region changed '+name)
    need(after['cells'][hx(LOOKUP)]==0 and after['cells'][hx(prefix.LIMIT)]==before['cells'][hx(prefix.LIMIT)],'immutable cells changed')
    need([word(sp+k*4) for k in range(5)]==args,'raw original effect arguments overwritten')
    need(before['fpcw']==after['fpcw'] and before['fptag']==after['fptag']==0xffff,'x87 boundary state changed')
    stopsp=after['registers']['esp'];diagnostic_args=[word(stopsp+k*4) for k in range(5)]
    need(diagnostic_args==[0x9e7f28,0,0,0x2007824,0x2007724],'diagnostic argument ABI changed')
    need(stopsp==0x2007708,'diagnostic stack boundary changed')
    for call in calls:
        call['returned']='after' in call;del call['return_pc']
    row={'prefix_case':case['id'],'prefix_record_sha256':sha(compact(reference)),
      'status':'stopped_before_unsupported_diagnostic_call','effect_returned':False,
      'before':before,'after':after,'raw_effect_argument_dwords':args,'diagnostic_argument_dwords':diagnostic_args,
      'call_trace':calls,'rng':rng,'ordered_external_memory_events':external,
      'instruction_steps':len(trace),'ordered_memory_events':len(events),
      'instruction_trace_sha256':sha(compact([hx(a) for a in trace])),
      'ordered_memory_trace_sha256':sha(compact(events))}
    if private is not None:private.append({'id':case['id'],'instructions':[hx(a) for a in trace],'memory':events})
    return row,set(trace),set(zip(trace,trace[1:]))


def generate(a,private=False):
    root=Path(__file__).resolve().parents[1]
    need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    need(sha((root/'scripts/emulate_action33_prefix_30.py').read_bytes())==PREFIX_SCRIPT,'R30-A emulator changed')
    raw=(root/'evidence/action33-prefix-30-oracle.bin').read_bytes();need(sha(raw)==PREFIX_ORACLE,'R30-A oracle changed')
    baseline=json.loads(gzip.decompress(raw));sites=extract(a.binary,a.exports09,a.exports10,a.runtime)
    data=a.binary.read_bytes();extra,_=instructions(data);p_ins,_=prefix.decode(data)
    admitted=dict(extra);admitted.update({k:v for k,v in p_ins.items() if 0x90cfc0<=k<0x90d02d or 0x946a04<=k<0x946a22})
    oracle=prefix.Oracle(data,code_ranges=prefix.RANGES+RANGES)
    oracle.uc.mem_map(prefix.MATCH,0x10000);oracle.uc.mem_map(prefix.POSITIONS,0x1000)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes();need(sha(table)==prefix.TABLE_HASH,'synthetic random table mismatch')
    oracle.uc.mem_write(prefix.TABLE,table)
    oracle.uc.mem_write(prefix.GRID,struct.pack('<108f',*[math.hypot(x,y) for y in range(12) for x in range(9)]))
    rows=[];starts=set();edges=set();traces=[] if private else None
    for n,reference in enumerate(baseline['cases']):
        case=prefix.make_case(n);actual,_,_=prefix.run_case(oracle,p_ins,case)
        need(compact(actual)==compact(reference),'actual R30-A prefix record changed '+str(n))
        row,s,e=continue_case(oracle,admitted,case,reference,traces)
        rows.append(row);starts.update(s);edges.update(e)
    result={'schema_version':1,'unit':'R30-B','specimen_sha256':prefix.EXPECTED,
      'prefix_baseline':sites['prefix_baseline'],'prefix_oracle_sha256':PREFIX_ORACLE,
      'scope':'same original machine after R30-A; no state repair; effect stops before diagnostic call and does not return',
      'start':'007024b4','stop_before':'0062ed99','unsupported_callee':'00944cff',
      'lookup_global_initialization':'00b63d28 lies outside raw PE backing and remains zero in the shared mapped image; no game initializer ran',
      'cases':rows,'coverage':{'cases':len(rows),'effect_returns':0,'diagnostic_stops':len(rows),
       'instruction_steps':sum(r['instruction_steps'] for r in rows),'ordered_memory_events':sum(r['ordered_memory_events'] for r in rows),
       'rng_calls':sum(len(r['rng']) for r in rows),'covered_instruction_starts':[hx(v) for v in sorted(starts)],
       'covered_edges':[[hx(x),hx(y)] for x,y in sorted(edges)]}}
    return result,traces


if __name__=='__main__':
    p=parser();p.add_argument('--private-trace',type=Path);a=p.parse_args()
    if a.private_trace:need(a.private_trace.resolve().is_relative_to(Path(__file__).resolve().parents[1]/'results'),'private trace must stay in results/')
    result,traces=generate(a,a.private_trace is not None)
    a.output.write_bytes(packed(result))
    if a.private_trace:a.private_trace.write_bytes(compact(traces)+b'\n')
    print(json.dumps({k:v for k,v in result['coverage'].items() if not k.startswith('covered_')}))

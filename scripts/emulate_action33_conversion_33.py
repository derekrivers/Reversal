#!/usr/bin/env python3
"""R33-A original-produced conversion and caller continuation; synthetic inputs."""
import json
from pathlib import Path
import struct
import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_opponent_32 as prior
from extract_action33_prefix_30 import rows,compare,normalized
p,g=prior.p,prior.g
STOP,GUARD_STOP,CONVERSION=0x702222,prior.GUARD_STOP,0x945640
RANGES=((g.ENTRY,STOP),*prior.RANGES[1:],(CONVERSION,0x945667))
FILES=prior.FILES
FTOL_FILES={'00945640.asm':'260f116e854f9faed18fe32a81cf1a105048bd6dbff0527021273f7bb5167937',
 '00945640.c':'12962a708ac9e4e3c8a39ce6885c59e49e73474f0df1b7fe1013537b86bfb101'}
OPPONENT_SOURCE='bca0b2487c6bca4db7d8a586183c1b9388866aedb9fe260229c07391b18785b9'
PRIOR_ORACLE='cb721094cdebd96b0ff87f1bae68afe437091c17a0277e52c362a348c5683ab6'
FOCUSED_MANIFEST='42425fa15eeb2da209497e396b81bacc99e77a2c608500cdd9febd7ee9091f79'
STATIC=(*prior.STATIC,(0x967890,8,1.0))
REGIONS={**g.REGIONS,**{p.hx(a):(a,n) for a,n,_ in STATIC}}
CALLS={**prior.CALLS,0x702193:(CONVERSION,0),0x7021e5:(g.HELPER,2)}
FP_SITES=(0x945647,0x945659,0x94565f)


def bit04_static(data,focused):
    raw=(focused/'manifest.json').read_bytes();p.need(p.sha(raw)==FOCUSED_MANIFEST,'focused manifest mismatch')
    meta=json.loads(raw);p.need(meta['specimen_sha256']==p.EXPECTED,'focused specimen mismatch');files={}
    for ext in ('.asm','.c','.refs'):
        name='005b58e0'+ext;raw=(focused/name).read_bytes();expected=meta['files'][name]
        p.need(len(raw)==expected['bytes'] and p.sha(raw)==expected['sha256'],'focused file mismatch '+name);files[name]=p.sha(raw)
    start,end=0x5b58e0,0x5b590a;off=p.pe_offset(data,start,end-start);raw=data[off:off+end-start]
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);decoded={i.address:i for i in md.disasm(raw,start)}
    p.need(sum(i.size for i in decoded.values())==len(raw),'incomplete bit04 helper')
    native=rows(focused/'005b58e0.asm');p.need(set(native)==set(decoded),'bit04 native address set mismatch');compare(decoded,native)
    return {'scope':'independent static local body only; not executed beyond the retained bit04 stop and not joined to the clear path',
      'native_manifest_sha256':FOCUSED_MANIFEST,'native_exports':files,'entry':p.hx(start),'end_exclusive':p.hx(end),'file_offset':p.hx(off),'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(decoded),
      'reads':[{'site':'005b58e0','width':1,'source':'signed low argument byte at ESP+4'},
       {'site':'005b58e5','width':4,'source':'signed dword at ECX+5bf+4*signed8(argument)'},
       {'site':'005b58fa','width':4,'source':'global 00ae23bc; only when indexed dword >= 0'}],
      'returns':['005b5902','005b5907'],'stack_cleanup':4,'calls':[],
      'return_expression':'indexed dword < 0: EAX=0; otherwise EAX=uint32(global[00ae23bc]+110*indexed_dword)',
      'writes':'none except CALL stack outside this local body','unresolved':'table-row producer, global 00ae23bc initialization/lifetime, pointer validity and later 007160f0 candidate matching'}


def schedule():
    result=prior.schedule()
    for source in (0,1,10,11):
        for value in (0.,1.,1.5,13.5,13.9375,14.,16.):
            result.append({'source_case':source,'mode':'distance','distance':value})
    # These are supplied-checkpoint helper comparisons, separately labelled.
    # The checkpoint and ST0 are produced by the original resolver entry at each CW.
    for source in (0,10):
        for rc in range(4):
            for value in (0.,1.5,13.9375,16.):
                result.append({'source_case':source,'mode':'rounding-probe','distance':value,'rc':rc})
    return result


def seed(machine,c):
    setup={**c,'mode':'baseline'} if c['mode'] in ('distance','rounding-probe') else c
    result=prior.seed(machine,setup)
    if 'distance' in c:machine.uc.mem_write(p.GRID,struct.pack('<108f',*[c['distance']]*108))
    if c['mode']=='rounding-probe':
        cw=machine.uc.reg_read(x.UC_X86_REG_FPCW)|(c['rc']<<10);machine.uc.reg_write(x.UC_X86_REG_FPCW,cw)
    return result


def native_rows(caller):
    native=rows(caller);folder=caller.parent
    for name,digest in FTOL_FILES.items():p.need(p.sha((folder/name).read_bytes())==digest,'conversion native file mismatch '+name)
    native.update(rows(folder/'00945640.asm'))
    p.need(normalized(native[0x945646])==normalized('fstcw word ptr [ebp-2]') and 0x945647 not in native,'native WAIT/FNSTCW fusion changed')
    native[0x945646]='wait';native[0x945647]='fnstcw word ptr [ebp-2]'
    return native


def extract(binary,fresh,caller):
    data,_,previous=prior.extract(binary,fresh,caller);native=native_rows(caller)
    for stem in FILES:native.update(rows(fresh/(stem+'.asm')))
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ins={};ranges=[]
    for a,b in RANGES+((STOP,STOP+5),(GUARD_STOP,GUARD_STOP+5)):
        off=p.pe_offset(data,a,b-a);raw=data[off:off+b-a];seq=list(md.disasm(raw,a))
        p.need(sum(i.size for i in seq)==len(raw),'incomplete range');compare({i.address:i for i in seq},native)
        ins.update((i.address,i) for i in seq);ranges.append({'start':p.hx(a),'end_exclusive':p.hx(b),'file_offset':p.hx(off),'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(seq),'executed':a not in (STOP,GUARD_STOP)})
    p.need(ins[STOP].op_str=='0x713e90' and ins[GUARD_STOP].op_str=='0x5b58e0','unsupported call changed')
    constants=[]
    for a,n,value in STATIC:
        off=p.pe_offset(data,a,n);raw=data[off:off+n]
        p.need(struct.unpack('<d' if n==8 else '<f',raw)[0]==value,'scalar constant changed')
        constants.append({'va':p.hx(a),'bytes':n,'value':value,'sha256':p.sha(raw)})
    edges=[]
    for a,i in ins.items():
        if a in (STOP,GUARD_STOP) or i.mnemonic.startswith('ret'):continue
        if i.mnemonic.startswith('j'):targets=[i.operands[0].imm]+([] if i.mnemonic=='jmp' else [a+i.size])
        elif i.mnemonic=='call':targets=[i.operands[0].imm,a+i.size]
        else:targets=[a+i.size]
        p.need(all(t in ins for t in targets),'CFG escape '+p.hx(a));edges.extend([[p.hx(a),p.hx(t)] for t in targets])
    return data,ins,{'specimen_sha256':p.EXPECTED,'native_manifest_sha256':g.MANIFEST,'native_exports':{**previous['native_exports'],**FTOL_FILES},
      'caller_export_sha256':g.CALLER,'prefix_setup_source_sha256':g.SOURCE,'grid_source_sha256':prior.GRID_SOURCE,
      'opponent_source_sha256':OPPONENT_SOURCE,'opponent_oracle_sha256':PRIOR_ORACLE,'ranges':ranges,'constants':constants,
      'cfg_edges':len(edges),'cfg_sha256':p.sha(p.compact(edges)),'original_grid':previous['original_grid'],
      'next_calls':{'guard_clear':['00702222','00713e90'],'guard_set':['0071614b','005b58e0']}}


def generate(a):
    root=Path(__file__).resolve().parents[1]
    for name,digest in (('emulate_action33_prefix_30.py',g.SOURCE),('emulate_action33_grid_31.py',prior.GRID_SOURCE),('emulate_action33_opponent_32.py',OPPONENT_SOURCE)):
        p.need(p.sha((root/'scripts'/name).read_bytes())==digest,'dependency source changed '+name)
    p.need(unicorn.__version__=='2.1.4','Unicorn version mismatch')
    data,ins,sites=extract(a.binary,a.fresh,a.caller);sites['bit04_static']=bit04_static(data,a.focused)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes();p.need(p.sha(table)==p.TABLE_HASH,'synthetic table mismatch')
    machine=p.Oracle(data,code_ranges=RANGES+((STOP,STOP+5),(GUARD_STOP,GUARD_STOP+5)));u=machine.uc
    u.mem_map(p.MATCH,0x10000);u.mem_map(p.POSITIONS,0x1000);u.mem_write(p.TABLE,table)
    result=[]
    for number,c in enumerate(schedule()):
        seed(machine,c);before=g.state(machine);trace=[];events=[];calls=[];pending=[];checkpoint=None;conversion=None;pc=0;fp_observations=[]
        end=GUARD_STOP if c['mode']=='flag-set' else 0x702198 if c['mode']=='rounding-probe' else STOP
        def capture(regions):
            return {'state':g.state(machine),'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in regions.items()},'trace_length':len(trace),'event_length':len(events),'call_length':len(calls)}
        def code(m,address,size,unused):
            nonlocal pc,checkpoint,conversion
            if pending and pending[-1][0]==address:
                _,index=pending.pop();calls[index]['after']=g.state(machine)
            if address in (prior.STOP,GUARD_STOP):checkpoint=capture(prior.REGIONS)
            if address==prior.STOP:conversion=capture(REGIONS)
            if address in (STOP,GUARD_STOP) or address==end:
                p.need(address==end,'unexpected stop');u.emu_stop();return
            pc=address;p.need(address in ins,'instruction outside admitted segment');trace.append(p.hx(address))
            if address in FP_SITES:
                state=g.state(machine);fp_observations.append({'site':p.hx(address),**{k:state[k] for k in ('fpcw','fpsw','fptag','active_x87')}})
            if address in CALLS:
                target,argc=CALLS[address]
                calls.append({'site':p.hx(address),'target':p.hx(target),'before':g.state(machine),
                  'arguments':list(struct.unpack('<'+'I'*argc,u.mem_read(u.reg_read(x.UC_X86_REG_ESP),4*argc))) if argc else [],'after':None})
                pending.append((address+size,len(calls)-1))
        def memory(m,kind,address,size,value,unused):
            p.need(any(base<=address and address+size<=base+n for base,n in REGIONS.values()),'unadmitted data access')
            write=kind==unicorn.UC_MEM_WRITE
            p.need(not write or not any(base<=address<base+n for base,n,_ in STATIC),'immutable scalar write')
            value=value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            events.append([p.hx(pc),'write' if write else 'read',p.hx(address),size,f'{value:016x}' if size==8 else value])
        hooks=[u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(g.ENTRY,0x3000000,count=3500)
        finally:
            for hook in hooks:u.hook_del(hook)
        p.need(u.reg_read(x.UC_X86_REG_EIP)==end,'segment did not terminate')
        p.need(bool(checkpoint),'caller checkpoint missing');after=g.state(machine)
        p.need(before['rng']==after['rng'] and before['rng_cells']==after['rng_cells'],'unexpected RNG change')
        if c['mode']!='flag-set':p.need(not pending,'unreturned call')
        result.append({'id':number,'case':c,'before':before,'checkpoint':checkpoint,'conversion':conversion,'after':after,'stop':p.hx(end),
          'calls':calls,'events':events,'instruction_trace':trace,'fp_observations':fp_observations,'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}})
    return {'unit':'R33-A','sites':sites,'cases':result,
      'scope':'synthetic original resolver entry to next call; rounding probes compare only original-produced conversion checkpoints; bit04 remains separate; no shot outcome',
      'coverage':{'cases':len(result),'guard_clear':sum(r['stop']==p.hx(STOP) for r in result),'guard_set':sum(r['stop']==p.hx(GUARD_STOP) for r in result),
        'rounding_probes':sum(r['case']['mode']=='rounding-probe' for r in result),'instructions':sum(len(r['instruction_trace']) for r in result),'events':sum(len(r['events']) for r in result),'rng_calls':0}}


def parser():
    parser=g.parser();parser.add_argument('--focused',type=Path,required=True);return parser


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(p.packed(result));print(json.dumps(result['coverage']))

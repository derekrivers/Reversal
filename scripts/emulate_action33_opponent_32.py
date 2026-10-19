#!/usr/bin/env python3
"""R32-A original resolver entry through guarded opponent scan and next calls."""
import json
from pathlib import Path
import struct
import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_prefix_30 as p
import emulate_action33_grid_31 as g
from extract_action33_prefix_30 import rows,compare

STOP,GUARD_STOP=0x702193,0x71614b
RANGES=((g.ENTRY,STOP),(g.HELPER,0x6f09ed),(0x6d59b0,0x6d5a0d),
 (0x714d30,0x714d34),(0x7160f0,GUARD_STOP),(0x716194,0x71619b),(0x5b57c0,0x5b57cf))
FILES=('006f09b0','006d59b0','00714d30','007160f0','005b57c0')
GRID_SOURCE='1f9af1f80c5692939ee0249b14556dcbc6acfc1b47bdd0577f2e68740b16d31d'
STATIC=((0x96d810,8,1680.0),(0x96d754,4,9.0),(0x968e18,8,2.5))
REGIONS={**g.REGIONS,**{p.hx(a):(a,n) for a,n,_ in STATIC}}
CALLS={0x702088:(0x6f09b0,2),0x70210b:(0x6d59b0,1),0x6d59bc:(0x714d30,0),
 0x6d59f0:(0x7160f0,0),0x71611c:(0x5b57c0,1)}


def schedule():
    result=[{'source_case':n,'mode':'baseline'} for n in range(160)]
    for source in (0,1,10,11):
        for mode in ('inactive','all-active','late-active','index-127'):
            for flag in (0,0xfb):result.append({'source_case':source,'mode':mode,'flag':flag})
        for index in (0,19):
            for flag in (4,0xff):result.append({'source_case':source,'mode':'flag-set','index':index,'flag':flag})
        for momentum in (1679,1680,1681):result.append({'source_case':source,'mode':'comparison','momentum':momentum})
    return result


def seed(machine,c):
    source=p.make_case(c['source_case']);initial,_,_,shooter=p.setup(machine,source)
    u=machine.uc;u.mem_write(p.GRID,g.grid(0))
    if c['mode']=='comparison':u.mem_write(p.MATCH+0x4786,struct.pack('<i',c['momentum']))
    elif c['mode']!='baseline':
        side=1-source['side'];base=p.MATCH+p.BASES[side]
        for k in range(20):
            active=c['mode']=='all-active' or (c['mode']=='late-active' and k==19) or (c['mode']=='index-127' and k==0) or (c['mode']=='flag-set' and k==c['index'])
            index=127 if c['mode']=='index-127' else k
            u.mem_write(base+k*p.STRIDE+0x19,bytes([index if active else 255]))
            if active:u.mem_write(p.MATCH+0x91e2+0x18e3*side+0x5b4+index,bytes([c['flag']]))
    return initial,shooter


def extract(binary,fresh,caller):
    data,_,prior=g.extract(binary,fresh,caller)
    meta=json.loads((fresh/'manifest.json').read_bytes());native=rows(caller);files={}
    for stem in FILES:
        for ext in ('.asm','.c'):
            name=stem+ext;raw=(fresh/name).read_bytes();m=meta['files'][name]
            p.need(len(raw)==m['bytes'] and p.sha(raw)==m['sha256'],'native file mismatch '+name);files[name]=m['sha256']
        native.update(rows(fresh/(stem+'.asm')))
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ins={};ranges=[]
    for a,b in RANGES+((STOP,STOP+5),(GUARD_STOP,GUARD_STOP+5)):
        off=p.pe_offset(data,a,b-a);raw=data[off:off+b-a];seq=list(md.disasm(raw,a))
        p.need(sum(i.size for i in seq)==len(raw),'incomplete range');compare({i.address:i for i in seq},native)
        ins.update((i.address,i) for i in seq);ranges.append({'start':p.hx(a),'end_exclusive':p.hx(b),'file_offset':p.hx(off),'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(seq),'executed':a not in (STOP,GUARD_STOP)})
    p.need(ins[STOP].op_str=='0x945640' and ins[GUARD_STOP].op_str=='0x5b58e0','unsupported call changed')
    constants=[]
    for a,n,value in STATIC:
        off=p.pe_offset(data,a,n);raw=data[off:off+n]
        p.need(struct.unpack('<d' if n==8 else '<f',raw)[0]==value,'scalar constant changed')
        constants.append({'va':p.hx(a),'bytes':n,'value':value,'sha256':p.sha(raw)})
    edges=[]
    for a,i in ins.items():
        if a in (STOP,GUARD_STOP):continue
        if i.mnemonic.startswith('ret'):continue
        if i.mnemonic.startswith('j'):
            targets=[i.operands[0].imm]+([] if i.mnemonic=='jmp' else [a+i.size])
        elif i.mnemonic=='call':targets=[i.operands[0].imm,a+i.size]
        else:targets=[a+i.size]
        p.need(all(t in ins for t in targets),'CFG escape '+p.hx(a));edges.extend([[p.hx(a),p.hx(t)] for t in targets])
    return data,ins,{'specimen_sha256':p.EXPECTED,'native_manifest_sha256':g.MANIFEST,'native_exports':files,
      'caller_export_sha256':g.CALLER,'prefix_setup_source_sha256':g.SOURCE,'grid_source_sha256':GRID_SOURCE,'ranges':ranges,'constants':constants,
      'cfg_edges':len(edges),'cfg_sha256':p.sha(p.compact(edges)),'original_grid':prior['original_grid'],
      'next_calls':{'guard_clear':['00702193','00945640'],'guard_set':['0071614b','005b58e0']}}


def generate(a):
    root=Path(__file__).resolve().parents[1]
    p.need(p.sha((root/'scripts/emulate_action33_prefix_30.py').read_bytes())==g.SOURCE,'prefix setup source changed')
    p.need(p.sha((root/'scripts/emulate_action33_grid_31.py').read_bytes())==GRID_SOURCE,'grid dependency source changed')
    p.need(unicorn.__version__=='2.1.4','Unicorn version mismatch')
    data,ins,sites=extract(a.binary,a.fresh,a.caller)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes();p.need(p.sha(table)==p.TABLE_HASH,'synthetic table mismatch')
    # Include the two stop instructions only so the original hook can stop before execution.
    machine=p.Oracle(data,code_ranges=RANGES+((STOP,STOP+5),(GUARD_STOP,GUARD_STOP+5)));u=machine.uc
    u.mem_map(p.MATCH,0x10000);u.mem_map(p.POSITIONS,0x1000);u.mem_write(p.TABLE,table)
    result=[]
    for number,c in enumerate(schedule()):
        seed(machine,c);before=g.state(machine);trace=[];events=[];calls=[];pending=[];checkpoint=None;pc=0
        end=GUARD_STOP if c['mode']=='flag-set' else STOP
        def code(m,address,size,unused):
            nonlocal pc,checkpoint
            if address in (STOP,GUARD_STOP):
                p.need(address==end,'unexpected stop');u.emu_stop();return
            pc=address;p.need(address in ins,'instruction outside admitted segment');trace.append(p.hx(address))
            if address==0x70210b:
                checkpoint={'state':g.state(machine),'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in g.REGIONS.items()},'trace_length':len(trace)-1,'event_length':len(events)}
            if pending and pending[-1][0]==address:
                _,index=pending.pop();calls[index]['after']=g.state(machine)
            if address in CALLS:
                target,argc=CALLS[address]
                calls.append({'site':p.hx(address),'target':p.hx(target),'before':g.state(machine),
                  'arguments':list(struct.unpack('<'+'I'*argc,u.mem_read(u.reg_read(x.UC_X86_REG_ESP),4*argc))) if argc else [],'after':None})
                pending.append((address+size,len(calls)-1))
        def memory(m,kind,address,size,value,unused):
            p.need(any(base<=address and address+size<=base+n for base,n in REGIONS.values()),'unadmitted data access')
            write=kind==unicorn.UC_MEM_WRITE
            p.need(not write or not any(address==a for a,_,_ in STATIC),'immutable scalar write')
            value=value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            # Qwords use a fixed hexadecimal scalar to avoid JSON number precision loss.
            events.append([p.hx(pc),'write' if write else 'read',p.hx(address),size,f'{value:016x}' if size==8 else value])
        hooks=[u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(g.ENTRY,0x3000000,count=3000)
        finally:
            for hook in hooks:u.hook_del(hook)
        p.need(u.reg_read(x.UC_X86_REG_EIP)==end,'segment did not terminate')
        p.need(bool(checkpoint),'caller checkpoint missing');after=g.state(machine)
        p.need(before['rng']==after['rng'] and before['rng_cells']==after['rng_cells'],'unexpected RNG change')
        if c['mode']!='flag-set':p.need(not pending,'unreturned call')
        result.append({'id':number,'case':c,'before':before,'checkpoint':checkpoint,'after':after,'stop':p.hx(end),
          'calls':calls,'events':events,'instruction_trace':trace,'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}})
    return {'unit':'R32-A','sites':sites,'cases':result,
      'scope':'original instructions on synthetic state; resolver entry to next bounded call; no live-game observation or shot outcome',
      'coverage':{'cases':len(result),'guard_clear':sum(r['stop']==p.hx(STOP) for r in result),'guard_set':sum(r['stop']==p.hx(GUARD_STOP) for r in result),
        'instructions':sum(len(r['instruction_trace']) for r in result),'events':sum(len(r['events']) for r in result),'rng_calls':0}}


if __name__=='__main__':
    a=g.parser().parse_args();result=generate(a);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(p.packed(result));print(json.dumps(result['coverage']))

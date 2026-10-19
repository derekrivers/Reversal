#!/usr/bin/env python3
"""Project the same R30-A original-entry runs onto the bounded TS composition.

The checkpoint is captured before 007022fd, without changing the live machine.
Only synthetic game-region operands are retained; CPU stack traces stay private.
"""
import gzip
import json
from pathlib import Path

import unicorn
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
import emulate_action33_prefix_30 as prefix
from extract_action33_prefix_30 import parser,extract
from emulate_action33_prefix_30 import need,sha,compact,packed,hx

START=0x7022fd
PREFIX_ORACLE='08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f'
PREFIX_SCRIPT='9486fdba017157b918081023641a2360a392839c2339c287e2a8fa97d28cee32'
PREFIX_SITES='6744c3025127c5ff5aef691f9aa0e3001a2858982ac1affcf6b22c5b9abe26c6'
TARGETS={0x6ce110,0x700420,0x6c38c0,0x90cfc0}


def project_call(c):
    target=int(c['target'],16);args=c['args'];receiver=None
    if target==0x6ce110:receiver=c['before']['ecx'];args=[args[0]&255]
    elif target==0x700420:receiver=c['before']['ecx'];args=[v&255 for v in args[:4]]
    elif target==0x6c38c0:receiver=c['before']['ecx']
    else:args=[args[0] if args[0]<0x80000000 else args[0]-0x100000000]
    return {'site':c['site'],'target':c['target'],'receiver':receiver,'args':args}


def generate(a):
    root=Path(__file__).resolve().parents[1]
    need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    need(sha((root/'scripts/emulate_action33_prefix_30.py').read_bytes())==PREFIX_SCRIPT,'prefix source changed')
    original=(root/'evidence/action33-prefix-30-oracle.bin').read_bytes()
    need(sha(original)==PREFIX_ORACLE,'prefix oracle changed')
    native=extract(a.binary,a.fresh,a.r29,a.preflight,a.caller,a.runtime)
    need(sha((json.dumps(native,indent=2)+'\n').encode())==PREFIX_SITES,'prefix static evidence changed')
    baseline=json.loads(gzip.decompress(original));data=a.binary.read_bytes();insns,_=prefix.decode(data)
    machine=prefix.Oracle(data,code_ranges=prefix.RANGES);uc=machine.uc
    uc.mem_map(prefix.MATCH,0x10000);uc.mem_map(prefix.POSITIONS,0x1000)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes()
    need(sha(table)==prefix.TABLE_HASH,'synthetic table changed');uc.mem_write(prefix.TABLE,table)
    import math,struct
    grid=struct.pack('<108f',*[math.hypot(x,y) for y in range(12) for x in range(9)])
    uc.mem_write(prefix.GRID,grid)
    rows=[]
    for n,reference in enumerate(baseline['cases']):
        case=prefix.make_case(n);_,initial_match,_,_=prefix.setup(machine,case)
        capture={};selector=[];writes=[];active=False;pc=0
        def code(m,address,size,unused):
            nonlocal active,pc
            pc=address
            if address==START:
                need(not active,'checkpoint reached twice');active=True
                frame=uc.reg_read(prefix.REGS['esp']);shooter=uc.reg_read(prefix.REGS['esi'])
                checkpoint=bytes(uc.mem_read(prefix.MATCH,0x10000))
                patches=[[i,v] for i,v in enumerate(checkpoint) if v!=initial_match[i]]
                need(all(i in (0x8d4c,0x8d4d,0x8d4e) for i,v in patches),'new prior game-state producer')
                capture.update(input={'match':prefix.MATCH,'shooter':shooter,
                  'action':uc.mem_read(frame+0x698,1)[0],'mode':uc.mem_read(frame+0x6a4,1)[0],
                  'zeroLocalByte':uc.mem_read(frame+0x30,1)[0],
                  'marker260':uc.mem_read(frame+0x19,1)[0],'marker375':uc.mem_read(frame+0x1a,1)[0],
                  'precisionBits':case['precision_bits']},rng=machine.state(),patches=patches,
                  match_sha256=sha(checkpoint),positions_sha256=sha(bytes(uc.mem_read(prefix.POSITIONS,0x1000))))
        def memory(m,access,address,size,value,unused):
            if not active:return
            if not any(base<=address and address+size<=base+length for base,length in
                       ((prefix.MATCH,0x10000),(prefix.POSITIONS,0x1000))):return
            write=access==unicorn.UC_MEM_WRITE
            v=value&((1<<(size*8))-1) if write else int.from_bytes(uc.mem_read(address,size),'little')
            event=['write' if write else 'read',hx(address),size,v]
            if 0x6ce110<=pc<0x6ce304:selector.append(event)
            if write:writes.append(event)
        hooks=[uc.hook_add(UC_HOOK_CODE,code),uc.hook_add(UC_HOOK_MEM_READ,memory),uc.hook_add(UC_HOOK_MEM_WRITE,memory)]
        try:actual,_,_=prefix.run_case(machine,insns,case)
        finally:
            for h in hooks:uc.hook_del(h)
        need(compact(actual)==compact(reference),'original-entry prefix changed '+str(n))
        need(active,'checkpoint absent')
        start=next(i for i,c in enumerate(actual['call_trace']) if c['site']=='0070230c')
        calls=[project_call(c) for c in actual['call_trace'][start:] if int(c['target'],16) in TARGETS]
        draw_rows=actual['rng'][1:]
        keeper_return=next(c for c in actual['call_trace'] if c['site']=='00702416')
        eligible=any(c['site']=='007004da' for c in actual['call_trace'])
        fallback=actual['flags']['00000014'];path='rejected' if not eligible else ('retained' if not fallback else
             ('weighted' if any(r['site']=='00700b1e' for r in draw_rows) else 'redrawn'))
        rows.append({'case':case,'checkpoint':capture,'selector_memory':selector,'game_writes':writes,
          'calls':calls,'draws':draw_rows,'result':{
            'keeper':keeper_return['before']['ecx'],'variant':actual['flags']['0000001c'],
            'responseWord':actual['keeper_response_raw']&65535,'positionFlag':actual['flags']['00000020'],
            'fallbackFlag':fallback,'marker260':actual['flags']['00000019'],'marker375':actual['flags']['0000001a'],
            'eligible':eligible,'path':path,'outgoingArgumentDwords':actual['outgoing_argument_dwords']},
          'final_rng':actual['final_rng'],'final_memory_sha256':{k:actual['memory_sha256'][k] for k in ('match','positions','random_table','grid')}})
    return {'unit':'R30-C','schema_version':1,'specimen_sha256':prefix.EXPECTED,
      'prefix_oracle_sha256':PREFIX_ORACLE,'prefix_emulator_sha256':PREFIX_SCRIPT,'prefix_sites_sha256':PREFIX_SITES,
      'start':'007022fd','stop_before':'007024b4','cases':rows,
      'scope':'semantic composition from original-entry-produced checkpoint; selector operands, projected calls, per-draw RNG and game memory; no full caller/stack equivalence',
      'first_missing_entry_callee':{'site':'00702088','target':'006f09b0'},
      'coverage':{'cases':len(rows),'selector_events':sum(len(r['selector_memory']) for r in rows),
        'game_writes':sum(len(r['game_writes']) for r in rows),'draws':sum(len(r['draws']) for r in rows)}}


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_bytes(packed(result));print(json.dumps(result['coverage']))

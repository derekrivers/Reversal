#!/usr/bin/env python3
"""R30-A: execute original mode-3/action33 entry through the pre-effect boundary.

No callee replacement, instruction patch, saved game, or original table is used.
Outputs contain synthetic scalars and digests, never PE bytes or original data.
"""
import argparse
import gzip
import hashlib
import json
import math
from pathlib import Path
import struct

import capstone
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM
import unicorn
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
 UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
 UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_FPCW, UC_X86_REG_FPSW, UC_X86_REG_FPTAG)
from emulate_random import Oracle, EXPECTED, STACK, TABLE, TABLE_END, CURSOR, OFFSET, LIMIT, SEED

ENTRY, END = 0x702050, 0x7024b4
MATCH, POSITIONS = 0x4100000, 0x4300000
SP, FRAME = STACK+0x8000, STACK+0x8000-0x694
GRID = 0xa15e44
BASES = (0x4796,0x6a6e)
STRIDE = 0x1be
TABLE_HASH = 'befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db'
# Endpoints are exact instruction boundaries. The body subsets are deliberately
# smaller than the functions, so unsupported dependency paths fail closed.
RANGES = ((ENTRY,END), (0x6f09b0,0x6f09ed), (0x6d59b0,0x6d5a0d),
 (0x714d30,0x714d34), (0x7160f0,0x716125), (0x716194,0x71619b),
 (0x5b57c0,0x5b57cf), (0x713e90,0x713ef5), (0x713fba,0x713fc0),
 (0x6ce110,0x6ce304), (0x700420,0x7004f1), (0x700a4f,0x700b9f),
 (0x6c38c0,0x6c38ea), (0x90cfc0,0x90d02d), (0x946a04,0x946a22),
 (0x945640,0x945667))
REGS = dict(zip(('eax','ebx','ecx','edx','esi','edi','ebp','esp'),
 (UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX,
 UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP,UC_X86_REG_ESP)))
ARGC = {0x6f09b0:2,0x6d59b0:1,0x714d30:0,0x7160f0:0,0x5b57c0:1,
 0x713e90:7,0x6ce110:1,0x700420:6,0x6c38c0:1,0x90cfc0:1,
 0x946a04:0,0x945640:0}
# Original immutable scalar constants and the two action dispatch entries.
STATIC = ((0x96d810,8),(0x96d754,4),(0x968e18,8),(0x967890,8),
 (0x9688b0,8),(0x968950,8),(0x968e40,8),(0x968e80,8),
 (0x96d698,8),(0x968ea8,8),(0x70a5c5,1),(0x70a5a4,4))


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compact(value):
    return json.dumps(value, separators=(',',':')).encode('utf-8')


def packed(value):
    payload=compact(value)+b'\n'
    result=gzip.compress(payload,compresslevel=9,mtime=0)
    need(result[:9]==bytes.fromhex('1f8b08000000000002'),'unexpected gzip header')
    return result[:9]+b'\xff'+result[10:]


def hx(a):
    return f'{a:08x}'


def pe_offset(data,va,length):
    need(data[:2]==b'MZ','MZ header')
    pe=struct.unpack_from('<I',data,0x3c)[0]
    need(data[pe:pe+4]==b'PE\0\0','PE signature')
    need(struct.unpack_from('<H',data,pe+4)[0]==0x14c,'x86 machine')
    opt=pe+24
    need(struct.unpack_from('<H',data,opt)[0]==0x10b,'PE32 magic')
    base=struct.unpack_from('<I',data,opt+28)[0]
    count,optlen=struct.unpack_from('<H',data,pe+6)[0],struct.unpack_from('<H',data,pe+20)[0]
    for k in range(count):
        _,rva,size,raw=struct.unpack_from('<IIII',data,opt+optlen+40*k+8)
        delta=va-base-rva
        if 0<=delta and delta+length<=size:
            return raw+delta
    raise ValueError('range lacks raw PE backing')


def decode(data):
    need(len(data)==7192576 and sha(data)==EXPECTED,'specimen size/SHA-256 mismatch')
    need(capstone.__version__=='5.0.7','requires Capstone 5.0.7')
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    insns={};ranges=[]
    for start,end in RANGES:
        off=pe_offset(data,start,end-start);body=data[off:off+end-start]
        decoded=list(md.disasm(body,start))
        need(sum(i.size for i in decoded)==len(body),'incomplete decode '+hx(start))
        insns.update((i.address,i) for i in decoded)
        ranges.append({'start':hx(start),'end_exclusive':hx(end),'file_offset':hx(off),
                       'bytes':len(body),'sha256':sha(body),'instructions':len(decoded)})
    return insns,ranges


def make_case(n):
    side=n%2;kind=(n//2)%5;precision=(53,64)[(n//10)%2]
    return {'id':n,'side':side,'selector_mode':('cache','direct','invalidate','fallback','activity-reject')[kind],
      'precision_bits':precision,'x':(n*5)%9,'y':(n*7)%12,
      'rating0_raw':(n*151+80)&65535,'rating1_raw':(n*97+190)&65535,
      'fallback_rating_raw':(0,700,32767,65535)[(n//4)%4],
      'counter_raw':n%256,'adjustment_float':float((n%41)-20),
      'match_byte_raw':(0,1,127,128,255)[(n//5)%5],
      'clock_word':(-32768,-1,0,1,10,300,32767)[(n//3)%7],
      'quality':(0,119,120,121,375,65535,0xffffffff)[n%7],
      'cursor_index':50999 if n%3==0 else n*101%51000,
      'offset':(n*971)%65536,'crt_state':(0x10203968+n*104729)&0xffffffff,
      'momentum':(0,1000000,-1000000)[n%3], 'state_byte':4 if n%7==0 else 0}


def setup(oracle,c):
    uc=oracle.uc;m=bytearray(0x10000);p=bytearray(0x1000)
    def w32(off,v):struct.pack_into('<I',m,off,v&0xffffffff)
    def w16(off,v):struct.pack_into('<H',m,off,v&65535)
    for side in (0,1):
        for k in range(20):
            q=BASES[side]+k*STRIDE
            m[q+0x19]=m[q+0x1a]=255;m[q+0x27]=side
            w32(q+0x19e,MATCH)
        q=BASES[side];m[q+0x19]=0
        m[q+0x102]=4;m[q+0x103]=11 if side==0 else 0
        m[q+0xf]=c['counter_raw'];m[q+0x2b]=2 if c['selector_mode']=='activity-reject' else 0
        for off,key in ((0x168,'rating0_raw'),(0x16a,'rating1_raw'),(0x3b,'fallback_rating_raw')):w16(q+off,c[key])
        struct.pack_into('<f',m,q+0xd1,c['adjustment_float'])
        # Getter 005b57c0 reads match + 91e2 + 18e3*side + 5b4 + tactical index.
        # Every value is initially zero, which proves the bit-04 bypass.
        w32(0x8ebc+4*side,POSITIONS+side*0x100)
        struct.pack_into('<H',p,side*0x100,0 if c['selector_mode']=='fallback' else 1)
        cache=MATCH+q if c['selector_mode'] in ('cache','activity-reject') else 0
        if c['selector_mode']=='invalidate':cache=MATCH+q+19*STRIDE
        w32(0xf59e+side*4,cache)
    shooter=BASES[c['side']]+3*STRIDE;m[shooter+0x19]=3
    m[shooter+0x102]=c['x'];m[shooter+0x103]=c['y'];w16(shooter+0x39,0xfff1)
    w16(shooter+0x198,0x33);w16(0x8ed0,c['clock_word'])
    w32(0x4782,12345);w32(0x4786,c['momentum'])
    m[0x8ea7]=c['x'];m[0x8ea8]=c['y'];m[0x8eaa]=c['match_byte_raw'];m[0x8ea9]=c['state_byte']
    uc.mem_write(MATCH,bytes(m));uc.mem_write(POSITIONS,bytes(p));uc.mem_write(STACK,b'\x00'*0x10000)
    args=[0x3000000,0x33,c['quality'],0x1f7f,3,0,0]
    uc.mem_write(SP,struct.pack('<7I',*args))
    initial={name:(0x12340000+k*0x101)&0xffffffff for k,name in enumerate(REGS)}
    initial.update(ecx=MATCH+shooter,esp=SP)
    for name,r in REGS.items():uc.reg_write(r,initial[name])
    uc.reg_write(UC_X86_REG_EFLAGS,0x202)
    uc.reg_write(UC_X86_REG_FPCW,0x27f if c['precision_bits']==53 else 0x37f)
    uc.reg_write(UC_X86_REG_FPSW,0);uc.reg_write(UC_X86_REG_FPTAG,0xffff)
    oracle.set_state({'cursorIndex':c['cursor_index'],'offset':c['offset'],'crtState':c['crt_state']})
    return initial,bytes(m),bytes(p),MATCH+shooter


def run_case(oracle,insns,c,private_traces=None,flag_violation=False):
    uc=oracle.uc;initial,before_match,before_positions,shooter=setup(oracle,c)
    if flag_violation:
        uc.mem_write(MATCH+0x91e2+0x18e3*(1-c['side'])+0x5b4,b'\x04')
    trace=[];events=[];calls=[];rng=[];pending=[];current=0;writes=[]
    def state():return oracle.state()
    def read_u32(a):return struct.unpack('<I',uc.mem_read(a,4))[0]
    def regs():return {name:uc.reg_read(r) for name,r in REGS.items()}
    def code(m,a,size,data):
        nonlocal current
        current=a
        need(a in insns and insns[a].size==size,'unadmitted instruction '+hx(a))
        trace.append(a);need(len(trace)<=10000,'step budget')
        if pending and a==pending[-1]['return_va_int']:
            call=pending.pop();call['after']=regs();call['fpcw_after']=uc.reg_read(UC_X86_REG_FPCW)
            if call['target']=='0090cfc0':
                value=uc.reg_read(UC_X86_REG_EAX);value=value if value<0x80000000 else value-0x100000000
                call['rng_final']=state();rng.append({'site':call['site'],'bound':call['args'][0] if call['args'][0]<0x80000000 else call['args'][0]-0x100000000,
                  'value':value,'initial':call['rng_initial'],'final':call['rng_final']})
        ins=insns[a]
        if ins.mnemonic=='call':
            need(ins.operands[0].type==CS_OP_IMM,'indirect call unsupported')
            target=ins.operands[0].imm
            need(target in ARGC,'unadmitted callee '+hx(target))
            sp=uc.reg_read(UC_X86_REG_ESP)
            call={'site':hx(a),'target':hx(target),'return_va_int':a+size,'before':regs(),
              'args':[read_u32(sp+4*k) for k in range(ARGC[target])],
              'fpcw_before':uc.reg_read(UC_X86_REG_FPCW)}
            if target==0x90cfc0:call['rng_initial']=state()
            calls.append(call);pending.append(call)
    def memory(m,access,a,size,value,data):
        write=access==unicorn.UC_MEM_WRITE
        synthetic=any(base<=a and a+size<=base+length for base,length in
          ((MATCH,0x10000),(POSITIONS,0x1000),(STACK,0x10000),(TABLE,TABLE_END-TABLE+4),(GRID,432),
           (CURSOR,4),(OFFSET,4),(LIMIT,4),(SEED,4)))
        constant=any(base<=a and a+size<=base+length for base,length in STATIC)
        need(synthetic or (constant and not write),'unadmitted memory '+hx(a)+' at '+hx(current))
        # Constants have digest-only provenance; exclude their values from public traces.
        observed=value&((1<<(size*8))-1) if write else int.from_bytes(uc.mem_read(a,size),'little')
        event=[hx(current),'write' if write else 'read',hx(a),size,observed if synthetic else 'constant']
        events.append(event)
        if write and MATCH<=a<MATCH+0x10000:writes.append(event)
    hooks=[uc.hook_add(UC_HOOK_CODE,code),uc.hook_add(UC_HOOK_MEM_READ,memory),uc.hook_add(UC_HOOK_MEM_WRITE,memory)]
    try:uc.emu_start(ENTRY,END,count=10000)
    finally:
        for hook in hooks:uc.hook_del(hook)
    need(uc.reg_read(UC_X86_REG_EIP)==END and not pending,'did not reach complete pre-call boundary')
    need(uc.reg_read(UC_X86_REG_ESP)==FRAME-20,'boundary stack mismatch')
    need(uc.reg_read(UC_X86_REG_ECX)==MATCH,'boundary receiver mismatch')
    outgoing=[read_u32(FRAME-20+4*k) for k in range(5)]
    need(outgoing[0]==shooter and outgoing[1:3]==[0x6d,0] and outgoing[3]&65535==0 and outgoing[4]==0,
         'boundary arguments mismatch')
    need(read_u32(SP+8)==c['quality'],'quality changed')
    need(bytes(uc.mem_read(POSITIONS,0x1000))==before_positions,'tactical tables changed')
    need(uc.reg_read(UC_X86_REG_FPCW)==(0x27f if c['precision_bits']==53 else 0x37f),'precision not restored')
    need(uc.reg_read(UC_X86_REG_FPTAG)==0xffff,'x87 stack not empty at boundary')
    need(len(rng)>=2 and [r['bound'] for r in rng[:2]]==[0,2],'caller RNG order changed')
    need(rng[0]['initial']==rng[0]['final'],'zero draw advanced state')
    for call in calls:
        need('after' in call,'unterminated call')
        target=int(call['target'],16);cleanup=0 if target in (0x714d30,0x7160f0,0x90cfc0,0x946a04,0x945640) else ARGC[target]*4
        need(call['after']['esp']==call['before']['esp']+cleanup,'callee stack contract '+call['target'])
        need(all(call['after'][r]==call['before'][r] for r in ('ebx','ebp','esi','edi')),'saved-register contract '+call['target'])
        need(call['fpcw_before']==call['fpcw_after'],'callee FPCW contract')
        del call['return_va_int']
    region_digests={'match':sha(bytes(uc.mem_read(MATCH,0x10000))),'positions':sha(bytes(uc.mem_read(POSITIONS,0x1000))),
      'stack':sha(bytes(uc.mem_read(STACK,0x10000))),'random_table':sha(bytes(uc.mem_read(TABLE,TABLE_END-TABLE+4))),
      'grid':sha(bytes(uc.mem_read(GRID,432)))}
    need(region_digests['random_table']==TABLE_HASH,'random table changed')
    need(region_digests['grid']==sha(struct.pack('<108f',*[math.hypot(x,y) for y in range(12) for x in range(9)])),
         'synthetic grid changed')
    # The only admitted non-stack writes are these observed state domains.
    need(all(int(e[2],16) not in range(POSITIONS,POSITIONS+0x1000) and
             not GRID<=int(e[2],16)<GRID+432 and not TABLE<=int(e[2],16)<=TABLE_END
             for e in events if e[1]=='write'),'write into immutable synthetic table')
    result={'input':c,'initial_registers':initial,'boundary_registers':regs(),'outgoing_argument_dwords':outgoing,
      'boundary_fpcw':uc.reg_read(UC_X86_REG_FPCW),'boundary_fpsw':uc.reg_read(UC_X86_REG_FPSW),
      'boundary_fptag':uc.reg_read(UC_X86_REG_FPTAG),'rng':rng,'final_rng':state(),
      'call_trace':calls,'match_writes':writes,'keeper_response_raw':read_u32(FRAME+0x38),
      'flags':{hx(o):uc.mem_read(FRAME+o,1)[0] for o in (0x14,0x19,0x1a,0x1c,0x20,0x25)},
      'instruction_steps':len(trace),'instruction_trace_sha256':sha(compact([hx(a) for a in trace])),
      'memory_events':len(events),'ordered_memory_trace_sha256':sha(compact(events)),
      'memory_sha256':region_digests}
    if private_traces is not None:private_traces.append({'id':c['id'],'instructions':[hx(a) for a in trace],'events':events})
    return result,set(trace),set(zip(trace,trace[1:]))


def generate(binary,table,private=False,count=160):
    data=binary.read_bytes();insns,ranges=decode(data)
    need(unicorn.__version__=='2.1.4','requires Unicorn 2.1.4')
    table_bytes=table.read_bytes();need(sha(table_bytes)==TABLE_HASH,'synthetic table SHA-256 mismatch')
    oracle=Oracle(data,code_ranges=RANGES)
    oracle.uc.mem_map(MATCH,0x10000);oracle.uc.mem_map(POSITIONS,0x1000)
    oracle.uc.mem_write(TABLE,table_bytes)
    grid=struct.pack('<108f',*[math.hypot(x,y) for y in range(12) for x in range(9)])
    oracle.uc.mem_write(GRID,grid)
    rows=[];starts=set();edges=set();traces=[] if private else None
    for n in range(count):
        row,s,e=run_case(oracle,insns,make_case(n),traces);rows.append(row);starts.update(s);edges.update(e)
    result={'schema_version':1,'unit':'R30-A','specimen_sha256':EXPECTED,'entry':hx(ENTRY),'stop_before':hx(END),
      'scope':'original mode3/action33 prefix with tactical bit04 clear in 007160f0; synthetic stable mapped state; no TypeScript equivalence claim',
      'emulator':'Unicorn 2.1.4 x86-32','synthetic_random_table_sha256':TABLE_HASH,
      'synthetic_grid_sha256':sha(grid),'code_ranges':ranges,
      'static_read_ranges':[{'va':hx(a),'bytes':n,'sha256':sha(data[pe_offset(data,a,n):pe_offset(data,a,n)+n])} for a,n in STATIC],
      'cases':rows,'coverage':{'cases':len(rows),'instruction_steps':sum(r['instruction_steps'] for r in rows),
        'memory_events':sum(r['memory_events'] for r in rows),'covered_instruction_starts':[hx(a) for a in sorted(starts)],
        'covered_edges':[[hx(a),hx(b)] for a,b in sorted(edges)]}}
    return result,traces


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('table',type=Path)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--private-trace',type=Path)
    a=p.parse_args()
    if a.private_trace:
        need(a.private_trace.resolve().is_relative_to(Path(__file__).resolve().parents[1]/'results'),'private trace must stay in results/')
    result,traces=generate(a.binary,a.table,a.private_trace is not None)
    a.output.write_bytes(packed(result) if a.output.suffix in ('.gz','.bin') else compact(result)+b'\n')
    if a.private_trace:a.private_trace.write_bytes(compact(traces)+b'\n')
    print(json.dumps({k:v for k,v in result['coverage'].items() if not k.startswith('covered_')}))

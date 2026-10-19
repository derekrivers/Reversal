#!/usr/bin/env python3
"""Original 006f09b0 and 00702050..0070210b with synthetic data only."""
import argparse
import gzip
import json
import math
from pathlib import Path
import struct

import capstone
import unicorn
from unicorn import x86_const as x
import emulate_action33_prefix_30 as p
from extract_action33_prefix_30 import rows,compare

ENTRY,STOP,HELPER,RETURN=0x702050,0x70210b,0x6f09b0,0x3000000
RANGES=((ENTRY,STOP),(HELPER,0x6f09ed))
SOURCE='9486fdba017157b918081023641a2360a392839c2339c287e2a8fa97d28cee32'
MANIFEST='5089d7a53a599ffaeada705cc7fb02ae62ab76070e3c886ac57cd99080019a4f'
CALLER='40afb06c0e55a22091d0aff2bcca1521feadc9fae0bb87f9416ab4a72472f8cf'
REGIONS={'match':(p.MATCH,0x10000),'positions':(p.POSITIONS,0x1000),
 'stack':(p.STACK,0x10000),'random_table':(p.TABLE,204000),'grid':(p.GRID,432)}
CELLS=(p.CURSOR,p.OFFSET,p.LIMIT,p.SEED)


def grid(pattern):
    if pattern==0:return struct.pack('<108f',*[math.hypot(a,b) for b in range(12) for a in range(9)])
    bits=(0,0x80000000,0x3f800000,0xbf800000,0x00800000,0x7f7fffff,0x80800000,0xff7fffff,0x3eaaaaab)
    return struct.pack('<108I',*[bits[n%len(bits)] for n in range(108)])


def extract(binary,fresh,caller):
    data=binary.read_bytes();p.need(p.sha(data)==p.EXPECTED and len(data)==7192576,'specimen SHA-256/size mismatch')
    p.need(capstone.__version__=='5.0.7','Capstone version mismatch')
    manifest=(fresh/'manifest.json').read_bytes();p.need(p.sha(manifest)==MANIFEST,'native manifest mismatch')
    meta=json.loads(manifest);p.need(meta['specimen_sha256']==p.EXPECTED,'native specimen mismatch')
    for name in ('006f09b0.asm','006f09b0.c'):
        payload=(fresh/name).read_bytes();m=meta['files'][name]
        p.need(len(payload)==m['bytes'] and p.sha(payload)==m['sha256'],'native file mismatch')
    p.need(p.sha(caller.read_bytes())==CALLER,'caller export mismatch')
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.detail=True
    ins={};sites=[]
    for a,b in RANGES+((STOP,STOP+5),):
        off=p.pe_offset(data,a,b-a);raw=data[off:off+b-a];seq=list(md.disasm(raw,a))
        p.need(sum(i.size for i in seq)==b-a,'incomplete range')
        native=rows(fresh/'006f09b0.asm') if a==HELPER else rows(caller)
        compare({i.address:i for i in seq},native);ins.update((i.address,i) for i in seq)
        sites.append({'start':p.hx(a),'end_exclusive':p.hx(b),'file_offset':p.hx(off),
          'bytes':len(raw),'sha256':p.sha(raw),'instructions':len(seq),'executed':a!=STOP})
    p.need(ins[STOP].op_str=='0x6d59b0','next call changed')
    grid_offset=p.pe_offset(data,p.GRID,432)
    return data,ins,{'specimen_sha256':p.EXPECTED,'native_manifest_sha256':MANIFEST,
      'caller_export_sha256':CALLER,'helper_exports':{n:meta['files'][n]['sha256'] for n in ('006f09b0.asm','006f09b0.c')},
      'prefix_setup_source_sha256':SOURCE,'ranges':sites,
      'original_grid':{'va':p.hx(p.GRID),'file_offset':p.hx(grid_offset),'bytes':432,'sha256':p.sha(data[grid_offset:grid_offset+432]),'contents_retained':False},
      'synthetic_grids':['float32 hypot(x,y), x=0..8/y=0..11','fixed finite normal/signed-zero bit patterns; not original game data'],
      'next_unsupported_call':{'site':'0070210b','target':'006d59b0'}}


def state(machine):
    u=machine.uc;tag=u.reg_read(x.UC_X86_REG_FPTAG);status=u.reg_read(x.UC_X86_REG_FPSW)
    active=[]
    for n in range(8):
        if (tag>>(n*2))&3!=3:
            significand,exponent=u.reg_read(getattr(x,'UC_X86_REG_FP'+str(n)))
            active.append({'physical':n,'significand':f'{significand:016x}','exponent':exponent})
    return {'registers':{k:u.reg_read(r) for k,r in p.REGS.items()},'eflags':u.reg_read(x.UC_X86_REG_EFLAGS),
      'fpcw':u.reg_read(x.UC_X86_REG_FPCW),'fpsw':status,'fptag':tag,'active_x87':active,
      'rng':machine.state(),'rng_cells':{p.hx(a):machine.get(a) for a in CELLS}}


def schedule():
    cases=[{'kind':'prefix','source_case':n,'pattern':0} for n in range(160)]
    for precision in (53,64):
        for pattern in (0,1):
            for n in range(108):
                cases.append({'kind':'helper','source_case':0,'pattern':pattern,'precision':precision,
                    'slot_x':0,'slot_y':0,'argument_x':n%9,'argument_y':n//9})
    # Signed-byte narrowing can yield a valid table address even for non-grid bytes.
    edge=(0,1,11,12,127,128,129,244,255)
    signed=lambda a:(a+128)%256-128
    for a in edge:
        for b in edge:
            dx=signed(abs(signed(a)-signed(b)))
            for dy in (0,1,11,12,127,128,255):
                index=9*signed(abs(signed(dy)))+dx
                if 0<=index<108:
                    cases.append({'kind':'helper','source_case':0,'pattern':1,'precision':64,
                     'slot_x':a,'slot_y':dy,'argument_x':b,'argument_y':0})
    return cases


def generate(a):
    root=Path(__file__).resolve().parents[1]
    p.need(p.sha((root/'scripts/emulate_action33_prefix_30.py').read_bytes())==SOURCE,'prefix setup source changed')
    p.need(unicorn.__version__=='2.1.4','Unicorn version mismatch')
    data,ins,sites=extract(a.binary,a.fresh,a.caller)
    table=(root/'evidence/random-validation/random-table.bin').read_bytes();p.need(p.sha(table)==p.TABLE_HASH,'synthetic table mismatch')
    machine=p.Oracle(data,code_ranges=RANGES);u=machine.uc
    u.mem_map(p.MATCH,0x10000);u.mem_map(p.POSITIONS,0x1000);u.mem_write(p.TABLE,table)
    result=[]
    for number,c in enumerate(schedule()):
        source=p.make_case(c['source_case']);initial_regs,_,_,shooter=p.setup(machine,source)
        u.mem_write(p.GRID,grid(c['pattern']))
        if c['kind']=='helper':
            u.mem_write(shooter+0x102,bytes([c['slot_x'],c['slot_y']]))
            u.mem_write(p.SP,struct.pack('<3I',RETURN,0xa5a50000|c['argument_x'],0x5a5a0000|c['argument_y']))
            u.reg_write(x.UC_X86_REG_FPCW,0x27f if c['precision']==53 else 0x37f)
        start,end=(ENTRY,STOP) if c['kind']=='prefix' else (HELPER,RETURN)
        before=state(machine);trace=[];events=[];calls=[];pc=0
        def code(m,address,size,unused):
            nonlocal pc
            pc=address;p.need(address in ins and address!=STOP,'instruction outside admitted segment');trace.append(p.hx(address))
            if address==0x702088:
                calls.append({'site':'00702088','target':'006f09b0','before':state(machine),
                 'arguments':list(struct.unpack('<2I',u.mem_read(u.reg_read(x.UC_X86_REG_ESP),8)))})
            if address==0x70208d:calls[-1]['after']=state(machine)
        def memory(m,kind,address,size,value,unused):
            p.need(any(base<=address and address+size<=base+length for base,length in REGIONS.values()),'unadmitted data access')
            write=kind==unicorn.UC_MEM_WRITE
            value=value&((1<<(size*8))-1) if write else int.from_bytes(u.mem_read(address,size),'little')
            events.append([p.hx(pc),'write' if write else 'read',p.hx(address),size,value])
        hooks=[u.hook_add(unicorn.UC_HOOK_CODE,code),u.hook_add(unicorn.UC_HOOK_MEM_READ|unicorn.UC_HOOK_MEM_WRITE,memory)]
        try:u.emu_start(start,end,count=200)
        finally:
            for hook in hooks:u.hook_del(hook)
        p.need(u.reg_read(x.UC_X86_REG_EIP)==end,'segment did not terminate')
        after=state(machine);p.need(before['rng']==after['rng'] and before['rng_cells']==after['rng_cells'],'unexpected RNG change')
        result.append({'id':number,'case':c,'before':before,'after':after,'calls':calls,'events':events,
           'instruction_trace':trace,'memory_sha256':{k:p.sha(bytes(u.mem_read(base,n))) for k,(base,n) in REGIONS.items()}})
    return {'unit':'R31-A','sites':sites,'cases':result,'scope':'bounded full integer/flags, active x87, ordered data/stack accesses and region digests; empty x87 register payloads excluded; no resolver/effect completion',
      'coverage':{'prefix_cases':160,'helper_cases':len(result)-160,'instructions':sum(len(r['instruction_trace']) for r in result),
        'events':sum(len(r['events']) for r in result),'rng_calls':0}}


def parser():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path)
    for name in ('fresh','caller','output'):parser.add_argument('--'+name,type=Path,required=True)
    return parser


if __name__=='__main__':
    a=parser().parse_args();result=generate(a);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(p.packed(result))
    print(json.dumps(result['coverage']))

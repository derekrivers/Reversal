#!/usr/bin/env python3
"""Original x86 keeper postlude and connected penalty response-body fixtures.

The actual entry validity checks, grid table, other actions and shot caller do
not execute. Slot values and the established stack frame are synthetic.
"""
import argparse,hashlib,json,random,struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_EDI,UC_X86_REG_ESI,UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_FPCW
from emulate_random import Oracle,EXPECTED,STACK,TABLE

SLOT=0x04000000;CONTEXT=0x04100000;OUTPUT=0x04200000
TABLE_HASH='befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db'
def f32(value):return struct.unpack('<f',struct.pack('<f',value))[0]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('table',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
 if a.output.exists():p.error('choose a new output directory')
 table=a.table.read_bytes();assert hashlib.sha256(table).hexdigest()==TABLE_HASH
 oracle=Oracle(a.binary.read_bytes(),code_ranges=[(0x7004d6,0x7004f1),(0x700a4f,0x700b89),(0x90cfc0,0x90d09d),(0x9469fa,0x946a22),(0x945640,0x945667)])
 for address in [SLOT,CONTEXT,OUTPUT]:oracle.uc.mem_map(address,0x10000)
 oracle.uc.mem_write(TABLE,table);oracle.put(SLOT+0x19e,CONTEXT)
 sp=STACK+0x8000;trace=[];path='retained';in_postlude=False
 def observe(uc,address,size,data):
  nonlocal path,in_postlude
  if address==0x700a4f:in_postlude=True
  if address==0x700b03:path='weighted'
  if address==0x700b41:path='redrawn'
  if address==0x90cfc0 and in_postlude:
   esp=uc.reg_read(UC_X86_REG_ESP);trace.append(struct.unpack('<i',uc.mem_read(esp+4,4))[0])
  if address==0x700b88:uc.emu_stop()
 oracle.uc.hook_add(UC_HOOK_CODE,observe)
 cases=[];counts={}
 special=[0,1,6,7,10,14,20,28,35,70,100,200,32767,32768,65535,65536-220]
 for precision in [53,64]:
  rng=random.Random(0x703968)
  for mode in ['postlude','penalty-body']:
   for n in range(2048):
    rating=special[n%len(special)] if n<256 else rng.randrange(65536)
    base=special[(n//len(special))%len(special)] if n<256 else rng.randrange(65536)
    # Includes exact float32 fractions, negative inputs, signed byte boundaries and zero bounds.
    adjust=[0,1,2,0.5,-5,100,-100][n%7] if n<256 else f32(rng.uniform(-100,100))
    distance=[0,1,2,0.5,10,-20,20][n%7] if n<256 else f32(rng.uniform(-20,20))
    input={'ratingRaw':rating,'fallbackRatingRaw':[0,1,200,32767,32768,65535][n%6] if n<256 else rng.randrange(65536),
     'precisionBits':precision,'counterRaw':n%256,'adjustmentFloat':adjust,'distanceFloat':distance,'matchByteRaw':n%256}
    state={'cursorIndex':50999 if n%7==0 else rng.randrange(51000),'offset':rng.randrange(65536),'crtState':rng.getrandbits(32)}
    oracle.set_state(state);oracle.uc.reg_write(UC_X86_REG_ESP,sp);oracle.uc.reg_write(UC_X86_REG_ESI,SLOT)
    oracle.uc.reg_write(UC_X86_REG_EDI,base if mode=='postlude' else rating+220)
    oracle.uc.reg_write(UC_X86_REG_FPCW,0x27f if precision==53 else 0x37f)
    oracle.put(sp+0x2c,rating);oracle.put(sp+0x30,OUTPUT)
    oracle.uc.mem_write(sp+0x24,struct.pack('<f',distance))
    oracle.uc.mem_write(SLOT+0xd1,struct.pack('<f',adjust));oracle.uc.mem_write(SLOT+0xf,bytes([input['counterRaw']]))
    oracle.uc.mem_write(SLOT+0x3b,struct.pack('<H',input['fallbackRatingRaw']));oracle.uc.mem_write(CONTEXT+0x8eaa,bytes([input['matchByteRaw']]))
    oracle.uc.mem_write(OUTPUT,b'\0');trace=[];path='retained';in_postlude=False
    oracle.uc.emu_start(0x700a4f if mode=='postlude' else 0x7004d6,0,timeout=100000,count=3000)
    assert oracle.uc.reg_read(UC_X86_REG_EIP)==0x700b88
    assert oracle.uc.reg_read(UC_X86_REG_ESP)==sp
    assert all(-65535<=b<=65535 for b in trace)
    value=oracle.uc.reg_read(UC_X86_REG_EAX);value=value if value<0x80000000 else value-0x100000000
    result={'response':value,'fallback':bool(oracle.uc.mem_read(OUTPUT,1)[0]),'path':path}
    counts[str(precision)+':'+mode+':'+path]=counts.get(str(precision)+':'+mode+':'+path,0)+1
    cases.append({'mode':mode,'input':input,**({'baseRaw':base} if mode=='postlude' else {}),'initial':state,'postludeBounds':trace,'result':result,'final':oracle.state()})
 header={'sha256':EXPECTED,'synthetic_table_sha256':TABLE_HASH,'oracle':'original x86 body/postlude with original RNG and __ftol instructions; synthetic established frames',
  'emulated_ranges':[['007004d6','007004f1'],['00700a4f','00700b88']],
  'control_words':{'53':'0x027f','64':'0x037f'},'rounding':'nearest/even for arithmetic; original __ftol temporarily uses truncation',
  'coverage':{'cases':len(cases),'paths':counts,'rng_bounds_and_final_state':True},
  'input_domain':'Raw uint16 ratings/base; uint8 counter/match byte; finite float32 adjustment[-100,100], distance[-20,20]',
  'limitations':['Entry validity/position checks and grid table acquisition skipped. Other action branches and caller do not execute.',
   'Selected rating, slot+d1, counter+f, fallback rating+3b and match+8eaa semantics remain partial.',
   'Connected penalty-body fixtures start after the action33 prelude; not whole-function or complete penalty-attempt equivalence.',
   'Both53/64-bit precision modes tested; static CRT setter requests53, but no runtime trace proves match-entry control state.',
   'No goal/save, score update, commentary or full-match execution.']}
 a.output.mkdir(parents=True)
 prefix=json.dumps(header,indent=2).rsplit('\n}',1)[0]
 (a.output/'oracle.json').write_text(prefix+',\n  "cases": [\n'+',\n'.join('    '+json.dumps(c,separators=(',',':')) for c in cases)+'\n  ]\n}\n')
 print(json.dumps({'coverage':header['coverage'],'instructions':oracle.instructions}))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Original-instruction oracles for three isolated shot-resolution boundaries.

Synthetic frames connect no slices. The keeper postlude, score updates and
commentary are excluded; these are not complete penalty-attempt outcomes.
"""
import argparse,hashlib,json,random,struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_EBP,UC_X86_REG_EDI,UC_X86_REG_ESI,UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_FPCW
from emulate_random import Oracle,EXPECTED,STACK,TABLE

CLASSIFY=(0x703b25,0x703beb)
KEEPER=(0x7004d6,0x7004f1)
GATE=(0x706cba,0x706d2c)
CONTEXT=0x04000000;SLOT=0x04100000
TABLE_HASH='befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db'

def signed16(x):return x if x<32768 else x-65536
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('table',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
 if a.output.exists():p.error('choose a new output directory')
 table=a.table.read_bytes();assert hashlib.sha256(table).hexdigest()==TABLE_HASH
 # Endpoints are admitted for the stop hook, which runs before their instruction.
 endpoints=[(x,x+1) for x in [0x703beb,0x700a4f,0x706d2c,0x706dfd]]
 oracle=Oracle(a.binary.read_bytes(),code_ranges=[CLASSIFY,KEEPER,GATE,(0x706d83,0x706d8d),(0x90cfc0,0x90d09d),(0x9469fa,0x946a22)]+endpoints)
 for address in [CONTEXT,SLOT]:oracle.uc.mem_map(address,0x10000)
 oracle.uc.mem_write(TABLE,table);oracle.put(SLOT+0x19e,CONTEXT)
 destinations={};stop_at=set()
 def stop(uc,address,size,data):
  if address in stop_at:uc.emu_stop()
 oracle.uc.hook_add(UC_HOOK_CODE,stop)
 sp=STACK+0x8000
 def run(start,ends):
  stop_at.clear();stop_at.update(ends)
  oracle.uc.reg_write(UC_X86_REG_FPCW,0x37f)
  oracle.uc.emu_start(start,0,timeout=100000,count=1000)
  end=oracle.uc.reg_read(UC_X86_REG_EIP)
  if end not in ends:raise RuntimeError(f'incomplete slice {start:x}: {end:x}')
  assert oracle.uc.reg_read(UC_X86_REG_ESP)==sp
  return end
 initial={'cursorIndex':50999,'offset':12345,'crtState':1}
 output=bytearray();counts={}
 for variant in [0,1]:
  for raw in range(65536):
   oracle.set_state(initial);oracle.uc.reg_write(UC_X86_REG_ESP,sp);oracle.uc.reg_write(UC_X86_REG_EBP,raw)
   oracle.put(sp+0x64,120);oracle.uc.mem_write(sp+0x1c,bytes([variant]))
   run(CLASSIFY[0],{CLASSIFY[1]})
   category=oracle.uc.mem_read(sp+0x10,1)[0];final=oracle.state()
   draws=0 if final==initial else 1
   if draws:assert final['cursorIndex']==0
   destinations[str(draws)]=final;output.extend([category,draws]);counts[str(category)]=counts.get(str(category),0)+1
 rng=random.Random(0x603968);keeper=[]
 ratings=[0,1,100,200,32767,32768,65535,65536-220,65536-219,32767-220]
 for n in range(4096):
  raw=ratings[n] if n<len(ratings) else rng.randrange(65536)
  state={'cursorIndex':50999 if n%7==0 else rng.randrange(51000),'offset':rng.randrange(65536),'crtState':rng.getrandbits(32)}
  oracle.set_state(state);oracle.uc.reg_write(UC_X86_REG_ESP,sp)
  oracle.uc.reg_write(UC_X86_REG_EDI,(raw+220)&0xffffffff)
  run(KEEPER[0],{0x700a4f})
  # EDI is the second draw, before the common floating-point postlude.
  value=oracle.uc.reg_read(UC_X86_REG_EDI);value=value if value<0x80000000 else value-0x100000000
  keeper.append({'ratingRaw':raw,'initial':state,'baseResponse':value,'final':oracle.state()})
 gates=[]
 pairs=[(q,k) for q,k in [(0,0),(71,29),(72,28),(68,32),(69,31),(70,30),(1,-1),(-1,1),(32767,-32768),(-32768,32767),(0,1),(1,0),(-1,0),(0,-1)]]
 pairs += [(rng.randrange(-32768,32768),rng.randrange(-32768,32768)) for _ in range(1000)]
 for q,k in pairs:
  for mode in [0,2,8,255]:
   oracle.uc.reg_write(UC_X86_REG_ESP,sp);oracle.uc.reg_write(UC_X86_REG_ESI,SLOT)
   oracle.uc.reg_write(UC_X86_REG_EDI,q&0xffffffff);oracle.uc.reg_write(UC_X86_REG_EBP,k&0xffffffff)
   oracle.uc.mem_write(CONTEXT+1,bytes([mode]));before=oracle.state()
   end=run(GATE[0],{0x706d2c,0x706dfd})
   assert before==oracle.state()
   ratio=struct.unpack('<f',oracle.uc.mem_read(sp+0x1c,4))[0]
   gates.append({'quality':q,'keeperTerm':k,'matchStateRaw':mode,'ratio':ratio,'entersScoringBranch':end==0x706dfd})
 a.output.mkdir(parents=True)
 (a.output/'classification.bin').write_bytes(output)
 header={'sha256':EXPECTED,'oracle':'original x86 instruction slices; independent synthetic frames','synthetic_table_sha256':TABLE_HASH,
  'classification':{'start':'00703b25','end_exclusive':'00703beb','threshold':120,'order':'variant=0 then1; raw quality0..65535 in each; records category:u8, RNG-draw-count:u8',
    'cases':131072,'initial':initial,'final_states_by_draw_count':destinations,'category_counts':counts,'bytes':len(output),'sha256':hashlib.sha256(output).hexdigest()},
  'keeper':{'start':'007004d6','end_exclusive':'00700a4f','cases':len(keeper)},
  'gate':{'start':'00706cba','stop_addresses':['00706d2c','00706dfd'],'cases':len(gates),'constants':{'0096d808':71,'0096d80c':68,'009689a8':2}},
  'limitations':['Slices are tested independently; no full shot, penalty or match equivalence.',
   'Classification receives quality after earlier adjustments and an externally supplied variant byte; penalty threshold120 only.',
   'Keeper base branch skips validity/position checks and stops before00700a4f floating-point adjustment and additional RNG.',
   'Ratio gate requires shot category1,14 or15; keeperTerm and quality are supplied after upstream changes.',
   'The71 threshold is a branch comparison, not a probability or unconditional goal; score changes and commentary do not execute.']}
 def write(name,metadata,cases):
  prefix=json.dumps(metadata,indent=2).rsplit('\n}',1)[0]
  (a.output/name).write_text(prefix+',\n  "cases": [\n'+',\n'.join('    '+json.dumps(c,separators=(',',':')) for c in cases)+'\n  ]\n}\n')
 (a.output/'oracle.json').write_text(json.dumps(header,indent=2)+'\n')
 write('keeper.json',{'sha256':EXPECTED,'synthetic_table_sha256':TABLE_HASH},keeper)
 write('gate.json',{'sha256':EXPECTED},gates)
 print(json.dumps({'classification':131072,'keeper':len(keeper),'gate':len(gates),'instructions':oracle.instructions}))
if __name__=='__main__':main()

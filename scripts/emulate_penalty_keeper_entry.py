#!/usr/bin/env python3
"""Run original00700420 entry-to-return for action33 with synthetic runtime data.

Executes original tactical-position helper, RNG and __ftol. Replaces the distance
lookup with an explicitly synthetic grid; no game process or shot caller runs.
"""
import argparse,hashlib,json,math,random,struct
from pathlib import Path
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX,UC_X86_REG_ECX,UC_X86_REG_EBX,UC_X86_REG_EBP,UC_X86_REG_EDI,UC_X86_REG_ESI,UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_FPCW
from emulate_random import Oracle,EXPECTED,STACK,TABLE,STOP

SLOT=0x04000000;CONTEXT=0x04100000;OUTPUT=0x04200000;POSITIONS=0x04300000;GRID=0xa15e44
TABLE_HASH='befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db'
def f32(v):return struct.unpack('<f',struct.pack('<f',v))[0]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('table',type=Path);p.add_argument('output',type=Path)
 p.add_argument('--original-grid-private',action='store_true',help='retain original lookup data only under ignored results/; never publish that oracle')
 a=p.parse_args()
 if a.output.exists():p.error('choose a new output directory')
 if a.original_grid_private and not a.output.resolve().is_relative_to(Path(__file__).resolve().parents[1]/'results'):p.error('private original-grid oracle must stay under ignored results/')
 table=a.table.read_bytes();assert hashlib.sha256(table).hexdigest()==TABLE_HASH
 oracle=Oracle(a.binary.read_bytes(),code_ranges=[(0x700420,0x7004f1),(0x700a4f,0x700b9d),(0x6c38c0,0x6c38e8),(0x90cfc0,0x90d09d),(0x9469fa,0x946a22),(0x945640,0x945667)])
 for address in [SLOT,CONTEXT,OUTPUT,POSITIONS]:oracle.uc.mem_map(address,0x10000)
 oracle.uc.mem_write(TABLE,table);original_grid=bytes(oracle.uc.mem_read(GRID,108*4))
 synthetic_grid=[f32(math.hypot(x,y)) for y in range(12) for x in range(9)]
 grid=list(struct.unpack('<108f',original_grid)) if a.original_grid_private else synthetic_grid
 grid_bytes=struct.pack('<108f',*grid);oracle.uc.mem_write(GRID,grid_bytes)
 oracle.put(SLOT+0x19e,CONTEXT)
 oracle.put(CONTEXT+0x8ebc,POSITIONS);oracle.put(CONTEXT+0x8ec0,POSITIONS+0x100)
 rng=random.Random(0x803968);cases=[];coverage={'eligible':0,'rejected':0};eligible=False;grid_index=None
 def observe(uc,address,size,data):
  nonlocal eligible,grid_index
  if address==0x7004a4:grid_index=uc.reg_read(UC_X86_REG_EBX)
  if address==0x7004d6:eligible=True
 oracle.uc.hook_add(UC_HOOK_CODE,observe)
 def input_case(precision,side,variant):
  return {'rating0Raw':rng.randrange(65536),'rating1Raw':rng.randrange(65536),'variantRaw':variant,'activityRaw':0,'tacticalSlotRaw':0,'side':side,
   'keeperX':4,'keeperY':0,'matchX':4,'matchY':11,'fallbackRatingRaw':rng.randrange(65536),'counterRaw':rng.randrange(256),
   'adjustmentFloat':f32(rng.uniform(-100,100)),'matchByteRaw':rng.randrange(256),'precisionBits':precision}
 inputs=[]
 for precision in [53,64]:
  for side in [0,1]:
   for variant in [0,1,255]:
    for raw in range(256):
     for field in ['activityRaw','tacticalSlotRaw']:
      entry=input_case(precision,side,variant);entry[field]=raw
      inputs.append((entry,1,'all-raw-'+field))
  for y in range(12):
   for x in range(9):
    for side in [0,1]:
     for variant in [0,255]:
      entry=input_case(precision,side,variant);entry.update(keeperX=0,keeperY=0,matchX=x,matchY=y)
      inputs.append((entry,1,'grid-sweep'))
  for _ in range(1024):
   entry=input_case(precision,rng.randrange(2),rng.randrange(256));entry.update(activityRaw=rng.choice([0,1,2,127,128,255]),tacticalSlotRaw=rng.choice([0,10,11,255,rng.randrange(256)]),keeperX=rng.randrange(9),keeperY=rng.randrange(12),matchX=rng.randrange(9),matchY=rng.randrange(12))
   inputs.append((entry,rng.choice([0,1,1,2,65535]),'mixed'))
 for n,(entry,position_code,kind) in enumerate(inputs):
  position=[[rng.randrange(65536) for _ in range(11)] for _ in range(2)]
  if entry['tacticalSlotRaw']<=10:position[entry['side']][entry['tacticalSlotRaw']]=position_code
  for side in [0,1]:oracle.uc.mem_write(POSITIONS+side*0x100,struct.pack('<11H',*position[side]))
  state={'cursorIndex':50999 if n%7==0 else rng.randrange(51000),'offset':rng.randrange(65536),'crtState':rng.getrandbits(32)}
  oracle.set_state(state);sp=STACK+0x8000;oracle.put(sp,STOP)
  # The first two stack arguments are unused on action33, but vary them.
  for offset,value in [(4,n&255),(8,(n*7)&255),(12,entry['variantRaw']),(16,0x33),(20,OUTPUT),(24,OUTPUT+1)]:oracle.put(sp+offset,value)
  oracle.uc.mem_write(OUTPUT,b'\xa5\x5a')
  for offset,key in [(0xf,'counterRaw'),(0x19,'tacticalSlotRaw'),(0x27,'side'),(0x2b,'activityRaw'),(0x102,'keeperX'),(0x103,'keeperY')]:oracle.uc.mem_write(SLOT+offset,bytes([entry[key]]))
  for offset,key in [(0x168,'rating0Raw'),(0x16a,'rating1Raw'),(0x3b,'fallbackRatingRaw')]:oracle.uc.mem_write(SLOT+offset,struct.pack('<H',entry[key]))
  oracle.uc.mem_write(SLOT+0xd1,struct.pack('<f',entry['adjustmentFloat']))
  for offset,key in [(0x8ea7,'matchX'),(0x8ea8,'matchY'),(0x8eaa,'matchByteRaw')]:oracle.uc.mem_write(CONTEXT+offset,bytes([entry[key]]))
  before_slot=bytes(oracle.uc.mem_read(SLOT,0x1be));before_match=bytes(oracle.uc.mem_read(CONTEXT,0xf63b))
  saved={UC_X86_REG_EBX:0x11223344,UC_X86_REG_EBP:0x22334455,UC_X86_REG_ESI:0x33445566,UC_X86_REG_EDI:0x44556677}
  for reg,value in saved.items():oracle.uc.reg_write(reg,value)
  cw=0x27f if entry['precisionBits']==53 else 0x37f
  oracle.uc.reg_write(UC_X86_REG_ESP,sp);oracle.uc.reg_write(UC_X86_REG_ECX,SLOT);oracle.uc.reg_write(UC_X86_REG_FPCW,cw);eligible=False;grid_index=None
  oracle.uc.emu_start(0x700420,STOP,timeout=100000,count=3000)
  assert oracle.uc.reg_read(UC_X86_REG_EIP)==STOP and oracle.uc.reg_read(UC_X86_REG_ESP)==sp+28
  assert all(oracle.uc.reg_read(reg)==value for reg,value in saved.items())
  assert oracle.uc.reg_read(UC_X86_REG_FPCW)==cw
  assert before_slot==bytes(oracle.uc.mem_read(SLOT,0x1be)) and before_match==bytes(oracle.uc.mem_read(CONTEXT,0xf63b))
  raw=oracle.uc.reg_read(UC_X86_REG_EAX)&65535;response=raw if raw<32768 else raw-65536
  flags=list(oracle.uc.mem_read(OUTPUT,2));assert grid_index is not None and grid_index<108
  result={'response':response,'positionFlag':flags[0],'fallbackFlag':flags[1],'eligible':eligible,'gridIndex':grid_index}
  coverage['eligible' if eligible else 'rejected']+=1
  if not eligible:assert oracle.state()==state and response==0 and flags==[0,0]
  cases.append({'kind':kind,'input':entry,'positions':position,'initial':state,'result':result,'final':oracle.state()})
 a.output.mkdir(parents=True)
 original_values=struct.unpack('<108f',original_grid)
 header={'sha256':EXPECTED,'synthetic_table_sha256':TABLE_HASH,'oracle':'original00700420 entry-to-return, action33; original tactical-position/RNG/__ftol helpers; synthetic runtime tables',
  'grid':{'origin':'fixed original lookup; private fixture, do not publish' if a.original_grid_private else 'synthetic float32 hypot(dx,dy), dx0..8 dy0..11; not the original lookup','values':grid,'sha256':hashlib.sha256(grid_bytes).hexdigest(),'va':'00a15e44'},
  'original_grid_window':{'entries':108,'sha256':hashlib.sha256(original_grid).hexdigest(),'exact_matches_with_synthetic_hypot':sum(x==y for x,y in zip(original_values,synthetic_grid)),'minimum':min(original_values),'maximum':max(original_values)},
  'coverage':{'cases':len(cases),**coverage,'all256_activity_and_slot_bytes':True,'both_sides':True,'variant_bytes':[0,1,255],'all108_grid_indices':True,'precision_bits':[53,64]},
  'abi_and_writes':'Verified ret24 stack cleanup, callee-saved registers, restored control word, unchanged446-byte slot and63035-byte match; outputs initialized before validity checks',
  'limitations':['Action33 only; other branches of00700420 remain unreconstructed. All coords restricted to x0..8/y0..11 and valid mapped context pointers.',
   'Tactical tables/runtime fields are synthetic; public grid is synthetic, optional private oracle retains the original grid window.',
   'Responses compared at signed low-word boundary used downstream; undefined upper return bits of lookup helper are not a contract.',
   'Runtime sources of ratings/counter/float/state, match-entry precision, shot caller, goals/saves and complete match remain open.']}
 prefix=json.dumps(header,indent=2).rsplit('\n}',1)[0]
 (a.output/'oracle.json').write_text(prefix+',\n  "cases": [\n'+',\n'.join('    '+json.dumps(c,separators=(',',':')) for c in cases)+'\n  ]\n}\n')
 print(json.dumps({'coverage':header['coverage'],'instructions':oracle.instructions}))
if __name__=='__main__':main()

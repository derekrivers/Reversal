#!/usr/bin/env python3
"""Compose three original calculation slices with original RNG/ftol helpers.

The commentary path is suppressed by setting sudden-death=1. The full shootout,
00700bd0 prelude, shared shot resolver, keeper logic and goal outcome do not run.
"""
from pathlib import Path
import argparse,hashlib,json,random,struct
from unicorn.x86_const import UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBX,UC_X86_REG_EAX,UC_X86_REG_EBP,UC_X86_REG_ESP,UC_X86_REG_EIP,UC_X86_REG_FPCW
from emulate_random import Oracle,EXPECTED,STACK,TABLE

CONTEXT=0x04000000;TAKER=0x04100000;PLAYER=0x04200000;OUTPUT=0x04300000
SLICES=[(0x6be9d7,0x6beacd),(0x700d19,0x700d3d),(0x6beaf0,0x6beb06)]
def signed16(v):return v if v<32768 else v-65536
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('table',type=Path);p.add_argument('output',type=Path);args=p.parse_args()
 if args.output.exists():p.error('choose a new output directory')
 table=args.table.read_bytes();table_hash=hashlib.sha256(table).hexdigest()
 if table_hash!='befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db':raise ValueError('expected retained synthetic table')
 oracle=Oracle(args.binary.read_bytes(),code_ranges=SLICES+[(0x90cfc0,0x90d09d),(0x9469fa,0x946a22),(0x945640,0x945667)])
 for address in [CONTEXT,TAKER,PLAYER,OUTPUT]:oracle.uc.mem_map(address,0x10000)
 oracle.uc.mem_write(TABLE,table);oracle.put(TAKER+0x6d,PLAYER)
 oracle.uc.mem_write(CONTEXT+0x8ea3,b'\x01')
 inputs=[];rng=random.Random(0x503968)
 ratings=[0,1,20,100,200,1000,65535,0xcccc+1,13107,65536-13107]
 for raw in range(256):
  for remaining in [0,1,3,5]:
   for pressure in ['none','must-score','score-to-win']:
    # Current scores/remaining deliberately cover the predicate boundaries.
    if pressure=='none':own,other,opp_remaining=2,0,5
    elif pressure=='must-score':own,other,opp_remaining=0,max(1,remaining),1
    else:own,other,opp_remaining=1,0,0
    # The original first predicate takes precedence when both pressure conditions hold.
    inputs.append({'oneOnOnesRaw':raw,'shotRatingRaw':ratings[(raw+remaining)%len(ratings)],'remaining':remaining,
      'opponentRemaining':opp_remaining,'score':own,'opponentScore':other})
 for _ in range(512):
  rating=rng.randint(-13107,13107)
  inputs.append({'oneOnOnesRaw':rng.randrange(256),'shotRatingRaw':rating&65535,'remaining':rng.randrange(6),
   'opponentRemaining':rng.randrange(6),'score':rng.randrange(8),'opponentScore':rng.randrange(8)})
 cases=[];pressure_counts={}
 for n,input in enumerate(inputs):
  side=n%2;own=input['score'];opp=input['opponentScore'];rem=input['remaining'];oprem=input['opponentRemaining']
  initial={'cursorIndex':50999 if n%7==0 else rng.randrange(51000),'offset':rng.randrange(65536),'crtState':rng.getrandbits(32)}
  oracle.set_state(initial)
  oracle.uc.mem_write(PLAYER+0x35,bytes([input['oneOnOnesRaw']]))
  oracle.uc.mem_write(TAKER+0x180,struct.pack('<H',input['shotRatingRaw']))
  oracle.uc.mem_write(CONTEXT+0x8ea1+side,bytes([rem]));oracle.uc.mem_write(CONTEXT+0x8ea1+(1-side),bytes([oprem]))
  oracle.uc.mem_write(CONTEXT+0xf5bc+side*0x36,bytes([own]));oracle.uc.mem_write(CONTEXT+0xf5bc+(1-side)*0x36,bytes([opp]))
  caller_sp=STACK+0x8000
  oracle.uc.reg_write(UC_X86_REG_ESP,caller_sp);oracle.uc.reg_write(UC_X86_REG_ESI,CONTEXT);oracle.uc.reg_write(UC_X86_REG_EDI,TAKER);oracle.uc.reg_write(UC_X86_REG_EBX,side)
  oracle.uc.reg_write(UC_X86_REG_FPCW,0x37f)
  # First slice computes the error budget; only original RNG and ftol helpers execute.
  oracle.uc.emu_start(*SLICES[0],timeout=100000,count=1000)
  if oracle.uc.reg_read(UC_X86_REG_EIP)!=SLICES[0][1]:raise RuntimeError('budget slice did not finish')
  budget=oracle.get(caller_sp+0x14);budget=budget if budget<0x80000000 else budget-0x100000000
  after_budget=oracle.state()
  # Enter the action-0x33 branch with its established frame/receiver values.
  helper_sp=STACK+0x6000;oracle.uc.reg_write(UC_X86_REG_ESP,helper_sp);oracle.uc.reg_write(UC_X86_REG_ESI,TAKER)
  oracle.put(helper_sp+0x22c,OUTPUT);oracle.uc.mem_write(OUTPUT,b'\x00\x00')
  oracle.uc.emu_start(*SLICES[1],timeout=100000,count=500)
  if oracle.uc.reg_read(UC_X86_REG_EIP)!=SLICES[1][1]:raise RuntimeError('base-quality slice did not finish')
  base=oracle.uc.reg_read(UC_X86_REG_EAX)&65535;base=signed16(base)
  event=struct.unpack('<H',oracle.uc.mem_read(OUTPUT,2))[0]
  # Return boundary: model callee-saved-register/frame restoration, then execute original caller instructions.
  oracle.uc.reg_write(UC_X86_REG_ESP,caller_sp);oracle.uc.reg_write(UC_X86_REG_ESI,CONTEXT);oracle.uc.reg_write(UC_X86_REG_EDI,TAKER)
  oracle.put(caller_sp+0x24,event)
  oracle.uc.emu_start(*SLICES[2],timeout=100000,count=500)
  if oracle.uc.reg_read(UC_X86_REG_EIP)!=SLICES[2][1]:raise RuntimeError('caller quality slice did not finish')
  quality=oracle.uc.reg_read(UC_X86_REG_EBP);quality=quality if quality<0x80000000 else quality-0x100000000
  pressure='must-score' if rem-1+own<opp else 'score-to-win' if oprem+opp<own+1 else 'none'
  pressure_counts[pressure]=pressure_counts.get(pressure,0)+1
  cases.append({'input':input,'side':side,'initial':initial,'after_budget':after_budget,'result':{'errorBudget':budget,'baseQuality':base,'quality':quality,'eventCode':event},'final':oracle.state()})
 result={'sha256':EXPECTED,'oracle':'original x86 calculation slices with original RNG/ftol helpers','synthetic_table_sha256':table_hash,
  'slices':[[hex(a),hex(b)] for a,b in SLICES],'cases':cases,'coverage':{'cases':len(cases),'raw_attribute_bytes':256,'pressure_cases':pressure_counts,'table_wrap':True},
  'limitations':['Sudden-death flag=1 suppresses commentary calls; presentation can consume shared RNG when enabled.',
   'Synthetic frames/context join calculation slices; full routine/caller setup and shared shot outcome do not execute.',
   'Shot rating meaning at roster+0x180 is unresolved; its signed16*5 bound is restricted to the recovered small-RNG domain.',
   'Player+0x35 is community-corroborated OneOnOnes, not Penalties at+0x38.','No keeper-save probability, goal decision or complete penalty attempt equivalence claimed.']}
 args.output.mkdir(parents=True)
 # One case per line keeps large retained fixtures reviewable in Git.
 header=json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2).rsplit('\n}',1)[0]
 payload=header+',\n  "cases": [\n'+',\n'.join('    '+json.dumps(case,separators=(',',':')) for case in cases)+'\n  ]\n}\n'
 (args.output/'x86-penalty-preparation.json').write_text(payload)
 print(json.dumps({'cases':len(cases),'pressure':pressure_counts,'instructions':oracle.instructions}))
if __name__=='__main__':main()

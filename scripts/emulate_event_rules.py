#!/usr/bin/env python3
"""Original x86 oracles for event priority and the post-goal stop-rule predicate.

Synthetic tables, match context and fixture only. No file loader, action routine
or complete match executes. Inputs and output bytes are retained for TS checks.
"""
from pathlib import Path
import argparse,hashlib,json,struct
import unicorn
from unicorn.x86_const import UC_X86_REG_ECX
from emulate_random import Oracle,EXPECTED

TABLE=0xb68788;COUNT=677;CONTEXT=0x04000000;FIXTURE=0x04100000
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('output',type=Path)
 args=p.parse_args()
 if args.output.exists():p.error('choose a new output directory')
 oracle=Oracle(args.binary.read_bytes(),code_ranges=[(0x6d5cd0,0x6d5cfe),(0x6d4250,0x6d4278)])
 oracle.uc.mem_map(CONTEXT,0x10000);oracle.uc.mem_map(FIXTURE,0x1000)
 oracle.put(CONTEXT+0x4792,FIXTURE);oracle.uc.reg_write(UC_X86_REG_ECX,CONTEXT)
 priorities=bytearray();tables=bytearray();rules=bytearray()
 for profile in range(2):
  table=bytes(((i*73+19) if profile==0 else (255-i*29))&255 for i in range(COUNT));tables.extend(table)
  for i,value in enumerate(table):oracle.uc.mem_write(TABLE+i*18,bytes([value]))
  for code in range(65536):
   result=oracle.call(0x6d5cd0,code);signed=result if result<0x80000000 else result-0x100000000
   if not -128<=signed<=127:raise RuntimeError('priority not sign-extended byte')
   priorities.append(signed&255)
 flags=[0,128,127,255]
 for flag in flags:
  oracle.uc.mem_write(FIXTURE+0x38,bytes([flag]))
  for target in range(65536):
   oracle.uc.mem_write(CONTEXT+0x8ed4,struct.pack('<H',target))
   result=oracle.call(0x6d4250)
   if result not in [0,1]:raise RuntimeError('rule result not normalized')
   rules.append(result)
 args.output.mkdir(parents=True)
 for name,b in [('priority-tables.bin',tables),('priority-oracle.bin',priorities),('post-goal-rule-oracle.bin',rules)]:
  (args.output/name).write_bytes(b)
 meta={'sha256':EXPECTED,'emulator':'unicorn '+unicorn.__version__,'oracle':'original x86 function emulation',
  'priority':{'address':'006d5cd0','code_range':['006d5cd0','006d5cfe'],'profiles':2,'table_entries':COUNT,
   'event_codes_per_profile':65536,'cases':len(priorities),'table_sha256':sha(tables),'oracle_sha256':sha(priorities),
   'output_layout':'each profile in order, indexed by raw uint16 event code; signed return represented as int8 byte'},
  'post_goal':{'address':'006d4250','code_range':['006d4250','006d4278'],'fixture_flag_bytes':flags,
   'period_targets_per_flag':65536,'cases':len(rules),'oracle_sha256':sha(rules),
   'output_layout':'each listed flag in order, indexed by raw uint16 period target; normalized 0/1 return'},
  'executed_instructions':oracle.instructions,
  'limitations':['Synthetic priorities and fixture state; no configuration parser or commentary formatter emulated.',
    'Post-goal predicate verified for every 16-bit target and four flag bytes; only bit 0x80 is inspected by the original instructions.',
    'Does not validate complete goal handling, golden-goal match outcome or shootout simulation.']}
 (args.output/'event-rule-oracle.json').write_text(json.dumps(meta,indent=2)+'\n')
 print(json.dumps({'priority_cases':len(priorities),'post_goal_cases':len(rules),'instructions':oracle.instructions}))
if __name__=='__main__':main()

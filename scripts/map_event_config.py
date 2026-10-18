#!/usr/bin/env python3
"""Index a commit-pinned community commentary config against the recovered loader.

Retains configuration labels and metadata. Labels are not recovered C++ symbols;
community text/timings are not authenticated as pristine SI 3.9.68 data.
"""
from pathlib import Path
import argparse,hashlib,json,re,shutil
EXPECTED='f8ed6307e3e295ae388bbaf49c5f4cf67337061a4353e5e1c9c4f3875e85fe88'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path)
 args=p.parse_args();raw=args.source.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=EXPECTED:raise ValueError('unexpected commentary file hash')
 text=raw.decode('cp1252');events=[];label=None;current=None;variant=None
 for number,line in enumerate(text.splitlines(),1):
  line=line.strip()
  if line.startswith('# EVENT_'):label=line[2:].strip()
  elif line.startswith('='):
   values=[int(v.strip()) for v in line[1:].split(',')]
   if len(values)!=9:raise ValueError(('event header',number,values))
   current={'config_id':values[0],'engine_code':values[0]+8000,'engine_code_hex':f'{values[0]+8000:04x}',
            'config_label':label,'source_line':number,'header':values[1:],'variants':[]}
   events.append(current);variant=None
  elif line.startswith('>'):
   if current is None:raise ValueError(('orphan variant',number))
   values=line[1:].split(',',2)
   if len(values)<2:raise ValueError(('variant header',number))
   variant={'divisor':int(values[0].strip()),'delay_ms':int(values[1].strip()),
            'sound':values[2].strip() if len(values)>2 else '', 'game':None,'report':None}
   current['variants'].append(variant)
  elif line[:1].upper() in ['G','R'] and len(line)>1 and line[1].isspace():
   if variant is None:raise ValueError(('orphan text',number))
   key='game' if line[0].upper()=='G' else 'report'
   if variant[key] is not None:raise ValueError(('duplicate text',number))
   variant[key]=line[1:].lstrip()
 ids=[e['config_id'] for e in events]
 assert len(ids)==len(set(ids))==677 and set(ids)==set(range(677))
 for e in events:
  assert e['variants'] and all(v['game'] is not None and v['divisor']>0 for v in e['variants'])
  maximum=max(v['divisor'] for v in e['variants'])
  # Loader EOF pass uses signed integer division of maximum*10 by each divisor.
  e['normalized_weight_total']=sum((maximum*10)//v['divisor'] for v in e['variants'])
  e['variant_count']=len(e['variants'])
 selected=[146,192,193,194,195,196,197,198,433,434,435,571]
 links=[{'config_id':e['config_id'],'engine_code_hex':e['engine_code_hex'],'config_label':e['config_label'],
         'source_line':e['source_line'],'variants':e['variant_count'],'first_game_text':e['variants'][0]['game']}
        for e in events if e['config_id'] in selected]
 metadata=[]
 for e in events:
  metadata.append({k:v for k,v in e.items() if k!='variants'}|{
   'variant_metadata':[{'divisor':v['divisor'],'delay_ms':v['delay_ms'],'sound':v['sound'],
     'has_game_text':v['game'] is not None,'has_report_text':v['report'] is not None} for v in e['variants']]})
 result={'source':{'repository':'https://github.com/nckstwrt/CM0102-Starter-Kit',
    'commit':'69cdaedd611450f33fb73fa2f41f14f5039f3918','path':'external/events_eng.cfg','bytes':len(raw),'sha256':EXPECTED,
    'trust_boundary':'Community configuration; header explicitly describes modified delays. Not authenticated as pristine SI 3.9.68 text/timing.'},
   'binary_bridge':{'loader':'006d9e50','priority_accessor':'006d5cd0','table_base':'00b68788',
    'event_index':'(uint16(code) & 0x7fff) - 8000, accepted only for 0..676',
    'record_bytes':18,'records':677,'variant_bytes':272,'game_text_pointer_offset':'0x108','report_text_pointer_offset':'0x10c'},
   'counts':{'events':len(events),'variants':sum(e['variant_count'] for e in events)},'selected_links':links,'events':metadata,
   'mapping':{'phases_1_2_3':'35-yard shootout: phase1 emits engine event0x2003 (config195)',
    'phases_4_5_6':'Penalty shootout: other nonzero entry phase emits0x2002 (config194)',
    'fixture_flags_bit_0x20':'Selects35-yard triplet in inspected period-end paths, subject to tie conditions',
    'fixture_flags_bit_0x01':'Selects penalty triplet in inspected period-end paths, subject to tie conditions',
    'fixture_flags_bit_0x80':'Post-goal stop rule when target !=495 and !=990; observed callers set+0x1a8 and emit config146 golden-goal event',
    'context_0xf638':'Pitch-condition abandonment minute threshold; -1 disables inspected check'},
   'limitations':['Labels and text establish a semantic bridge for this pinned community config; variants and timings may differ in other files.',
    'The configuration parser and inverse-divisor weight calculation are based on static loader analysis, not full-loader emulation.',
    'No complete shootout, goal routine or match outcome has been reproduced.']}
 args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
 dest=args.output.parent.parent/'source-data';dest.mkdir(exist_ok=True)
 shutil.copyfile(args.source,dest/'community-events-eng.cfg')
 print(json.dumps({'events':len(events),'variants':result['counts']['variants'],'links':links},indent=2))
if __name__=='__main__':main()

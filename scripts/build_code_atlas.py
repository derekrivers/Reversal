#!/usr/bin/env python3
"""Turn a native factual inventory into public, queryable coverage files."""
from pathlib import Path
import argparse,json
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('inventory',type=Path);p.add_argument('output',type=Path);args=p.parse_args()
 data=json.loads(args.inventory.read_text());out=args.output;out.mkdir(parents=True,exist_ok=True)
 for key,name in [('functions','functions.jsonl'),('source_units','source-units.jsonl')]:
  (out/name).write_text(''.join(json.dumps(row,separators=(',',':'))+'\n' for row in data[key]))
 summary={k:v for k,v in data.items() if k not in ['functions','source_units']}
 summary['files']={'functions':'functions.jsonl','source_units':'source-units.jsonl'}
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 groups={key:{'source_units':[],'functions':set()} for key in ['UI/screens','Match simulation','Tactics/training','Transfers/contracts/scouting','Database/storage','Competitions/fixtures','Managers/news/finance','Other source units']}
 def group(unit):
  name=unit.lower()
  if name.endswith('_screens.cpp') or name=='scrman.cpp':return 'UI/screens'
  if name.startswith('match_') or name in ['weather.cpp','simulated_stats.cpp']:return 'Match simulation'
  if any(s in name for s in ['tactic','training','formation']):return 'Tactics/training'
  if any(s in name for s in ['transfer','contract','scout']):return 'Transfers/contracts/scouting'
  if name in ['database.cpp','db_files.cpp']:return 'Database/storage'
  if any(s in name for s in ['league','cup','comp','fixture','fix_man','regional','division','qual','round']):return 'Competitions/fixtures'
  if any(s in name for s in ['manager','news','finance']):return 'Managers/news/finance'
  return 'Other source units'
 for unit in data['source_units']:
  target=groups[group(unit['unit'])];target['source_units'].append(unit['unit']);target['functions'].update(r['function'] for r in unit['references'] if 'function'in r)
 for row in groups.values():row['source_units']=sorted(row['source_units']);row['functions']=sorted(row['functions'])
 counts=data['counts'];sources=[]
 workstreams={'method':'Source-filename filters for research navigation; not exclusive function ownership or recovered module contracts','groups':groups,
  'functions_without_direct_source_anchor':counts['internal_functions']-counts['functions_with_direct_source_path_reference']}
 (out/'workstreams.json').write_text(json.dumps(workstreams,indent=2)+'\n')
 workstream_rows=['| Research workstream | Source-path strings | Directly anchored functions |','| --- | ---: | ---: |']+[f'| {name} | {len(row["source_units"])} | {len(row["functions"])} |' for name,row in groups.items()]
 (out/'WORKSTREAMS.md').write_text('# Research workstreams\n\nThese groups use source-filename filters to navigate the executable inventory. They are not recovered module APIs or behavioral completion claims. A function may reference more than one source unit/workstream.\n\n'+'\n'.join(workstream_rows)+f'\n\n{workstreams["functions_without_direct_source_anchor"]:,} functions have no direct source-path anchor. Their code is inventoried, but source ownership remains open. Exact unit/function lists are retained in `workstreams.json`.\n\nThe next work inside each group is to establish inputs, outputs, state ownership and dependencies before implementing it in TypeScript. UI screen anchors inform React behavior/design research; Windows widget code is not a browser implementation.\n')
 for unit in data['source_units']:
  sources.append((len({r['function'] for r in unit['references'] if 'function'in r}),unit['unit']))
 rows=['| Source unit | Functions with direct reference |','| --- | ---: |']+[f'| `{name}` | {n} |' for n,name in sorted(sources,reverse=True)[:30]]
 report=f'''# Executable code atlas

This inventories the pinned 3.9.68 executable's Ghidra-inferred functions. It is a map of known code locations and direct relationships, **not recovery of the complete original source**.

| Structural observation | Count |
| --- | ---: |
| Internal functions | {counts['internal_functions']:,} |
| External function symbols | {counts['external_function_symbols']:,} |
| Embedded original source-path strings | {counts['source_path_strings']:,} |
| Functions directly referencing a source path | {counts['functions_with_direct_source_path_reference']:,} |
| Functions carrying working research names | {counts['functions_with_working_research_name']:,} |
| Call instructions | {counts['call_instructions']:,} |
| Call instructions without a static target | {counts['unresolved_indirect_call_instructions']:,} |
| Executable memory bytes | {counts['executable_memory_bytes']:,} |
| Executable bytes in inferred function bodies | {counts['executable_bytes_in_inferred_function_bodies']:,} |

The function-body byte count measures structural analysis only. It must not be presented as a percentage of simulation or source code reconstructed. Most functions still have no established behavioral contract.

## Query the map

`functions.jsonl` has one record per internal function: address, working name, inferred body size/bounds, direct callees, source-path anchors and unresolved indirect call sites. `source-units.jsonl` has one record per embedded source path and its observed references. `summary.json` records input hash, counts, imported symbols and limitations.

```sh
python3 - <<'PY'
import json
from pathlib import Path
for line in Path('evidence/code-atlas/functions.jsonl').read_text().splitlines():
    row=json.loads(line)
    if 'match_eng.cpp' in row['direct_source_units']:
        print(row['entry'], row['name'], row['direct_callees'])
PY
```

## Most-referenced source units

{chr(10).join(rows)}

These are investigation anchors. Assertions can be inlined and a function can reference multiple units; the counts do not establish exclusive ownership. Units with fewer assertions can contain much more unlabelled code.

## Reconstruction coverage

`validation-coverage.json` tracks tested whole functions and tested slices separately. A source-path anchor, a working name, a pseudocode export and a validated implementation are different evidence levels. There is no claim that all code has been understood, that indirect dispatch is complete or that original C++ classes have been recovered.
'''
 (out/'README.md').write_text(report)
 print(json.dumps({'functions':len(data['functions']),'source_paths':len(data['source_units']),'counts':counts}))
if __name__=='__main__':main()

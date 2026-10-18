#!/usr/bin/env node
// Validate retained x86 oracles without a game installation or emulator.
import { mkdirSync,readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url));
process.chdir(root);mkdirSync('results',{recursive:true});
const checks=[
 ['reconstruction/check-random.ts','evidence/random-validation/x86-oracle.json','evidence/random-validation/random-table.bin','results/random.json'],
 ['reconstruction/check-clock.ts','evidence/clock-validation/clock-oracle.json','evidence/clock-validation/clock-oracle.bin','results/clock.json'],
 ['reconstruction/check-event-rules.ts','evidence/event-rule-validation','results/event-rules.json'],
 ['reconstruction/check-penalty-preparation.ts','evidence/penalty-preparation-validation/x86-penalty-preparation.json','evidence/random-validation/random-table.bin','results/penalty-preparation.json'],
 ['reconstruction/check-penalty-resolution.ts','evidence/penalty-resolution-validation','evidence/random-validation/random-table.bin','results/penalty-resolution.json'],
 ['reconstruction/check-keeper-response.ts','evidence/keeper-response-validation/oracle.json','evidence/random-validation/random-table.bin','results/keeper-response.json'],
 ['reconstruction/check-penalty-keeper-entry.ts','evidence/penalty-keeper-entry-validation/oracle.json','evidence/random-validation/random-table.bin','results/penalty-keeper-entry.json']
];
for(const args of checks){const r=spawnSync(process.execPath,args,{stdio:'inherit'});if(r.status!==0)process.exit(r.status??1);}
const checkpoint=JSON.parse(readFileSync('checkpoints/latest.json','utf8')).path;
const expected=JSON.parse(readFileSync(`${checkpoint}/expected-database.json`,'utf8'));
const receipt=JSON.parse(readFileSync(`${checkpoint}/RESTORE-VERIFICATION.json`,'utf8'));
const manifest=JSON.parse(readFileSync(`${checkpoint}/DB-MANIFEST.json`,'utf8'));
assert.equal(receipt.status,'passed');
assert.equal(expected.sha256,receipt.sha256);assert.equal(manifest.input_sha256,receipt.sha256);
assert.equal(expected.functions.length,receipt.named_functions_and_comments);
assert.equal(expected.labels.length,receipt.global_labels);
assert.equal(expected.partial_data_types.length,receipt.partial_structures);
assert.equal(expected.partial_data_types.reduce((sum,t)=>sum+t.fields.length,0),receipt.structure_fields);
assert.equal(Object.keys(manifest.project_files).length,receipt.project_file_hashes_verified);
assert.equal(expected.code_signatures.length,receipt.original_code_signatures);
assert.equal(expected.code_comments.length,receipt.code_comments);
for(const type of expected.partial_data_types)for(const field of type.fields){
  assert.ok(field.offset>=0&&field.offset+field.bytes<=type.bytes,`${type.path}: ${field.name}`);
}
const config=JSON.parse(readFileSync('evidence/event-config-map.json','utf8'));
assert.equal(config.events.length,677);assert.equal(new Set(config.events.map(e=>e.config_id)).size,677);
assert.equal(config.events.reduce((n,e)=>n+e.variant_count,0),4754);
for(const e of config.events){assert.equal(e.engine_code,e.config_id+8000);assert.equal(e.variant_metadata.length,e.variant_count);}
const random=JSON.parse(readFileSync('evidence/random-validation/x86-oracle.json','utf8'));
assert.ok(random.table.origin.startsWith('synthetic fixture:'),'Public RNG input must be synthetic');
const keeperEntry=JSON.parse(readFileSync('evidence/penalty-keeper-entry-validation/oracle.json','utf8'));
assert.ok(keeperEntry.grid.origin.startsWith('synthetic '),'Original grid input must stay in ignored private fixtures');
const originalGridReceipt=JSON.parse(readFileSync('evidence/penalty-keeper-entry-validation/original-grid-validation-receipt.json','utf8'));
assert.equal(originalGridReceipt.status,'passed');assert.equal(originalGridReceipt.sha256,expected.sha256);
assert.equal(originalGridReceipt.cases,keeperEntry.coverage.cases);
assert.equal(originalGridReceipt.grid_window.sha256,keeperEntry.original_grid_window.sha256);
const lines=readFileSync('evidence/SHA256SUMS','utf8').trim().split('\n');
for(const line of lines){const match=/^([a-f0-9]{64})  (.+)$/.exec(line);assert.ok(match,line);
  assert.equal(createHash('sha256').update(readFileSync(match[2])).digest('hex'),match[1],match[2]);}
const atlas=JSON.parse(readFileSync('evidence/code-atlas/summary.json','utf8'));
const functions=readFileSync('evidence/code-atlas/functions.jsonl','utf8').trim().split('\n').map(line=>JSON.parse(line));
const units=readFileSync('evidence/code-atlas/source-units.jsonl','utf8').trim().split('\n').map(line=>JSON.parse(line));
assert.equal(functions.length,atlas.counts.internal_functions);assert.equal(new Set(functions.map(f=>f.entry)).size,functions.length);
assert.equal(units.length,atlas.counts.source_path_strings);assert.equal(atlas.sha256,expected.sha256);
assert.equal(functions.filter(f=>f.direct_source_units.length>0).length,atlas.counts.functions_with_direct_source_path_reference);
assert.equal(functions.filter(f=>f.working_research_name).length,atlas.counts.functions_with_working_research_name);
assert.equal(functions.reduce((n,f)=>n+f.call_instruction_count,0),atlas.counts.call_instructions);
assert.equal(functions.reduce((n,f)=>n+f.unresolved_indirect_call_sites.length,0),atlas.counts.unresolved_indirect_call_instructions);
const coverage=JSON.parse(readFileSync('evidence/code-atlas/validation-coverage.json','utf8'));
for(const entry of coverage.entries)assert.ok(functions.some(f=>f.entry===entry.function),entry.function);
const currentNames=JSON.parse(readFileSync('evidence/investigation-09-annotations.json','utf8'));
assert.equal(currentNames.sha256,expected.sha256);
const nameOverlay=new Map(currentNames.annotations.map(([address,name])=>[address,name]));
assert.equal(nameOverlay.size,currentNames.annotations.length);
for(const [address,name] of nameOverlay)assert.equal(expected.functions.find(f=>f.address===address)?.name,name);
for(const entry of expected.functions)assert.equal(nameOverlay.get(entry.address)??functions.find(f=>f.entry===entry.address)?.name,entry.name);
const workstreams=JSON.parse(readFileSync('evidence/code-atlas/workstreams.json','utf8'));
const groups=Object.values(workstreams.groups);
assert.equal(groups.reduce((n,g)=>n+g.source_units.length,0),units.length);
assert.equal(new Set(groups.flatMap(g=>g.functions)).size,atlas.counts.functions_with_direct_source_path_reference);
console.log('Research evidence, native-checkpoint metadata, executable inventory and fixture hashes verified. Native database reopening is a separate retained check.');

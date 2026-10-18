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
 ['reconstruction/check-descriptor-handle.ts','evidence/descriptor-handle-validation/oracle.json','results/descriptor-handle.json'],
 ['reconstruction/check-match-microhelpers.ts','evidence/match-microhelpers-validation','results/match-microhelpers.json'],
 ['reconstruction/check-match-scalar.ts','evidence/match-scalar-22-oracle.json'],
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
assert.equal(expected.function_body_sites.length,receipt.function_body_sites_verified);
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
const semantic=JSON.parse(readFileSync('evidence/code-atlas/semantic-coverage.json','utf8'));
assert.equal(semantic.specimen_sha256,expected.sha256);
assert.equal(semantic.inventory_internal_functions,functions.length);
const inventoryAddresses=new Set(functions.map(f=>f.entry));
const mappedAddresses=new Set();
for(const row of semantic.functions){
  assert.ok(inventoryAddresses.has(row.address),`Unknown mapped function ${row.address}`);
  assert.ok(!mappedAddresses.has(row.address),`Duplicate mapped function ${row.address}`);
  assert.ok(['boundary-mapped','contract-supported'].includes(row.state),row.address);
  assert.ok(semantic.sources[row.source],row.source);
  mappedAddresses.add(row.address);
}
for(const source of Object.values(semantic.sources)){
  readFileSync(source.report);readFileSync(source.evidence);
}
const cleanupSummary=JSON.parse(readFileSync('evidence/cleanup-family-18-summary.json','utf8'));
const cleanupRows=readFileSync('evidence/cleanup-family-18-rows.jsonl','utf8').trim().split('\n').map(JSON.parse);
assert.equal(cleanupSummary.specimen_sha256,expected.sha256);
assert.equal(cleanupSummary.total,143);assert.equal(cleanupRows.length,cleanupSummary.total);
const cleanupAddresses=new Set();
for(const row of cleanupRows){
  assert.ok(inventoryAddresses.has(row.entry) && !cleanupAddresses.has(row.entry),row.entry);
  assert.equal(functions.find(f=>f.entry===row.entry).body_bytes,row.body_bytes);
  assert.equal(cleanupSummary.templates[row.template].body_bytes,row.body_bytes);
  cleanupAddresses.add(row.entry);
}
for(const [kind,template] of Object.entries(cleanupSummary.templates))
  assert.equal(cleanupRows.filter(row=>row.template===kind).length,template.members);
const unwindAddresses=new Set(readFileSync('evidence/unwind-family-15-rows.jsonl','utf8').trim().split('\n').map(line=>JSON.parse(line).entry));
const wrapperAddresses=new Set(readFileSync('evidence/delete-wrapper-family-17-rows.jsonl','utf8').trim().split('\n').map(line=>JSON.parse(line).entry));
for(const address of cleanupAddresses)assert.ok(!mappedAddresses.has(address)&&!unwindAddresses.has(address)&&!wrapperAddresses.has(address),address);
const importSummary=JSON.parse(readFileSync('evidence/import-thunks-18-summary.json','utf8'));
const importRows=readFileSync('evidence/import-thunks-18-rows.jsonl','utf8').trim().split('\n').map(JSON.parse);
assert.equal(importSummary.specimen_sha256,expected.sha256);
assert.equal(importSummary.total,23);assert.equal(importRows.length,importSummary.total);
assert.equal(new Set(importRows.map(row=>row.iat_slot)).size,importSummary.unique_iat_slots);
const importAddresses=new Set();
for(const row of importRows){
  assert.ok(inventoryAddresses.has(row.entry)&&!importAddresses.has(row.entry),row.entry);
  assert.equal(functions.find(f=>f.entry===row.entry).body_bytes,6);
  assert.ok(!mappedAddresses.has(row.entry)&&!unwindAddresses.has(row.entry)&&!wrapperAddresses.has(row.entry)&&!cleanupAddresses.has(row.entry),row.entry);
  importAddresses.add(row.entry);
}
assert.equal(functions.length-mappedAddresses.size-unwindAddresses.size-wrapperAddresses.size-cleanupAddresses.size-importAddresses.size,4897);
const overlayReceipts=['09','10','11','12','13','14','15','16','17','18','19','21'].map(n=>JSON.parse(readFileSync(`evidence/investigation-${n}-annotations.json`,'utf8')));
for(const receipt of overlayReceipts)assert.equal(receipt.sha256,expected.sha256);
const overlayRows=overlayReceipts.flatMap(receipt=>receipt.annotations.map(row=>[row[0],receipt.investigation>=12?row[2]:row[1]]));
const nameOverlay=new Map(overlayRows);
assert.equal(nameOverlay.size,overlayRows.length);
for(const [address,name] of nameOverlay)assert.equal(expected.functions.find(f=>f.address===address)?.name,name);
for(const entry of expected.functions)assert.equal(nameOverlay.get(entry.address)??functions.find(f=>f.entry===entry.address)?.name,entry.name);
for(const annotationReceipt of overlayReceipts.filter(r=>r.investigation>=12)){
 const notes=new Map(annotationReceipt.function_comments);
 for(const [address] of annotationReceipt.annotations){
  const actual=expected.functions.find(f=>f.address===address)?.comment;
  assert.equal(actual,notes.has(address)?`CM0102 investigation${annotationReceipt.investigation} (2026-10-18): ${notes.get(address)}`:null);
 }
}
const workstreams=JSON.parse(readFileSync('evidence/code-atlas/workstreams.json','utf8'));
const groups=Object.values(workstreams.groups);
assert.equal(groups.reduce((n,g)=>n+g.source_units.length,0),units.length);
assert.equal(new Set(groups.flatMap(g=>g.functions)).size,atlas.counts.functions_with_direct_source_path_reference);
console.log('Research evidence, native-checkpoint metadata, executable inventory and fixture hashes verified. Native database reopening is a separate retained check.');

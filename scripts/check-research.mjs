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
 ['reconstruction/check-event-rules.ts','evidence/event-rule-validation','results/event-rules.json']
];
for(const args of checks){const r=spawnSync(process.execPath,args,{stdio:'inherit'});if(r.status!==0)process.exit(r.status??1);}
const expected=JSON.parse(readFileSync('checkpoints/2026-10-18-investigation-04/expected-database.json','utf8'));
const receipt=JSON.parse(readFileSync('checkpoints/2026-10-18-investigation-04/RESTORE-VERIFICATION.json','utf8'));
const manifest=JSON.parse(readFileSync('checkpoints/2026-10-18-investigation-04/DB-MANIFEST.json','utf8'));
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
const lines=readFileSync('evidence/SHA256SUMS','utf8').trim().split('\n');
for(const line of lines){const match=/^([a-f0-9]{64})  (.+)$/.exec(line);assert.ok(match,line);
  assert.equal(createHash('sha256').update(readFileSync(match[2])).digest('hex'),match[1],match[2]);}
console.log('Research evidence, 21 database names, 7 structure layouts and fixture hashes verified. Native database reopening is a separate retained check.');

#!/usr/bin/env node
// Check retained R30-D evidence; no private PE, native exports or emulation required.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {strict as assert} from 'node:assert';

const hash=value=>createHash('sha256').update(value).digest('hex');
const keys=(value,names)=>assert.deepEqual(Object.keys(value).sort(),names.split(' ').sort());
const hex=(value,length=8)=>assert.match(value,new RegExp(`^[0-9a-f]{${length}}$`));
const uint=value=>assert.ok(Number.isInteger(value)&&value>=0&&value<=0xffffffff);

export function checkRetained(evidenceBytes,receiptBytes){
 assert.equal(hash(evidenceBytes),'fc1a86fa0e4cd9c0e3221ad562dcbe5411bae1c6b546d0d61181cfa261e58798','R30-D evidence SHA-256');
 assert.equal(hash(receiptBytes),'0ffdda7af23a92146054a9505c793911155a630eeee45f61c33fa4137d699094','R30-D validation receipt SHA-256');
 const evidence=JSON.parse(evidenceBytes),receipt=JSON.parse(receiptBytes);
 keys(evidence,'sites producer_oracle integrity');
 const s=evidence.sites,o=evidence.producer_oracle;
 keys(s,'unit specimen_sha256 checkpoint_archive_sha256 native_manifest_sha256 staff_manifest_sha256 lifecycle_manifest_sha256 scope address_kind native_export_hashes ranges encoded_global_reference_scan global_storage constructor_imports diagnostic_source static_only');
 assert.equal(s.unit,'R30-D');
 assert.equal(s.specimen_sha256,'0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86');
 for(const name of ['checkpoint_archive_sha256','native_manifest_sha256','staff_manifest_sha256','lifecycle_manifest_sha256'])hex(s[name],64);
 assert.equal(s.scope,'selected PE/native ranges and direct encoded references; no whole-body upgrade');
 assert.equal(s.address_kind,'virtual unless file_offset is explicit');
 const nativeNames=['0062a680','0062a8a0','006dbb80','006e0d00','006eaea0','00828110','0082a9c0','0082ff40','008968f0','008982b0','00528080','00528540'];
 keys(s.native_export_hashes,[...nativeNames.flatMap(name=>[name+'.asm',name+'.c']),'0062ed70.asm','00944cff.asm','006cfe10.asm'].join(' '));
 Object.values(s.native_export_hashes).forEach(value=>hex(value,64));
 assert.equal(s.ranges.length,25);let instructions=0;
 for(const range of s.ranges){
  keys(range,'owner start end_exclusive file_offset bytes sha256 instructions all_native_operands_match');
  for(const name of ['owner','start','end_exclusive','file_offset'])hex(range[name]);hex(range.sha256,64);
  assert.ok(Object.hasOwn(s.native_export_hashes,range.owner+'.asm'));
  assert.equal(parseInt(range.end_exclusive,16)-parseInt(range.start,16),range.bytes);
  assert.equal(parseInt(range.start,16)-parseInt(range.file_offset,16),0x400000);
  uint(range.instructions);assert.ok(range.instructions>0);assert.equal(range.all_native_operands_match,true);instructions+=range.instructions;
 }
 assert.equal(instructions,538);
 keys(s.encoded_global_reference_scan,'text_literal_occurrences confirmed_direct_absolute_write_sites limit');
 assert.equal(s.encoded_global_reference_scan.text_literal_occurrences,299);
 assert.deepEqual(s.encoded_global_reference_scan.confirmed_direct_absolute_write_sites,['00829325','0082c35b','00830102']);
 assert.equal(s.encoded_global_reference_scan.limit,'does not exclude computed-address stores, bulk initialization or alias writes');
 assert.deepEqual(s.global_storage,{va:'00b63d28',section:'.data',section_va:'00987000',section_raw_bytes:0x153000,
  section_virtual_bytes:0x45d63c,delta:0x1dcd28,raw_backed:false,loader_initial_value:0,game_initializer_executed_in_R30_A_B:false});
 assert.deepEqual(s.constructor_imports,{'009670f8':{dll:'KERNEL32.dll',symbol:'GetLogicalDriveStringsA'},
  '00967100':{dll:'KERNEL32.dll',symbol:'GetDriveTypeA'}});
 keys(s.diagnostic_source,'va nul_inclusive_bytes sha256 raw_string_retained');
 assert.equal(s.diagnostic_source.va,'009e7f28');assert.equal(s.diagnostic_source.nul_inclusive_bytes,41);
 hex(s.diagnostic_source.sha256,64);assert.equal(s.diagnostic_source.raw_string_retained,false);
 assert.deepEqual(s.static_only,['global setup and teardown','roster lookup 008968f0','diagnostic and refresh callees']);
 keys(o,'unit specimen_sha256 scope cases case_count instruction_steps');
 assert.equal(o.unit,'R30-D');assert.equal(o.specimen_sha256,s.specimen_sha256);
 assert.equal(o.scope,'80 synthetic original-entry 006e0d00 -> 006eaea0 prefixes; caller-supplied staff+61 nonnull; stop before 006eaf46; no function return or live state claim');
 assert.equal(o.case_count,80);assert.equal(o.cases.length,o.case_count);let steps=0;
 for(const [n,c] of o.cases.entries()){
  keys(c,'seed index slot staff attribute_record stop_before function_returned call instruction_steps ordered_event_count trace_sha256 events_sha256 full_memory_sha256');
  assert.equal(c.seed,Math.floor(n/20));assert.equal(c.index,n%20);
  assert.equal(c.slot,0x210000+0x1be*c.index);assert.equal(c.staff,0x230000+0x80*c.seed);assert.equal(c.attribute_record,0x240000+0x80*c.seed);
  assert.equal(c.stop_before,'006eaf46');assert.equal(c.function_returned,false);
  assert.deepEqual(c.call,{site:'006e0dde',target:'006eaea0',ecx:c.slot,
   arguments:[0x220000,c.staff,0x89abcd00+c.seed,0xa5a50000+c.index,0x89abcd00+c.seed]});
  assert.equal(c.instruction_steps,46);assert.equal(c.ordered_event_count,28);steps+=c.instruction_steps;
  hex(c.trace_sha256,64);hex(c.events_sha256,64);assert.equal(c.full_memory_sha256.length,6);c.full_memory_sha256.forEach(value=>hex(value,64));
 }
 assert.equal(steps,3680);assert.equal(o.instruction_steps,steps);
 keys(evidence.integrity,'optimized_python negative_probes privacy');
 assert.equal(evidence.integrity.optimized_python,'explicit ValueError gates; no assert');
 assert.deepEqual(evidence.integrity.negative_probes,['resealed producer operand rejected']);
 assert.equal(evidence.integrity.privacy,'only compact sites and deterministic synthetic scalars/digests; no PE bytes, source paths or page dumps');
 keys(receipt,'unit status evidence_sha256 normal_optimized_evidence selected_ranges compared_instructions producer_cases producer_instruction_steps negative_probes privacy limits');
 assert.equal(receipt.unit,'R30-D');assert.equal(receipt.status,'passed');assert.equal(receipt.evidence_sha256,hash(evidenceBytes));
 assert.equal(receipt.normal_optimized_evidence,'byte-identical; all fields regenerated from pinned inputs and synthetic schedule');
 assert.deepEqual([receipt.selected_ranges,receipt.compared_instructions,receipt.producer_cases,receipt.producer_instruction_steps],
  [s.ranges.length,instructions,o.case_count,steps]);
 assert.deepEqual(receipt.negative_probes,['changed PE rejected','changed export manifest rejected','resealed producer operand rejected','executed wrong producer store rejected']);
 assert.equal(receipt.privacy,'no original diagnostic path in raw/hex/base64; no original PE bytes or page dumps retained');
 assert.equal(receipt.limits,'static provenance plus synthetic slot-producer prefix; no initialized live match or returned diagnostic');
 return {unit:'R30-D',status:'passed',node:process.version,selected_ranges:s.ranges.length,compared_instructions:instructions,
  producer_cases:o.case_count,producer_instruction_steps:steps,
  scope:'retained static provenance and synthetic producer-prefix evidence; no fresh emulation, function return or live state validation'};
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 const root=new URL('../',import.meta.url);
 console.log(JSON.stringify(checkRetained(readFileSync(new URL('evidence/action33-state-30-evidence.json',root)),
  readFileSync(new URL('evidence/action33-state-30-validation.json',root)))));
}

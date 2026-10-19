#!/usr/bin/env node
// Bounded original contract-call and constructor frontiers on synthetic state.
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';

const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='82e51c46fe98ba06551c184d2d3e811ffdb67dde9aad171c8a7ef05f68f344e5';
const RECEIPT_HASH='eddbd5891d46df1f0d94f08fa088b0bb9a26177b431b44203cb1602d8614d01e';
const SCOPE='R33-B original-produced synthetic placement state enters the actual contract call through pre-004cf62b; independent constructor entry stops before GetLogicalDriveStringsA; no receiver initialization, row lookup, enclosing setup caller, or live lifecycle';
const hash=b=>createHash('sha256').update(b).digest('hex');
const hex=(s,n=8)=>assert.match(s,new RegExp(`^[0-9a-f]{${n}}$`));
const keys=(o,s)=>assert.deepEqual(Object.keys(o).sort(),s.split(' ').sort());
const uint=n=>assert.ok(Number.isInteger(n)&&n>=0&&n<=0xffffffff);
const hx=n=>n.toString(16).padStart(8,'0');
const regions='tactics rows club staff attributes match manager slots constructor_storage stack database_globals owner_globals status_globals crt_globals seh club_records';
const stageKeys='entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256';
const coverage={placement_call_prefixes:80,constructor_os_frontiers:8,instruction_steps:1728,
 next_unresolved:'004cf62b reads auxiliary base 00ae2d0c=0; 004c7073 indirect GetLogicalDriveStringsA blocks receiver constructor'};
const probes=['changed specimen rejected','changed state manifest rejected','changed contract export rejected',
 'changed setup global store rejected','executed wrong auxiliary stride rejected','raw private fragment rejected',
 'hex private fragment rejected','excessive expansion rejected'];

function stage(s){
 keys(s,stageKeys);hex(s.entry);hex(s.stop);uint(s.instruction_steps);uint(s.ordered_memory_events);
 hex(s.trace_sha256,64);hex(s.events_sha256,64);
 for(const k of ['before_memory_sha256','after_memory_sha256']){
  keys(s[k],regions);Object.values(s[k]).forEach(v=>hex(v,64));
 }
 assert.equal(s.calls.length,s.call_frames.length);
 for(const [n,f] of s.call_frames.entries()){
  keys(f,'site target ecx arguments');hex(f.site);hex(f.target);uint(f.ecx);f.arguments.forEach(uint);
  assert.deepEqual(s.calls[n],[f.site,f.target]);
 }
}

export function checkOracle(o){
 keys(o,'unit specimen_sha256 synthetic_only scope placement_calls constructor_frontiers coverage');
 assert.deepEqual([o.unit,o.specimen_sha256,o.synthetic_only,o.scope],['R34-B',SPECIMEN,true,SCOPE]);
 assert.deepEqual(o.coverage,coverage);assert.equal(o.placement_calls.length,80);
 assert.equal(o.constructor_frontiers.length,8);let steps=0;
 for(const [n,c] of o.placement_calls.entries()){
  keys(c,'club_id staff club_pointer source_id entry_receiver receiver_global auxiliary_base next_read_address next_read_instruction next_read_executed next_read_is_loader_backed continuation observed_reads function_returned');
  const club=Math.floor(n/20),index=n%20,id=(club*11+index)%32;
  const staff=0x230000+0x6e*id,home=0x2a0000+0x245*club;
  assert.deepEqual([c.club_id,c.staff,c.club_pointer,c.source_id,c.entry_receiver,c.receiver_global,c.auxiliary_base],
   [club,staff,home,id,0,0,0]);
  assert.deepEqual([c.next_read_address,c.next_read_instruction,c.next_read_executed,c.next_read_is_loader_backed,c.function_returned],
   [id*0x4f,'004cf62b',false,false,false]);
  stage(c.continuation);steps+=c.continuation.instruction_steps;
  assert.deepEqual([c.continuation.entry,c.continuation.stop,c.continuation.instruction_steps],['006eafa0','004cf62b',20]);
  assert.deepEqual(c.continuation.call_frames,[{site:'006eafa0',target:'004cf5f0',ecx:0,arguments:[staff,home]}]);
  assert.deepEqual(c.observed_reads.map(e=>[e[0],e[2],e[3]]),[
   ['004cf5f0',c.observed_reads[0][2],4],['004cf600',c.observed_reads[1][2],4],
   ['004cf60c',hx(staff),4],['004cf60e','00ae2364',4],['004cf624','00ae2d0c',4]]);
  assert.ok(c.observed_reads.every(e=>e[1]==='read'));
  for(const k of Object.keys(c.continuation.before_memory_sha256)){
   if(k!=='stack')assert.equal(c.continuation.before_memory_sha256[k],c.continuation.after_memory_sha256[k]);
  }
 }
 for(const [seed,c] of o.constructor_frontiers.entries()){
  keys(c,'seed receiver entry_argument global_after os_call os_arguments os_call_executed constructor_returned frontier');
  assert.deepEqual([c.seed,c.receiver,c.entry_argument,c.global_after,c.os_call,c.os_call_executed,c.constructor_returned],
   [seed,0x290000+seed*0x40,0,0,'004c7073 -> IAT009670f8',false,false]);
  assert.equal(c.os_arguments[0],0xc8);uint(c.os_arguments[1]);
  assert.ok(0x300000<=c.os_arguments[1]&&c.os_arguments[1]<0x310000);
  stage(c.frontier);steps+=c.frontier.instruction_steps;
  assert.deepEqual([c.frontier.entry,c.frontier.stop,c.frontier.instruction_steps,c.frontier.calls],
   ['004c7040','004c7073',16,[]]);
 }
 assert.equal(steps,coverage.instruction_steps);
}

export function checkRetained(raw,receiptRaw){
 assert.equal(hash(raw),ORACLE_HASH);assert.equal(hash(receiptRaw),RECEIPT_HASH);
 const expanded=gunzipSync(raw,{maxOutputLength:2000000});
 const v=JSON.parse(expanded),r=JSON.parse(receiptRaw);keys(v,'sites oracle');checkOracle(v.oracle);
 const s=v.sites;
 assert.deepEqual([s.unit,s.baseline_commit,s.specimen_sha256,s.scope],
  ['R34-B','4ee3cd0304ac34d2ed0ac09b5f97c06afc67e7f6',SPECIMEN,SCOPE]);
 assert.equal(s.contract_export_sha256,'72a20b7d73d5212bec8fe024efff7292fcf30833220739151f0db2de33c14476');
 assert.deepEqual(s.zero_tail_globals['00ae1050'],{loader_zero:true,game_initializer_executed:false});
 assert.deepEqual(s.constructor_os_import,{dll:'KERNEL32.dll',symbol:'GetLogicalDriveStringsA'});
 assert.equal(s.selected_ranges.length,5);let compared=0;
 for(const range of s.selected_ranges){
  keys(range,'entry end_exclusive file_offset bytes sha256 instructions all_native_operands_match executed');
  for(const k of ['entry','end_exclusive','file_offset'])hex(range[k]);hex(range.sha256,64);
  uint(range.bytes);uint(range.instructions);
  assert.equal(parseInt(range.end_exclusive,16)-parseInt(range.entry,16),range.bytes);
  if(range.all_native_operands_match)compared+=range.instructions;
 }
 assert.deepEqual(s.selected_ranges.map(x=>[x.entry,x.end_exclusive,x.instructions,x.executed,x.all_native_operands_match]),[
  ['008297ca','0082980e',18,false,true],['0082c7ba','0082c7ef',15,false,true],
  ['0083036c','0083038c',9,false,true],['004cf5f0','004cf62b',19,true,true],
  ['004c7040','004c7073',16,true,false]]);
 assert.equal(compared,61);
 keys(r,'unit status specimen_sha256 evidence_sha256 expanded_canonical_sha256 compressed_bytes expanded_canonical_bytes normal_optimized_evidence compared_instructions coverage negative_probes privacy limits');
 assert.deepEqual([r.unit,r.status,r.specimen_sha256,r.evidence_sha256],['R34-B','passed',SPECIMEN,hash(raw)]);
 assert.equal(r.expanded_canonical_sha256,hash(expanded));
 assert.equal(r.compressed_bytes,raw.length);assert.equal(r.expanded_canonical_bytes,expanded.length);
 assert.equal(r.normal_optimized_evidence,'byte-identical original-instruction regeneration');
 assert.equal(r.compared_instructions,compared);assert.deepEqual(r.coverage,coverage);
 assert.deepEqual(r.negative_probes,probes);assert.equal(r.limits,SCOPE);
 const wrong=structuredClone(v.oracle);wrong.placement_calls[0].club_pointer+=0x245;
 assert.throws(()=>checkOracle(wrong));
 const wrongStop=structuredClone(v.oracle);wrongStop.placement_calls[0].next_read_executed=true;
 assert.throws(()=>checkOracle(wrongStop));
 return {unit:'R34-B',status:'passed',node:process.version,compared_instructions:compared,...coverage};
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 const root=new URL('../',import.meta.url);
 console.log(JSON.stringify(checkRetained(
  readFileSync(new URL('evidence/action33-contract-34-oracle.bin',root)),
  readFileSync(new URL('evidence/action33-contract-34-validation.json',root)))));
}

#!/usr/bin/env node
// Public retained check: no private executable or native database is opened.
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';
const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='bfd41a4760cd2f1b32e83a48c03a37e298f2e9de2448b425c12d1d23863d3d43';
const RECEIPT_HASH='1043936f3d00073cccd314fdb5a320eed6245d2448c58519ac6d6e68ffd6a93a';
const SCOPE='synthetic interior allocation-request windows only; no allocator return, auxiliary table, receiver, contract row or live lifecycle produced';
const counts=[0,1,2,31,64,255,0x3333333,0x80000000,0xffffffff];
const coverage={allocation_request_windows:18,instruction_steps:99,allocators_executed:0,records_produced:0,contract_lookup_advanced:false};
const hash=b=>createHash('sha256').update(b).digest('hex');
const keys=(o,s)=>assert.deepEqual(Object.keys(o).sort(),s.split(' ').sort());
const hex=(s,n=8)=>assert.match(s,new RegExp(`^[0-9a-f]{${n}}$`));
const regions='tactics rows club staff attributes match manager slots constructor_storage stack database_globals owner_globals status_globals crt_globals seh';
const probes=['changed specimen rejected','changed state manifest rejected','executed wrong allocation stride rejected',
 'resealed sentinel store width rejected','raw private fragment rejected','hex private fragment rejected',
 'base64 private fragment rejected','excessive expansion rejected'];

export function checkOracle(o){
 keys(o,'unit specimen_sha256 synthetic_only scope cases coverage');
 assert.deepEqual([o.unit,o.specimen_sha256,o.synthetic_only,o.scope],['R35-B',SPECIMEN,true,SCOPE]);
 assert.deepEqual(o.coverage,coverage);assert.equal(o.cases.length,18);let total=0;
 for(const [n,c] of o.cases.entries()){
  keys(c,'path count requested_bytes allocator_call_executed auxiliary_base_after receiver_after function_entry function_returned frontier observed_events');
  const fresh=n<9,path=fresh?'new':'load',count=counts[n%9];
  assert.deepEqual([c.path,c.count,c.requested_bytes],[path,count,Number(BigInt(count)*79n&0xffffffffn)],'allocation request arithmetic');
  assert.deepEqual([c.allocator_call_executed,c.auxiliary_base_after,c.receiver_after,c.function_entry,c.function_returned],[false,0,0,false,false],'unproduced table/receiver frontier');
  const f=c.frontier;
  keys(f,'entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256');
  assert.deepEqual([f.entry,f.stop,f.instruction_steps,f.ordered_memory_events],fresh?['0082849a','008284ad',6,3]:['0082af53','0082af61',5,2]);
  assert.deepEqual(f.calls,[]);assert.deepEqual(f.call_frames,[]);total+=f.instruction_steps;
  hex(f.trace_sha256,64);hex(f.events_sha256,64);
  for(const k of ['before_memory_sha256','after_memory_sha256']){keys(f[k],regions);Object.values(f[k]).forEach(x=>hex(x,64));}
  for(const name of Object.keys(f.before_memory_sha256))if(name!=='stack'&&!(fresh&&name==='database_globals'))assert.equal(f.before_memory_sha256[name],f.after_memory_sha256[name]);
  assert.deepEqual(c.observed_events,fresh?[
   ['0082849a','read','00ae2364',4],['0082849f','write','00ae2d10',4],['008284ac','write','00307ffc',4]]:[
   ['0082af53','read','00ae2d10',4],['0082af60','write','00307ffc',4]]);
 }
 assert.equal(total,99);
}

function checkSites(s){
 keys(s,'unit baseline_commit specimen_sha256 scope state_manifest_sha256 state_archive_sha256 state_export_sha256 selected_ranges constructor_imports static_lifecycle contract_frontier evidence_class');
 assert.deepEqual([s.unit,s.baseline_commit,s.specimen_sha256,s.scope],['R35-B','eabc39b',SPECIMEN,SCOPE]);
 assert.equal(s.state_manifest_sha256,'b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a');
 assert.equal(s.state_archive_sha256,'ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a');
 assert.equal(Object.keys(s.state_export_sha256).length,16);Object.values(s.state_export_sha256).forEach(x=>hex(x,64));
 assert.equal(s.selected_ranges.length,15);let compared=0,peOnly=0;
 for(const [n,r] of s.selected_ranges.entries()){
  keys(r,'entry end_exclusive file_offset bytes sha256 instructions native_operands_match executed');
  for(const k of ['entry','end_exclusive','file_offset'])hex(r[k]);hex(r.sha256,64);
  assert.equal(parseInt(r.end_exclusive,16)-parseInt(r.entry,16),r.bytes);
  assert.equal(r.native_operands_match,n<12);assert.equal(r.executed,false);
  if(r.native_operands_match)compared+=r.instructions;else peOnly+=r.instructions;
 }
 assert.deepEqual([compared,peOnly],[300,350]);
 assert.deepEqual(s.constructor_imports,{'009670f8':{dll:'KERNEL32.dll',symbol:'GetLogicalDriveStringsA'},'00967100':{dll:'KERNEL32.dll',symbol:'GetDriveTypeA'}});
 const l=s.static_lifecycle;
 keys(l,'auxiliary_global auxiliary_count stride new_count_source new_allocate_call new_publish load_count_read load_allocate_call load_publish current_load_read new_primary_secondary_defaults default_sites auxiliary_release_call auxiliary_clear receiver_bytes receiver_setup receiver_constructor receiver_first_os_call receiver_release receiver_clear');
 assert.deepEqual([l.auxiliary_global,l.auxiliary_count,l.stride,l.receiver_bytes],['00ae2d0c','00ae2d10',79,60]);
 assert.deepEqual(l.new_primary_secondary_defaults,[-1,-1]);assert.deepEqual(l.default_sites,['0082854e','00828556']);
 assert.deepEqual([l.new_allocate_call,l.load_allocate_call],['008284ad -> 00944e46','0082af61 -> 00944e46']);
 assert.deepEqual(s.contract_frontier,{instruction:'004cf62b',advanced:false,reason:'no original allocator return, auxiliary records or initialized receiver'});
 assert.equal(s.evidence_class,'selected static native/PE observations and synthetic interior allocation-request execution');
}

export function check(){
 const raw=readFileSync(new URL('../evidence/action33-aux-35-oracle.bin',import.meta.url));assert.equal(hash(raw),ORACLE_HASH,'oracle hash');
 const expanded=gunzipSync(raw,{maxOutputLength:2000000}),value=JSON.parse(expanded);keys(value,'sites oracle');checkSites(value.sites);checkOracle(value.oracle);
 const receiptRaw=readFileSync(new URL('../evidence/action33-aux-35-validation.json',import.meta.url));assert.equal(hash(receiptRaw),RECEIPT_HASH,'receipt hash');
 const r=JSON.parse(receiptRaw);keys(r,'unit status specimen_sha256 evidence_sha256 expanded_canonical_sha256 normal_optimized_evidence native_compared_instructions pe_only_decoded_instructions coverage negative_probes privacy scope');
 assert.deepEqual([r.unit,r.status,r.specimen_sha256,r.evidence_sha256,r.expanded_canonical_sha256],['R35-B','passed',SPECIMEN,ORACLE_HASH,hash(expanded)]);
 assert.equal(r.normal_optimized_evidence,'byte-identical original-instruction regeneration');assert.deepEqual([r.native_compared_instructions,r.pe_only_decoded_instructions],[300,350]);
 assert.deepEqual(r.coverage,coverage);assert.deepEqual(r.negative_probes,probes);assert.equal(r.scope,SCOPE);
 assert.equal(r.privacy,'compressed and bounded expanded evidence plus authored files scanned for raw/hex/base64 samples');
 for(const mutate of [o=>o.cases[1].requested_bytes++,o=>o.cases[0].auxiliary_base_after=0x200000,o=>o.cases[0].allocator_call_executed=true]){
  const changed=structuredClone(value.oracle);mutate(changed);assert.throws(()=>checkOracle(changed));
 }
 console.log('R35-B: 18 synthetic allocation-request windows, 99 original steps; table and receiver unproduced');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)check();

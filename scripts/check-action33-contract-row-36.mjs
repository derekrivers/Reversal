#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';
const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='9c606eac088a3a6cdea2435a5bd6b3275b97452b81bf998177aaa410f39524a7',RECEIPT_HASH='da438f0d611e9ef186a1203b5c924e6702f9e64ccbed6f13951ca7a8af121d41';
const SCOPE='synthetic initializer/reserve entries stop before allocators; separate exhaustive interior source-eligibility windows; no row/index write or lookup return executed';
const counts=[0,1,2,31,64,255,0x3333333,0x80000000,0xffffffff],flags=[0,1,2,0x80000000,0xffffffff];
const classes=[0,6,7,8,9,10,11,12,13,15],order=[11,12,13,6,7,15,9,10,8];
const coverage={initializer_entries:9,reserve_entries:5,eligibility_windows:512,eligible:10,instruction_steps:7466,allocator_calls_executed:0,row_index_writes_executed:0,row_returns:0};
const hash=b=>createHash('sha256').update(b).digest('hex');
const keys=(o,s)=>assert.deepEqual(Object.keys(o).sort(),s.split(' ').sort());
const hex=(s,n=8)=>assert.match(s,new RegExp(`^[0-9a-f]{${n}}$`));
const regions='tactics rows club staff attributes match manager slots constructor_storage stack database_globals owner_globals status_globals crt_globals seh';
const probes=['changed specimen rejected','changed contracts manifest rejected','changed support manifest rejected','changed state manifest rejected',
 'executed wrong row allocation stride rejected','executed wrong temporary store rejected','executed wrong reserve capacity rejected','executed wrong eligible class rejected',
 'resealed row-index store width rejected','raw private fragment rejected','hex private fragment rejected','base64 private fragment rejected','excessive expansion rejected'];

function frontier(f){
 keys(f,'entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256');
 hex(f.entry);hex(f.stop);hex(f.trace_sha256,64);hex(f.events_sha256,64);
 for(const k of ['before_memory_sha256','after_memory_sha256']){keys(f[k],regions);Object.values(f[k]).forEach(v=>hex(v,64));}
 assert.equal(f.calls.length,f.call_frames.length);
 for(const [n,c] of f.call_frames.entries()){keys(c,'site target ecx arguments');assert.deepEqual(f.calls[n],[c.site,c.target]);assert.deepEqual(c.arguments,[]);}
}

export function checkOracle(o){
 keys(o,'unit specimen_sha256 synthetic_only scope initializer_frontiers reserve_frontiers eligibility_windows coverage');
 assert.deepEqual([o.unit,o.specimen_sha256,o.synthetic_only,o.scope],['R36-B',SPECIMEN,true,SCOPE]);assert.deepEqual(o.coverage,coverage);
 assert.equal(o.initializer_frontiers.length,9);assert.equal(o.reserve_frontiers.length,5);assert.equal(o.eligibility_windows.length,512);let steps=0;
 for(const [n,c] of o.initializer_frontiers.entries()){
  keys(c,'count requested_bytes receiver temporary allocator_executed function_returned frontier');
  assert.deepEqual([c.count,c.requested_bytes,c.receiver,c.temporary,c.allocator_executed,c.function_returned],
   [counts[n],Number(BigInt(counts[n])*80n&0xffffffffn),0x290000,0x307da4,false,false],'initializer allocation boundary');
  const f=c.frontier;frontier(f);assert.deepEqual([f.entry,f.stop,f.instruction_steps],['004c7560','004c75a4',61]);
  assert.deepEqual(f.call_frames,[{site:'004c7587',target:'0085e410',ecx:c.temporary,arguments:[]},
   {site:'0085e431',target:'0054a110',ecx:c.temporary+0x25,arguments:[]},{site:'0085e43f',target:'0054a110',ecx:c.temporary+0x2d,arguments:[]}]);steps+=f.instruction_steps;
  for(const k of Object.keys(f.before_memory_sha256))if(!['stack','seh','constructor_storage'].includes(k))assert.equal(f.before_memory_sha256[k],f.after_memory_sha256[k]);
 }
 for(const [n,c] of o.reserve_frontiers.entries()){
  keys(c,'flag receiver base capacity count requested_bytes allocator_executed function_returned frontier');
  assert.deepEqual([c.flag,c.receiver,c.base,c.capacity,c.count,c.requested_bytes,c.allocator_executed,c.function_returned],
   [flags[n],0x260000,0,200,0,16000,false,false],'reserve allocator boundary');
  const f=c.frontier;frontier(f);assert.deepEqual([f.entry,f.stop,f.instruction_steps],['004c79a0','004c7a02',n===0?23:18]);
  assert.deepEqual(f.calls,[]);steps+=f.instruction_steps;
  for(const k of Object.keys(f.before_memory_sha256))if(!['stack','manager'].includes(k))assert.equal(f.before_memory_sha256[k],f.after_memory_sha256[k]);
 }
 let admitted=0;
 for(const [n,c] of o.eligibility_windows.entries()){
  keys(c,'context classification eligible entry stop instruction_steps trace_sha256 events_sha256 memory_sha256 memory_unchanged observed_reads reserve_executed row_index_written');
  const context=n<256?0:0x220000,classification=n%256,eligible=context!==0&&classes.includes(classification);
  assert.deepEqual([c.context,c.classification,c.eligible,c.entry,c.stop],[context,classification,eligible,'004c7832',eligible?'004c786c':'004c7907'],'exact source eligibility');
  assert.deepEqual([c.memory_unchanged,c.reserve_executed,c.row_index_written],[true,false,false]);
  const index=order.indexOf(classification),count=context===0?3:index<0?24:6+index*2;
  assert.equal(c.instruction_steps,count);steps+=count;admitted+=Number(eligible);
  for(const k of ['trace_sha256','events_sha256','memory_sha256'])hex(c[k],64);
  assert.deepEqual(c.observed_reads,[['004c7832','read','00230039',4],...(context?[['004c783d','read','0023003d',1]]:[])]);
 }
 assert.equal(admitted,10);assert.equal(steps,7466);
}

function sites(s){
 keys(s,'unit baseline_commit specimen_sha256 scope manifest_sha256 export_sha256 selected_ranges row_publication_static lifetime_static connected_lookup');
 assert.deepEqual([s.unit,s.baseline_commit,s.specimen_sha256,s.scope],['R36-B','d984a187df89656313a76db249e56b91735ed984',SPECIMEN,SCOPE]);
 assert.deepEqual(s.manifest_sha256,{contracts:'12bcb7700e4982f1cc8d15786f27cc018db58fdba02de89b0e1eb81c10a6076c',support:'92d0708d6eada4983366d522314881e04c293b0bfaab4c467eb08f71992d7741',state:'b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a'});
 keys(s.export_sha256,'contracts support state');for(const group of Object.values(s.export_sha256))Object.values(group).forEach(v=>hex(v,64));
 assert.equal(s.selected_ranges.length,11);let native=0,pe=0;
 for(const [n,r] of s.selected_ranges.entries()){
  keys(r,'entry end_exclusive file_offset bytes sha256 instructions native_operands_match');for(const k of ['entry','end_exclusive','file_offset'])hex(r[k]);hex(r.sha256,64);
  assert.equal(parseInt(r.end_exclusive,16)-parseInt(r.entry,16),r.bytes);assert.equal(r.native_operands_match,n<6);
  if(r.native_operands_match)native+=r.instructions;else pe+=r.instructions;
 }
 assert.deepEqual([native,pe],[446,98]);
 const p=s.row_publication_static;
 keys(p,'executed eligibility_context_offset eligibility_class_offset eligible_classes reserve_call reserve_flag negative_result_skips_publication auxiliary_stride manager_row_stride auxiliary_index_store row_source_id_store row_constructor_call row_constructor_arguments first_row_constructor_date_dependency row_context_id_store row_context_resolution');
 assert.deepEqual([p.executed,p.eligibility_context_offset,p.eligibility_class_offset,p.eligible_classes,p.reserve_flag,p.negative_result_skips_publication,p.auxiliary_stride,p.manager_row_stride],
  [false,57,61,classes,1,true,79,80]);
 assert.deepEqual([p.auxiliary_index_store,p.row_source_id_store,p.row_constructor_call],['004c788e','004c789b','004c78a2 -> 0085e960']);
 assert.deepEqual(p.row_constructor_arguments,['source','source+52 DWORD']);
 keys(s.lifetime_static,'receiver_publish initializer_call row_growth_call receiver_destroy receiver_free receiver_clear auxiliary_free auxiliary_clear');
 assert.deepEqual(s.connected_lookup,{advanced:false,stop:'004cf62b',row_returned:false});
}

export function check(){
 const raw=readFileSync(new URL('../evidence/action33-contract-row-36-oracle.bin',import.meta.url));assert.equal(hash(raw),ORACLE_HASH,'oracle hash');
 const expanded=gunzipSync(raw,{maxOutputLength:2000000}),value=JSON.parse(expanded);keys(value,'sites oracle');sites(value.sites);checkOracle(value.oracle);
 const receiptRaw=readFileSync(new URL('../evidence/action33-contract-row-36-validation.json',import.meta.url));assert.equal(hash(receiptRaw),RECEIPT_HASH,'receipt hash');
 const r=JSON.parse(receiptRaw);keys(r,'unit status specimen_sha256 evidence_sha256 expanded_canonical_sha256 normal_optimized_evidence native_compared_instructions pe_only_decoded_instructions coverage negative_probes privacy scope');
 assert.deepEqual([r.unit,r.status,r.specimen_sha256,r.evidence_sha256,r.expanded_canonical_sha256],['R36-B','passed',SPECIMEN,ORACLE_HASH,hash(expanded)]);
 assert.deepEqual([r.normal_optimized_evidence,r.native_compared_instructions,r.pe_only_decoded_instructions],['byte-identical original-instruction regeneration',446,98]);
 assert.deepEqual(r.coverage,coverage);assert.deepEqual(r.negative_probes,probes);assert.equal(r.scope,SCOPE);
 assert.equal(r.privacy,'compressed and bounded expanded evidence plus authored files scanned for raw/hex/base64 samples');
 for(const mutate of [o=>o.initializer_frontiers[1].requested_bytes++,o=>o.reserve_frontiers[0].capacity++,o=>o.eligibility_windows[256].eligible=false,o=>o.coverage.row_index_writes_executed=1]){
  const changed=structuredClone(value.oracle);mutate(changed);assert.throws(()=>checkOracle(changed));
 }
 console.log('R36-B: 9 initializer + 5 reserve frontiers, 512 eligibility windows, 7466 original steps; no row produced');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)check();

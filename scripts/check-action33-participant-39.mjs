#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';
import {checkRetained as checkPrior} from './check-action33-slot-32.mjs';
const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE='840645b6471b3c528354ff90e81be1f4b2258aad78537358ecf69a05437dbf68';
const RECEIPT='fc7b45029c1b4bd2bcccb218be5c2243bbccbba07a80b46ab91dc99314765a37';
const PRIOR='8c0ed7d1f2d662ca7d7bc597373371b16f136ea86ec9d080f366a61cfefdcded';
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const hx=n=>n.toString(16).padStart(8,'0');
const keys=(v,n)=>assert.deepEqual(Object.keys(v).sort(),n.split(' ').sort());
const hex=v=>assert.match(v,/^[0-9a-f]{64}$/);
const common='entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256'.split(' ');
const coverage={cases:80,prefix_instruction_steps:25280,new_instruction_steps:1120,new_memory_events:880};
const negativeProbes=['changed specimen','changed inherited native manifest','changed authored heap operand',
 'executed wrong heap global','executed wrong heap mode source','executed wrong original participant store',
 'resealed inherited native width','late raw private excerpt','late lowercase hex','late uppercase hex',
 'embedded base64 alignment zero','embedded base64 alignment one','embedded base64 alignment two','excessive gzip expansion'];
const root=new URL('../',import.meta.url);

export function checkOracle(o,prior){
 keys(o,'unit specimen_sha256 prior_oracle_sha256 synthetic_separate_entries resolver_entered effect_returned frontier cases coverage');
 assert.equal(o.unit,'R39-B');assert.equal(o.specimen_sha256,SPECIMEN);assert.equal(o.prior_oracle_sha256,PRIOR);
 assert.equal(o.synthetic_separate_entries,true);assert.equal(o.resolver_entered,false);assert.equal(o.effect_returned,false);
 assert.deepEqual(o.frontier,{site:'0094bf49',iat:'009670dc',symbol:'KERNEL32.dll!HeapSize',
  reason:'CRT heap handle, mode and exit-list storage not initialized'});
 assert.deepEqual(o.coverage,coverage);assert.equal(o.cases.length,80);
 for(const [n,c] of o.cases.entries()){
  keys(c,'club_id index original_lookup_result slot slot_record prefix_sha256 prefix_instruction_steps initial_cpu final_cpu continuation events heap_size_arguments lookup_global');
  const old=prior.cases[n],club=Math.floor(n/20),index=n%20,id=(club*11+index)%32,record=0x230000+0x6e*id;
  assert.deepEqual([c.club_id,c.index,c.slot,c.original_lookup_result,c.slot_record],
   [club,index,0x280000+0x1be*index,record,record],'original participant alias');
  const stages=Object.fromEntries(['initializer','lookup','placement','status'].map(name=>[name,
   Object.fromEntries(common.map(k=>[k,old[name][k]]))]));
  assert.equal(c.prefix_sha256,hash(JSON.stringify(stages)),'complete prior prefix');assert.equal(c.prefix_instruction_steps,316);
  const i=c.initial_cpu,f=c.final_cpu,s=c.continuation,p=i.esp;
  for(const r of [i,f]){keys(r,'eax ebx ecx edx esi edi ebp esp eip eflags fpcw fpsw fptag');
   Object.values(r).forEach(x=>assert.ok(Number.isInteger(x)&&x>=0&&x<=0xffffffff));}
  assert.deepEqual(i,{eax:0xb63d08,ebx:0x12345678,ecx:0xb63d08,edx:0x87654301,esi:0,edi:record,
   ebp:0,esp:0x307d90,eip:0x946214,eflags:0x202,fpcw:0,fpsw:0,fptag:0x5555},'pending original status CPU');
  assert.deepEqual(f,{...i,eax:0,ebp:p-8,esp:p-32,eip:0x94bf49,eflags:0x293},'continuation CPU');
  keys(s,common.join(' '));assert.deepEqual([s.entry,s.stop,s.instruction_steps,s.ordered_memory_events],['00946214','0094bf49',14,11]);
  assert.deepEqual(s.calls,[['00946214','0094bef1']]);
  assert.deepEqual(s.call_frames,[{site:'00946214',target:'0094bef1',ecx:i.ecx,arguments:[0]}],'original CRT frame');
  assert.deepEqual(s.before_memory_sha256,old.status.after_memory_sha256,'status memory continuity');
  for(const [name,digest] of Object.entries(s.before_memory_sha256)){
   hex(digest);hex(s.after_memory_sha256[name]);
   if(name==='stack')assert.notEqual(digest,s.after_memory_sha256[name]);else assert.equal(digest,s.after_memory_sha256[name]);
  }
  const events=[['00946214','write',hx(p-4),4],['0094bef1','write',hx(p-8),4],
   ['0094bef4','write',hx(p-12),4],['0094bef5','write',hx(p-16),4],['0094bef6','read','00de4404',4],
   ['0094befb','write',hx(p-20),4],['0094bf3e','read',hx(p),4],['0094bf3e','write',hx(p-24),4],
   ['0094bf41','write',hx(p-28),4],['0094bf43','read','00de4400',4],['0094bf43','write',hx(p-32),4]];
  assert.deepEqual(c.events,events,'ordered operand/source events');assert.equal(s.events_sha256,hash(JSON.stringify(events)));
  assert.equal(s.trace_sha256,'379866e2b93e2301973e88c1fa68ca04cbfebb69efb70488d6de6e20a517a53c');
  assert.deepEqual(c.heap_size_arguments,[0,0,0],'HeapSize arguments');assert.equal(c.lookup_global,0);
 }
}

export function checkRetained(raw,receiptRaw){
 assert.equal(hash(raw),ORACLE,'oracle integrity');assert.equal(hash(receiptRaw),RECEIPT,'receipt integrity');
 const priorRaw=readFileSync(new URL('evidence/action33-slot-32-oracle.bin',root));
 checkPrior(priorRaw,readFileSync(new URL('evidence/action33-slot-32-validation.json',root)));
 const prior=JSON.parse(gunzipSync(priorRaw)).oracle;
 const expanded=gunzipSync(raw,{maxOutputLength:2000000}),v=JSON.parse(expanded),r=JSON.parse(receiptRaw);
 keys(v,'sites oracle');checkOracle(v.oracle,prior);
 const s=v.sites;assert.equal(s.unit,'R39-B');assert.equal(s.specimen_sha256,SPECIMEN);assert.equal(s.baseline_commit,'58f3033');
 assert.equal(s.ranges.reduce((n,x)=>n+x.instructions,0),875);assert.equal(s.extra_ranges.reduce((n,x)=>n+x.instructions,0),819);
 for(const range of s.extra_ranges){
  keys(range,'entry end_exclusive file_offset bytes sha256 instructions all_native_operands_match source');hex(range.sha256);
  assert.equal(range.all_native_operands_match,false);assert.equal(range.source,'pinned PE only; no focused native export');
  assert.equal(parseInt(range.end_exclusive,16)-parseInt(range.entry,16),range.bytes);
 }
 assert.deepEqual(s.crt_imports,{'009670dc':{dll:'KERNEL32.dll',symbol:'HeapSize'},
  '00967110':{dll:'KERNEL32.dll',symbol:'HeapCreate'},'00967114':{dll:'KERNEL32.dll',symbol:'HeapDestroy'}});
 keys(r,'unit status specimen_sha256 oracle_sha256 expanded_sha256 normal_optimized_regeneration coverage native_compared_instructions pe_only_instructions privacy_windows privacy_forms negative_probes limits');
 assert.equal(r.unit,'R39-B');assert.equal(r.status,'passed');assert.equal(r.specimen_sha256,SPECIMEN);
 assert.equal(r.oracle_sha256,hash(raw));assert.equal(r.expanded_sha256,hash(expanded));
 assert.equal(r.normal_optimized_regeneration,'byte-identical');assert.deepEqual(r.coverage,coverage);
 assert.equal(r.native_compared_instructions,875);assert.equal(r.pe_only_instructions,819);
 assert.ok(r.privacy_windows>4000);assert.ok(r.privacy_forms>r.privacy_windows);
 assert.deepEqual(r.negative_probes,negativeProbes);
 assert.equal(r.limits,'separate synthetic entries; no resolver, Windows calls, initialized lookup object, TypeScript or live claim');
 const bad=structuredClone(v.oracle);bad.cases[0].slot_record^=1;assert.throws(()=>checkOracle(bad,prior),/original participant alias/);
 const wrong=structuredClone(v.oracle);wrong.cases[0].events[9][2]='00de4404';assert.throws(()=>checkOracle(wrong,prior),/ordered operand/);
 return {unit:'R39-B',status:'passed',node:process.version,...coverage,native_compared_instructions:875,pe_only_instructions:819};
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 console.log(JSON.stringify(checkRetained(readFileSync(new URL('evidence/action33-participant-39-oracle.bin',root)),
  readFileSync(new URL('evidence/action33-participant-39-validation.json',root)))));
}

#!/usr/bin/env node
// Retained synthetic instruction observations; no private PE or native export.
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';
const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='8c0ed7d1f2d662ca7d7bc597373371b16f136ea86ec9d080f366a61cfefdcded';
const RECEIPT_HASH='7766d436de06a0cd8f02f08bb73347263fe80c78cf69f31e57f9c15cc299e322';
const SLOT_MANIFEST='4a50131744515c61a2f18ed4149342950e81c0e051bb79399aaefd349737ed3d';
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const keys=(o,n)=>assert.deepEqual(Object.keys(o).sort(),n.split(' ').sort());
const hex=(v,n=8)=>assert.match(v,new RegExp(`^[0-9a-f]{${n}}$`));
const uint=v=>assert.ok(Number.isInteger(v)&&v>=0&&v<=0xffffffff);
const common='entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256';
const regions='tactics rows club staff attributes match manager slots constructor_storage stack database_globals owner_globals status_globals crt_globals seh';
const coverage={initializer_returns:80,lookup_returns:80,placement_frontiers:80,normal_status_frontiers:80,instruction_steps:25280};
const negativeProbes=['changed specimen rejected','changed slot manifest rejected','resealed initializer width operand rejected',
 'executed wrong initializer side field rejected','executed wrong prior-side read rejected','executed wrong slot context store rejected',
 'raw private fragment in container rejected','hex private fragment in expanded JSON rejected','oversized gzip expansion rejected'];
function regs(r){keys(r,'eax ebx ecx edx esi edi ebp esp eip');Object.values(r).forEach(uint);}
function stage(s,extra){
 keys(s,common+' '+extra);hex(s.entry);hex(s.stop);uint(s.instruction_steps);uint(s.ordered_memory_events);
 hex(s.trace_sha256,64);hex(s.events_sha256,64);
 for(const name of ['before_memory_sha256','after_memory_sha256']){keys(s[name],regions);Object.values(s[name]).forEach(v=>hex(v,64));}
 assert.equal(s.calls.length,s.call_frames.length);
 for(const [n,f] of s.call_frames.entries()){
  keys(f,'site target ecx arguments');hex(f.site);hex(f.target);uint(f.ecx);f.arguments.forEach(uint);
  assert.deepEqual(s.calls[n],[f.site,f.target]);
 }
}
export function checkOracle(o){
 keys(o,'unit specimen_sha256 synthetic_only pipeline_scope cases coverage');
 assert.equal(o.unit,'R32-B');assert.equal(o.specimen_sha256,SPECIMEN);assert.equal(o.synthetic_only,true);
 assert.equal(o.pipeline_scope,'separate original entries preserve slot initializer output and consume original returned staff pointer');
 assert.deepEqual(o.coverage,coverage);assert.equal(o.cases.length,80);let steps=0;
 for(const [n,c] of o.cases.entries()){
  keys(c,'club_id index staff_id initializer lookup placement status');const club=Math.floor(n/20),index=n%20,id=(club*11+index)%32;
  const slot=0x280000+0x1be*index,staff=0x230000+0x6e*id,attribute=0x240000+0x46*id;
  assert.deepEqual([c.club_id,c.index,c.staff_id],[club,index,id]);
  const i=c.initializer;stage(i,'receiver initial_registers final_registers function_returned side_write side_value');
  assert.deepEqual([i.entry,i.stop,i.receiver,i.function_returned,i.side_value],['006eada0','00700000',slot,true,0],'initializer side output');
  assert.deepEqual(i.side_write,['006eadb2','write',(slot+0x27).toString(16).padStart(8,'0'),1],'initializer side store');
  assert.deepEqual(i.calls,[]);regs(i.initial_registers);regs(i.final_registers);
  assert.equal(i.initial_registers.ecx,slot);assert.equal(i.final_registers.eax,slot);assert.equal(i.final_registers.esp,0x308004);
  assert.equal(i.final_registers.eip,0x700000);for(const r of ['ebx','esi','edi','ebp'])assert.equal(i.final_registers[r],i.initial_registers[r]);
  const l=c.lookup;stage(l,'returned_record initial_registers final_registers');regs(l.initial_registers);regs(l.final_registers);
  assert.deepEqual([l.entry,l.stop,l.returned_record,l.final_registers.eax,l.final_registers.esp],['008968f0','00700000',staff,staff,0x308010]);
  assert.deepEqual(l.calls,[['0089695c','008982b0'],['008982c8','00600a50'],['00600be6','005409b0'],['008969cb','0053b900']]);
  assert.deepEqual(l.call_frames.map(f=>f.arguments),[[0x220000,0],[0x220000,1,1,0,0],[0x220000],[0x220000]]);
  for(const r of ['ebx','esi','edi','ebp'])assert.equal(l.final_registers[r],l.initial_registers[r]);
  const p=c.placement;stage(p,'slot staff_alias attribute_alias side_read side_value final_registers function_returned stop_reason');regs(p.final_registers);
  assert.deepEqual([p.entry,p.stop,p.slot,p.staff_alias,p.attribute_alias,p.side_value,p.function_returned],
   ['006e0d00','006eaf8f',slot,staff,attribute,0,false]);
  assert.deepEqual(p.side_read,['006eaf77','read',(slot+0x27).toString(16).padStart(8,'0'),1],'placement prior-side read');
  assert.equal(p.stop_reason,'before 006eaf8f reads unproduced match+4792 owner pointer');
  assert.equal(p.final_registers.eax,0x250000);assert.equal(p.final_registers.ecx&255,0);assert.equal(p.final_registers.eip,0x6eaf8f);
  assert.deepEqual(p.call_frames,[{site:'006e0dde',target:'006eaea0',ecx:slot,
    arguments:[0x250000,staff,0x89abcd00+club,0xa5a50000+index,0x89abcd80+club]}],'placement call provenance');
  const s=c.status;stage(s,'record_argument lookup_global unsupported_argument function_returned stop_reason');
  assert.deepEqual([s.entry,s.stop,s.record_argument,s.lookup_global,s.unsupported_argument,s.function_returned],
   ['0062ed70','00946214',staff,0,0,false]);
  assert.equal(s.stop_reason,'before 00946214 -> 0094bef1 with loader-zero exit-list base');
  assert.deepEqual(s.calls,[['0062edfc','0062c680'],['0062c6c8','0054a110'],['0062c6d2','0094627a'],['0094627e','0094620d']]);
  assert.deepEqual(s.call_frames.map(f=>[f.ecx,f.arguments]),[[0,[staff]],[0xb63d08,[]],[0xb63d08,[0x62ce20]],[0xb63d08,[0x62ce20]]]);
  assert.deepEqual(['initializer','lookup','placement','status'].map(name=>c[name].instruction_steps),[67,135,66,48]);
  for(const name of ['initializer','lookup','placement','status'])steps+=c[name].instruction_steps;
 }
 assert.equal(steps,coverage.instruction_steps);
}
export function checkRetained(raw,receiptRaw){
 assert.equal(hash(raw),ORACLE_HASH,'oracle hash');assert.equal(hash(receiptRaw),RECEIPT_HASH,'receipt hash');
 const expanded=gunzipSync(raw,{maxOutputLength:2000000}),v=JSON.parse(expanded),r=JSON.parse(receiptRaw);
 keys(v,'sites oracle');checkOracle(v.oracle);const s=v.sites;
 keys(s,'unit baseline_commit specimen_sha256 manifest_sha256 source_archive_sha256 export_hashes ranges zero_tail_globals constructor_imports scope slot_manifest_sha256 slot_export_hashes');
 assert.equal(s.unit,'R32-B');assert.equal(s.specimen_sha256,SPECIMEN);assert.equal(s.baseline_commit,'06de3f3db9da6627a9efae47e5d0d87942b696ae');
 assert.equal(s.slot_manifest_sha256,SLOT_MANIFEST);Object.values(s.slot_export_hashes).forEach(v=>hex(v,64));
 assert.equal(s.scope,'selected static ranges and synthetic original entries; no game caller, completed slot or live lifecycle');
 assert.equal(s.ranges.length,20);let instructions=0;for(const range of s.ranges){
  keys(range,'entry end_exclusive file_offset bytes sha256 instructions all_native_operands_match');
  for(const k of ['entry','end_exclusive','file_offset'])hex(range[k]);hex(range.sha256,64);uint(range.bytes);uint(range.instructions);
  assert.equal(parseInt(range.end_exclusive,16)-parseInt(range.entry,16),range.bytes);assert.equal(range.all_native_operands_match,true);instructions+=range.instructions;
 }
 assert.equal(instructions,875);
 assert.ok(s.ranges.some(r=>r.entry==='006eada0'&&r.end_exclusive==='006eae98'));
 assert.ok(s.ranges.some(r=>r.entry==='006eaea0'&&r.end_exclusive==='006eaf98'));
 keys(r,'unit status specimen_sha256 evidence_sha256 expanded_canonical_sha256 compressed_bytes expanded_canonical_bytes normal_optimized_evidence compared_instructions coverage negative_probes privacy limits');
 assert.equal(r.unit,'R32-B');assert.equal(r.status,'passed');assert.equal(r.specimen_sha256,SPECIMEN);
 assert.equal(r.evidence_sha256,hash(raw));assert.equal(r.expanded_canonical_sha256,hash(expanded));assert.equal(r.compressed_bytes,raw.length);assert.equal(r.expanded_canonical_bytes,expanded.length);
 assert.equal(r.normal_optimized_evidence,'byte-identical original-instruction regeneration');assert.equal(r.compared_instructions,instructions);
 assert.deepEqual(r.coverage,coverage);assert.deepEqual(r.negative_probes,negativeProbes);
 assert.equal(r.privacy,'compressed and bounded expanded bytes plus authored files scanned for raw/hex/base64 code/source samples');
 assert.equal(r.limits,'separate synthetic original entries; no enclosing caller, loaded game, complete slot, lookup object or normal effect return');
 const bad=structuredClone(v.oracle);bad.cases[0].initializer.side_value=1;assert.throws(()=>checkOracle(bad),/initializer side output/);
 const wrong=structuredClone(v.oracle);wrong.cases[0].placement.side_read[2]='00280026';assert.throws(()=>checkOracle(wrong),/placement prior-side read/);
 return {unit:'R32-B',status:'passed',node:process.version,compared_instructions:instructions,...coverage};
}
if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 const root=new URL('../',import.meta.url);console.log(JSON.stringify(checkRetained(readFileSync(new URL('evidence/action33-slot-32-oracle.bin',root)),
  readFileSync(new URL('evidence/action33-slot-32-validation.json',root)))));
}

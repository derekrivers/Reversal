#!/usr/bin/env node
// Retained original observations on synthetic interior windows and entries.
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';
const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='f5dbbdff245eda8bbe946430461a93c76b8dd971e0d2d52e89d667c45681eafd';
const RECEIPT_HASH='32b1dd813f7d6c16300b2d8e8e09f903bcafec0d5b5dfa626e3c066f76731a44';
const SCOPE='synthetic interior producer windows and separate initializer/lookup/placement entries; no connected enclosing caller or live lifecycle';
const hash=b=>createHash('sha256').update(b).digest('hex');
const keys=(o,s)=>assert.deepEqual(Object.keys(o).sort(),s.split(' ').sort());
const hex=(s,n=8)=>assert.match(s,new RegExp(`^[0-9a-f]{${n}}$`));
const uint=n=>assert.ok(Number.isInteger(n)&&n>=0&&n<=0xffffffff);
const hx=n=>n.toString(16).padStart(8,'0');
const stages=['producer','binding','initializer','lookup','placement'];
const common='entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256';
const regions='tactics rows club staff attributes match manager slots constructor_storage stack database_globals owner_globals status_globals crt_globals seh club_records';
const extras={producer:'home_id away_id home_pointer away_pointer fixture pointer_writes function_entry',
 binding:'owner_pointer owner_write function_entry callee_entry_executed function_returned',
 initializer:'receiver side_value function_returned',lookup:'returned_record function_returned',
 placement:'slot staff_alias attribute_alias owner_pointer owner_reads side_value fixture_preserved next_call final_registers function_returned'};
const coverage={interior_fixture_producers:80,interior_caller_bindings:80,initializer_returns:80,
 lookup_returns:80,placement_frontiers:80,instruction_steps:25520};
const probes=['changed specimen rejected','changed owner manifest rejected','changed database manifest rejected',
 'resealed owner-store width rejected','executed wrong owner-store field rejected','executed wrong club-pointer destination rejected',
 'executed away-club read on home branch rejected','raw private fragment in container rejected',
 'hex private fragment in expanded JSON rejected','oversized gzip expansion rejected'];

function stage(s,kind){
 keys(s,common+' '+extras[kind]);hex(s.entry);hex(s.stop);uint(s.instruction_steps);uint(s.ordered_memory_events);
 hex(s.trace_sha256,64);hex(s.events_sha256,64);
 for(const k of ['before_memory_sha256','after_memory_sha256']){keys(s[k],regions);Object.values(s[k]).forEach(v=>hex(v,64));}
 assert.equal(s.calls.length,s.call_frames.length);
 for(const [n,f] of s.call_frames.entries()){
  keys(f,'site target ecx arguments');hex(f.site);hex(f.target);uint(f.ecx);f.arguments.forEach(uint);
  assert.deepEqual(s.calls[n],[f.site,f.target]);
 }
}

export function checkOracle(o){
 keys(o,'unit specimen_sha256 synthetic_only scope cases coverage');
 assert.deepEqual([o.unit,o.specimen_sha256,o.synthetic_only,o.scope],['R33-B',SPECIMEN,true,SCOPE]);
 assert.deepEqual(o.coverage,coverage);assert.equal(o.cases.length,80);let total=0;
 for(const [n,c] of o.cases.entries()){
  keys(c,'club_id index staff_id producer binding initializer lookup placement');
  const club=Math.floor(n/20),index=n%20,id=(club*11+index)%32;
  const slot=0x280000+0x1be*index,staff=0x230000+0x6e*id,attribute=0x240000+0x46*id;
  const fixture=0x304040,home=0x2a0000+0x245*club,away=0x2a0000+0x245*(7+index);
  assert.deepEqual([c.club_id,c.index,c.staff_id],[club,index,id]);
  for(const kind of stages){stage(c[kind],kind);total+=c[kind].instruction_steps;}
  assert.deepEqual(stages.map(s=>c[s].instruction_steps),[23,23,67,135,71]);
  const p=c.producer;
  assert.deepEqual([p.entry,p.stop,p.function_entry,p.home_id,p.away_id,p.fixture,p.home_pointer,p.away_pointer],
   ['0084c266','0084c2b1',false,club,7+index,fixture,home,away],'original club producer');
  assert.deepEqual(p.pointer_writes,[['0084c294','write',hx(fixture+0x1c),4],['0084c2ad','write',hx(fixture+0x20),4]]);
  assert.deepEqual(p.calls,[]);
  const b=c.binding;
  assert.deepEqual([b.entry,b.stop,b.function_entry,b.callee_entry_executed,b.function_returned,b.owner_pointer],
   ['0084c3dd','006b7f54',false,true,false,fixture],'original owner binding');
  assert.deepEqual(b.owner_write,['006b7f4e','write','00254792',4]);
  assert.deepEqual(b.call_frames,[{site:'0084c3e8',target:'006b7f20',ecx:0x250000,arguments:[fixture,1,0,0]}]);
  const i=c.initializer;
  assert.deepEqual([i.entry,i.stop,i.receiver,i.side_value,i.function_returned],['006eada0','00700000',slot,0,true]);
  assert.deepEqual(i.calls,[]);
  const l=c.lookup;
  assert.deepEqual([l.entry,l.stop,l.returned_record,l.function_returned],['008968f0','00700000',staff,true]);
  assert.deepEqual(l.calls,[['0089695c','008982b0'],['008982c8','00600a50'],['00600be6','005409b0'],['008969cb','0053b900']]);
  assert.deepEqual(l.call_frames.map(f=>f.arguments),[[0x220000,0],[0x220000,1,1,0,0],[0x220000],[0x220000]]);
  const q=c.placement;
  assert.deepEqual([q.entry,q.stop,q.slot,q.staff_alias,q.attribute_alias,q.owner_pointer,q.side_value,q.fixture_preserved,q.function_returned],
   ['006e0d00','006eafa0',slot,staff,attribute,fixture,0,true,false]);
  assert.deepEqual(q.owner_reads,[['006eaf8f','read','00254792',4],['006eaf95','read',hx(fixture+0x1c),4]],'owner alias reads');
  assert.deepEqual(q.call_frames,[{site:'006e0dde',target:'006eaea0',ecx:slot,
   arguments:[0x250000,staff,0x89abcd00+club,0xa5a50000+index,0x89abcd80+club]}]);
  keys(q.next_call,'site target ecx arguments executed');
  assert.deepEqual(q.next_call,{site:'006eafa0',target:'004cf5f0',ecx:0,arguments:[staff,home],executed:false},'contract call boundary');
  keys(q.final_registers,'eax ebx ecx edx esi edi ebp esp eip');Object.values(q.final_registers).forEach(uint);
  assert.equal(q.final_registers.eip,0x6eafa0);assert.equal(q.final_registers.eax,home);assert.equal(q.final_registers.ecx,0);
 }
 assert.equal(total,coverage.instruction_steps);
}

export function checkRetained(raw,receiptRaw){
 assert.equal(hash(raw),ORACLE_HASH,'oracle hash');assert.equal(hash(receiptRaw),RECEIPT_HASH,'receipt hash');
 const expanded=gunzipSync(raw,{maxOutputLength:2000000}),v=JSON.parse(expanded),r=JSON.parse(receiptRaw);
 keys(v,'sites oracle');checkOracle(v.oracle);const s=v.sites;
 keys(s,'unit baseline_commit specimen_sha256 manifest_sha256 source_archive_sha256 export_hashes ranges zero_tail_globals constructor_imports scope slot_manifest_sha256 slot_export_hashes owner_manifest_sha256 database_manifest_sha256 owner_export_hashes database_export_hashes');
 assert.deepEqual([s.unit,s.baseline_commit,s.specimen_sha256,s.scope],['R33-B','afbdea6fb05957f11fbfa83dbe852cc85f656cf9',SPECIMEN,SCOPE]);
 assert.equal(s.owner_manifest_sha256,'42425fa15eeb2da209497e396b81bacc99e77a2c608500cdd9febd7ee9091f79');
 assert.equal(s.database_manifest_sha256,'83d24d0790139ab37f7e3c82e12dfff9844456a8273e8d5ee10d1036359c7daf');
 assert.equal(s.slot_manifest_sha256,'4a50131744515c61a2f18ed4149342950e81c0e051bb79399aaefd349737ed3d');
 for(const name of ['manifest_sha256','source_archive_sha256','export_hashes','slot_export_hashes','owner_export_hashes','database_export_hashes']){
  Object.values(s[name]).forEach(v=>hex(v,64));
 }
 assert.deepEqual(s.zero_tail_globals['00ae1050'],{loader_zero:true,game_initializer_executed:false});
 assert.equal(s.ranges.length,34);let instructions=0;
 for(const range of s.ranges){
  keys(range,'entry end_exclusive file_offset bytes sha256 instructions all_native_operands_match');
  for(const k of ['entry','end_exclusive','file_offset'])hex(range[k]);hex(range.sha256,64);
  uint(range.bytes);uint(range.instructions);assert.equal(parseInt(range.end_exclusive,16)-parseInt(range.entry,16),range.bytes);
  assert.equal(range.all_native_operands_match,true);instructions+=range.instructions;
 }
 assert.equal(instructions,1035);
 keys(r,'unit status specimen_sha256 evidence_sha256 expanded_canonical_sha256 compressed_bytes expanded_canonical_bytes normal_optimized_evidence compared_instructions coverage negative_probes privacy limits');
 assert.deepEqual([r.unit,r.status,r.specimen_sha256,r.evidence_sha256],['R33-B','passed',SPECIMEN,hash(raw)]);
 assert.equal(r.expanded_canonical_sha256,hash(expanded));assert.equal(r.compressed_bytes,raw.length);assert.equal(r.expanded_canonical_bytes,expanded.length);
 assert.equal(r.normal_optimized_evidence,'byte-identical original-instruction regeneration');assert.equal(r.compared_instructions,instructions);
 assert.deepEqual(r.coverage,coverage);assert.deepEqual(r.negative_probes,probes);
 assert.equal(r.privacy,'compressed and bounded expanded bytes plus authored files scanned for raw/hex/base64 code/source samples');assert.equal(r.limits,SCOPE);
 const swapped=structuredClone(v.oracle);swapped.cases[0].producer.home_pointer=swapped.cases[0].producer.away_pointer;
 assert.throws(()=>checkOracle(swapped),/original club producer/);
 const changed=structuredClone(v.oracle);changed.cases[0].placement.next_call.arguments[1]=changed.cases[0].producer.away_pointer;
 assert.throws(()=>checkOracle(changed),/contract call boundary/);
 return {unit:'R33-B',status:'passed',node:process.version,compared_instructions:instructions,...coverage};
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 const root=new URL('../',import.meta.url);console.log(JSON.stringify(checkRetained(readFileSync(new URL('evidence/action33-owner-33-oracle.bin',root)),
  readFileSync(new URL('evidence/action33-owner-33-validation.json',root)))));
}

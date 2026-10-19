#!/usr/bin/env node
// Retained synthetic fixture evidence; no original PE, native database or emulator.
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';

const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='ecb4bcc534d285a6b5a28653fe8575795ca981363846c6b3576563237ca24dd9';
const RECEIPT_HASH='3bf6ff39b03e496213f270f911753de81064c584c5c77c7aec77126356a0b838';
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const keys=(value,names)=>assert.deepEqual(Object.keys(value).sort(),names.split(' ').sort());
const hex=(value,n=8)=>assert.match(value,new RegExp(`^[0-9a-f]{${n}}$`));
const uint=value=>assert.ok(Number.isInteger(value)&&value>=0&&value<=0xffffffff);
const memoryNames='tactics rows club staff attributes match manager slots constructor_storage stack database_globals owner_globals status_globals crt_globals seh';
const common='entry stop calls call_frames instruction_steps ordered_memory_events trace_sha256 events_sha256 before_memory_sha256 after_memory_sha256';
const registers='eax ebx ecx edx esi edi ebp esp eip';
const coverage={lookup_returns:160,nonnull_returns:80,null_attribute_returns:80,placement_frontiers:80,
 normal_status_frontiers:80,null_diagnostic_frontiers:80,constructor_os_frontiers:8,instruction_steps:29800};
const negatives=['changed specimen rejected','changed native manifest rejected','resealed roster-ID operand rejected',
 'executed wrong returned staff base rejected','executed wrong slot context store rejected',
 'raw private fragment in compressed container rejected','hex private fragment in expanded JSON rejected','oversized gzip expansion rejected'];

function stage(s,extra){
 keys(s,common+' '+extra);hex(s.entry);hex(s.stop);uint(s.instruction_steps);uint(s.ordered_memory_events);
 hex(s.trace_sha256,64);hex(s.events_sha256,64);
 for(const name of ['before_memory_sha256','after_memory_sha256']){
  keys(s[name],memoryNames);Object.values(s[name]).forEach(value=>hex(value,64));
 }
 assert.equal(s.calls.length,s.call_frames.length);
 for(const [n,f] of s.call_frames.entries()){
  keys(f,'site target ecx arguments');hex(f.site);hex(f.target);uint(f.ecx);f.arguments.forEach(uint);
  assert.deepEqual(s.calls[n],[f.site,f.target]);
 }
}

export function checkOracle(o){
 keys(o,'unit specimen_sha256 synthetic_only pipeline_scope cases constructor_frontiers coverage');
 assert.equal(o.unit,'R31-B');assert.equal(o.specimen_sha256,SPECIMEN);assert.equal(o.synthetic_only,true);
 assert.equal(o.pipeline_scope,'separate original function entries consume actual returned lookup pointer; no enclosing game caller or live initialization claim');
 assert.deepEqual(o.coverage,coverage);assert.equal(o.cases.length,160);assert.equal(o.constructor_frontiers.length,8);
 let steps=0;
 for(const [n,c] of o.cases.entries()){
  const club=Math.floor(n/40),index=Math.floor(n/2)%20,nonnull=n%2===0,id=(club*11+index)%32;
  const staff=0x230000+0x6e*id,attribute=0x240000+0x46*id,slot=0x280000+0x1be*index;
  keys(c,'club_id index staff_id attribute_nonnull table_cell lookup status'+(nonnull?' placement':''));
  assert.deepEqual([c.club_id,c.index,c.staff_id,c.attribute_nonnull,c.table_cell],
   [club,index,id,nonnull,0x210000+0x91*club+2+4*index]);
  const l=c.lookup;stage(l,'returned_record initial_registers final_registers');
  assert.equal(l.entry,'008968f0');assert.equal(l.stop,'00700000');assert.equal(l.returned_record,nonnull?staff:0,'lookup result');
  for(const name of ['initial_registers','final_registers']){keys(l[name],registers);Object.values(l[name]).forEach(uint);}
  assert.deepEqual(l.initial_registers,{eax:0xdeadbeef,ebx:0x12345678,ecx:0x200000,edx:0x87654321,
   esi:0x01020304,edi:0xfeedface,ebp:0xcafef00d,esp:0x308000,eip:0x8968f0});
  assert.equal(l.final_registers.eax,l.returned_record);assert.equal(l.final_registers.esp,0x308010);assert.equal(l.final_registers.eip,0x700000);
  for(const r of ['ebx','esi','edi','ebp'])assert.equal(l.final_registers[r],l.initial_registers[r]);
  const calls=[['0089695c','008982b0'],['008982c8','00600a50'],['00600be6','005409b0']];
  if(nonnull)calls.push(['008969cb','0053b900']);assert.deepEqual(l.calls,calls);
  assert.deepEqual(l.call_frames.map(f=>f.arguments),[[0x220000,0],[0x220000,1,1,0,0],[0x220000],...(nonnull?[[0x220000]]:[])]);
  if(nonnull){
   const p=c.placement;stage(p,'slot staff_alias attribute_alias function_returned stop_reason');
   assert.equal(p.entry,'006e0d00');assert.equal(p.stop,'006eaf77');
   assert.deepEqual([p.slot,p.staff_alias,p.attribute_alias,p.function_returned],[slot,staff,attribute,false]);
   assert.equal(p.stop_reason,'next read 006eaf77 requires pre-existing slot+27 side byte');
   assert.deepEqual(p.call_frames,[{site:'006e0dde',target:'006eaea0',ecx:slot,
    arguments:[0x250000,staff,0x89abcd00+club,0xa5a50000+index,0x89abcd80+club]}],'placement call provenance');
   steps+=p.instruction_steps;
  }
  const s=c.status;stage(s,'stop_reason lookup_global record_argument function_returned '+(nonnull?'unsupported_argument':'diagnostic_arguments'));
  assert.equal(s.entry,'0062ed70');assert.equal(s.lookup_global,0);assert.equal(s.record_argument,l.returned_record);assert.equal(s.function_returned,false);
  if(nonnull){
   assert.equal(s.stop,'00946214');assert.equal(s.unsupported_argument,0);
   assert.equal(s.stop_reason,'before 00946214 -> 0094bef1 with exit-list base 00de4638=0');
   assert.deepEqual(s.calls,[['0062edfc','0062c680'],['0062c6c8','0054a110'],['0062c6d2','0094627a'],['0094627e','0094620d']]);
   assert.deepEqual(s.call_frames.map(f=>f.arguments),[[staff],[],[0x62ce20],[0x62ce20]]);
  }else{
   assert.equal(s.stop,'0062ed99');assert.deepEqual(s.calls,[]);
   assert.equal(s.stop_reason,'before 0062ed99 -> 00944cff; null record diagnostic preserved');
   assert.deepEqual(s.diagnostic_arguments,[0x9e7f28,0,0,0x307f00,0x307e00]);
  }
  steps+=l.instruction_steps+s.instruction_steps;
 }
 for(const [n,s] of o.constructor_frontiers.entries()){
  stage(s,'mode seed receiver entry_argument arguments stop_reason function_returned lookup_global');
  const seed=n%4,mode=n<4?'new':'load_argument';
  assert.deepEqual([s.mode,s.seed,s.receiver,s.entry_argument],[mode,seed,0x290000+seed*0x40,mode==='new'?0:0x2a0000+seed*0x100]);
  assert.equal(s.entry,'0062a680');assert.equal(s.stop,'0062a6b1');assert.deepEqual(s.calls,[]);
  assert.deepEqual(s.arguments,[200,0x307984]);assert.equal(s.lookup_global,0);assert.equal(s.function_returned,false);
  assert.equal(s.stop_reason,'before IAT009670f8 GetLogicalDriveStringsA; unresolved on-disk imports never called');
  steps+=s.instruction_steps;
 }
 assert.equal(steps,coverage.instruction_steps);
}

export function checkRetained(raw,receiptRaw){
 assert.equal(hash(raw),ORACLE_HASH,'oracle hash');assert.equal(hash(receiptRaw),RECEIPT_HASH,'receipt hash');
 const expanded=gunzipSync(raw,{maxOutputLength:2000000});const value=JSON.parse(expanded),receipt=JSON.parse(receiptRaw);
 keys(value,'sites oracle');checkOracle(value.oracle);
 const s=value.sites;keys(s,'unit baseline_commit specimen_sha256 manifest_sha256 source_archive_sha256 export_hashes ranges zero_tail_globals constructor_imports scope');
 assert.equal(s.unit,'R31-B');assert.equal(s.baseline_commit,'36b44d8701b6abe332bc5a112198a570a8946536');assert.equal(s.specimen_sha256,SPECIMEN);
 assert.deepEqual(s.manifest_sha256,{state:'b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a',
  staff:'c6457fcd1b68d524d2d4ce623d144e77a3e5ae23c9a4699e157b9ec2181f7b35',
  focused:'27093fe32f6bcf31c94cb78c108eb78b025713c14215cc3602daeb2db57aad68',
  support:'92d0708d6eada4983366d522314881e04c293b0bfaab4c467eb08f71992d7741'});
 const oldArchive='ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a';
 const newArchive='f787a4dd87cb0efc9d7b270f8be0656e49d0f5f64738f1d19aab759540936bdd';
 assert.deepEqual(s.source_archive_sha256,{state:oldArchive,staff:oldArchive,focused:newArchive,support:newArchive});
 const groups={state:['006eaea0','006e0d00','006dbb80','0062a680','0062a8a0','00828110','0082a9c0','0082ff40'],
  staff:['008968f0','008982b0'],focused:['00600a50','005409b0','0053b900','0053b3d0','0062c680'],support:['0054a110','0094627a','0094620d']};
 const exportNames=Object.entries(groups).flatMap(([group,names])=>names.flatMap(name=>[`${group}/${name}.asm`,`${group}/${name}.c`]));
 keys(s.export_hashes,[...exportNames,'exports25/0062ed70.asm'].join(' '));Object.values(s.export_hashes).forEach(v=>hex(v,64));
 assert.equal(s.ranges.length,13);let instructions=0;
 for(const r of s.ranges){keys(r,'entry end_exclusive file_offset bytes sha256 instructions all_native_operands_match');
  for(const name of ['entry','end_exclusive','file_offset'])hex(r[name]);hex(r.sha256,64);uint(r.instructions);uint(r.bytes);
  assert.equal(parseInt(r.end_exclusive,16)-parseInt(r.entry,16),r.bytes);assert.equal(parseInt(r.entry,16)-parseInt(r.file_offset,16),0x400000);
  assert.equal(r.all_native_operands_match,true);instructions+=r.instructions;
 }
 assert.equal(instructions,729);
 assert.equal(s.scope,'bounded lookup and initialization frontiers; no new whole-body register, live database or match claim');
 assert.deepEqual(s.zero_tail_globals,Object.fromEntries(['00b63d28','00b63d10','00de4634','00de4638'].map(va=>[va,{loader_zero:true,game_initializer_executed:false}])));
 assert.deepEqual(s.constructor_imports,{'009670f8':{dll:'KERNEL32.dll',symbol:'GetLogicalDriveStringsA'},'00967100':{dll:'KERNEL32.dll',symbol:'GetDriveTypeA'}});
 keys(receipt,'unit status specimen_sha256 evidence_sha256 expanded_canonical_sha256 compressed_bytes expanded_canonical_bytes normal_optimized_evidence compared_instructions coverage negative_probes privacy limits');
 assert.equal(receipt.unit,'R31-B');assert.equal(receipt.status,'passed');assert.equal(receipt.specimen_sha256,SPECIMEN);
 assert.equal(receipt.evidence_sha256,hash(raw));assert.equal(receipt.expanded_canonical_sha256,hash(expanded));
 assert.equal(receipt.compressed_bytes,raw.length);assert.equal(receipt.expanded_canonical_bytes,expanded.length);
 assert.equal(receipt.normal_optimized_evidence,'byte-identical original-instruction regeneration');assert.equal(receipt.compared_instructions,instructions);
 assert.deepEqual(receipt.coverage,coverage);assert.deepEqual(receipt.negative_probes,negatives);
 assert.equal(receipt.privacy,'compressed and bounded expanded bytes scanned for original code/source in raw, hex and base64; no original pages retained');
 assert.equal(receipt.limits,'synthetic function-entry fixture kernels; no game caller, loaded database, lookup-object initialization or normal effect return');
 const changed=structuredClone(value.oracle);changed.cases[0].lookup.returned_record^=1;
 assert.throws(()=>checkOracle(changed),/lookup result/);
 const swapped=structuredClone(value.oracle),args=swapped.cases[0].placement.call_frames[0].arguments;
 [args[2],args[4]]=[args[4],args[2]];assert.throws(()=>checkOracle(swapped),/placement call provenance/);
 return {unit:'R31-B',status:'passed',node:process.version,compared_instructions:instructions,...coverage,
  scope:'retained synthetic fixture kernels and explicit frontiers; no fresh emulation or live state claim'};
}

if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url){
 const root=new URL('../',import.meta.url);
 console.log(JSON.stringify(checkRetained(readFileSync(new URL('evidence/action33-lifecycle-31-oracle.bin',root)),
  readFileSync(new URL('evidence/action33-lifecycle-31-validation.json',root)))));
}

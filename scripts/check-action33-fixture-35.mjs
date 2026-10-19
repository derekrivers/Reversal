#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';
const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='85625c272b1c8383805a8a1169ab2e4fc5eb12f541a5ac370ae06774b906a53a';
const RECEIPT_HASH='e2980862e4e32669da3a214a48da7a810a47b0c467b1ff22ae6488c87aad52fe';
const SCOPE='original selector entry to pending HeapSize import; no selection, RNG, fixture or prepare-match execution';
const hash=b=>createHash('sha256').update(b).digest('hex');
const keys=(o,s)=>assert.deepEqual(Object.keys(o).sort(),s.split(' ').sort());
const hex=(s,n=8)=>assert.match(s,new RegExp(`^[0-9a-f]{${n}}$`));
const uint=n=>assert.ok(Number.isInteger(n)&&n>=0&&n<=0xffffffff);
const hx=n=>n.toString(16).padStart(8,'0');
const coverage={selector_entries:8,caller_interior_windows:4,produced_date_initializers:320,instruction_steps:8520};

export function checkOracle(o){
 keys(o,'unit scope specimen_sha256 synthetic_harness cases coverage');
 assert.deepEqual([o.unit,o.scope,o.specimen_sha256,o.synthetic_harness],['R35-C',SCOPE,SPECIMEN,true]);
 assert.deepEqual(o.coverage,coverage);assert.equal(o.cases.length,8);let total=0;
 for(const [n,c] of o.cases.entries()){
  keys(c,'seed entry selector_function_entry_executed caller_interior_window receiver stop instruction_steps trace_sha256 events_sha256 memory_events call_frames produced_date_addresses date_writes static_flag receiver_global next_call before_memory_sha256 after_memory_sha256 final_registers rng_calls fixture_produced function_returned');
  const interior=n%2===1;
  assert.deepEqual([c.seed,c.entry,c.selector_function_entry_executed,c.caller_interior_window,c.receiver,c.stop],
   [Math.floor(n/2),interior?'005cdac3':'0084be20',true,interior,0,'0094bf49']);
  assert.deepEqual([c.instruction_steps,c.static_flag,c.receiver_global,c.rng_calls,c.fixture_produced,c.function_returned],
   [interior?1066:1064,1,0,0,false,false]);total+=c.instruction_steps;
  hex(c.trace_sha256,64);hex(c.events_sha256,64);uint(c.memory_events);
  const dates=[],calls=[];
  if(interior)calls.push(['005cdac9','0084be20']);
  calls.push(['0084be6f','009463af']);
  for(let object=0;object<2;object++){
   calls.push(['009463ea','00453c30'],['00453c45','009463af']);
   for(let index=0;index<20;index++){
    dates.push(0xdd7287+object*0x625+0x71+index*0x49+0x14);
    calls.push(['009463ea','00453c50'],['00453c56','0054a110']);
   }
   calls.push(['00946403','00946419']);
  }
  calls.push(['00946403','00946419'],['0084be79','0094627a'],['0094627e','0094620d'],['00946214','0094bef1']);
  assert.deepEqual(c.produced_date_addresses,dates,'produced date sequence');
  assert.deepEqual(c.date_writes,dates.flatMap(address=>[
   ['0054a112','write',hx(address),2],['0054a117','write',hx(address+2),2],['0054a11d','write',hx(address+4),4]]),'ordered date write widths');
  assert.deepEqual(c.call_frames.map(f=>[f.site,f.target]),calls,'original ordered calls');
  for(const f of c.call_frames){keys(f,'site target ecx arguments');uint(f.ecx);f.arguments.forEach(uint);}
  const outer=c.call_frames.find(f=>f.site==='0084be6f');
  assert.deepEqual(outer.arguments,[0xdd7287,0x625,2,0x453c30,0x453c10]);
  assert.deepEqual(c.call_frames.filter(f=>f.site==='00453c45').map(f=>f.arguments),[0,1].map(i=>[0xdd7287+i*0x625+0x71,0x49,20,0x453c50,0x5a53c0]));
  assert.deepEqual(c.call_frames.filter(f=>f.target==='00453c50').map(f=>f.ecx+0x14),dates);
  assert.deepEqual(c.call_frames.filter(f=>f.target==='0054a110').map(f=>f.ecx),dates);
  assert.deepEqual(c.call_frames.slice(-3).map(f=>f.arguments),[[0x84c500],[0x84c500],[0]]);
  assert.deepEqual(c.next_call,{site:'0094bf49',iat:'009670dc',dll:'KERNEL32.dll',symbol:'HeapSize',arguments:[0,0,0],executed:false},'heap boundary');
  for(const name of ['before_memory_sha256','after_memory_sha256']){
   keys(c[name],'stack seh selector_globals crt_globals');Object.values(c[name]).forEach(v=>hex(v,64));
  }
  assert.equal(c.before_memory_sha256.crt_globals,c.after_memory_sha256.crt_globals);
  keys(c.final_registers,'eax ebx ecx edx esi edi ebp esp eip');Object.values(c.final_registers).forEach(uint);
  assert.equal(c.final_registers.eip,0x94bf49);
 }
 assert.equal(total,8520);
}

export function checkRetained(raw,receiptRaw){
 assert.equal(hash(raw),ORACLE_HASH,'oracle hash');
 assert.equal(hash(receiptRaw),RECEIPT_HASH,'receipt hash');
 const v=JSON.parse(gunzipSync(raw,{maxOutputLength:2000000})),r=JSON.parse(receiptRaw);
 keys(v,'sites oracle');checkOracle(v.oracle);
 const s=v.sites;keys(s,'unit baseline_commit specimen_sha256 scope manifest_sha256 export_hashes ranges direct_caller zero_tail_globals heap_import');
 assert.deepEqual([s.unit,s.baseline_commit,s.specimen_sha256,s.scope],['R35-C','eabc39b443d18ca59c88c211c65b5ea5d089ed52',SPECIMEN,SCOPE]);
 assert.equal(s.ranges.length,14);let native=0,pe=0;
 for(const x of s.ranges){
  keys(x,'entry end_exclusive file_offset bytes sha256 instructions validation');
  for(const name of ['entry','end_exclusive','file_offset'])hex(x[name]);hex(x.sha256,64);
  assert.equal(parseInt(x.end_exclusive,16)-parseInt(x.entry,16),x.bytes);uint(x.instructions);
  if(x.validation==='PE/native operands')native+=x.instructions;
  else{assert.equal(x.validation,'pinned PE decoding only');pe+=x.instructions;}
 }
 assert.equal(native+pe,669);assert.equal(pe,79);
 assert.deepEqual(s.direct_caller,{site:'005cdac9',parent:'005cccd0',receiver_load:'005cdac3',global:'00dd7ee4'});
 assert.deepEqual(s.zero_tail_globals,['00dd7160','00dd7287','00dd7ee4','00de4400','00de4404','00de4634','00de4638']);
 assert.deepEqual(s.heap_import,{iat:'009670dc',dll:'KERNEL32.dll',symbol:'HeapSize'});
 assert.equal(r.unit,'R35-C');assert.equal(r.status,'passed');assert.equal(r.specimen_sha256,SPECIMEN);
 assert.equal(r.evidence_sha256,hash(raw));assert.equal(r.expanded_canonical_sha256,hash(gunzipSync(raw)));
 assert.deepEqual(r.coverage,coverage);assert.equal(r.native_operand_instructions,native);assert.equal(r.pe_only_instructions,pe);
 assert.equal(r.normal_optimized_evidence,'byte-identical original-instruction regeneration');assert.equal(r.negative_probes.length,13);
 assert.ok(r.negative_probes.every(p=>p.endsWith(' rejected')));assert.equal(r.limits,SCOPE);
 return v;
}

function main(){
 const raw=readFileSync(new URL('../evidence/action33-fixture-35-oracle.bin',import.meta.url));
 const receipt=readFileSync(new URL('../evidence/action33-fixture-35-validation.json',import.meta.url));
 const v=checkRetained(raw,receipt);
 const wrong=structuredClone(v.oracle);wrong.cases[0].produced_date_addresses[0]++;
 assert.throws(()=>checkOracle(wrong),/produced date sequence/);
 const width=structuredClone(v.oracle);width.cases[0].date_writes[0][3]=4;
 assert.throws(()=>checkOracle(width),/ordered date write widths/);
 console.log('R35-C retained selector initialization: 8 entries, 320 date initializers, 8520 original instructions; integrity and semantic mutations passed');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main();

#!/usr/bin/env node
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {strict as assert} from 'node:assert';
import {pathToFileURL} from 'node:url';
const SPECIMEN='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const ORACLE_HASH='3054ec34f543a3534c0a0ca12e6e42828ec299d15eace19483fddef7afd11841';
const RECEIPT_HASH='33d5b9a1d2a1dd84a8215125e85d2b585ae1f09df96bd163be86a64aaa3daccc';
const SCOPE='separate constructor entries, original flag-store window and caller allocation interiors; no initialized receiver, rows or selector join';
const hash=b=>createHash('sha256').update(b).digest('hex');
const keys=(o,s)=>assert.deepEqual(Object.keys(o).sort(),s.split(' ').sort());
const hex=(s,n=8)=>assert.match(s,new RegExp(`^[0-9a-f]{${n}}$`));
const uint=n=>assert.ok(Number.isInteger(n)&&n>=0&&n<=0xffffffff);
const coverage={constructor_drive_entries:16,caller_allocation_interiors:24,flag_store_windows:8,
 separate_flagged_constructor_entries:8,receiver_returns:0,row_writes:0,instruction_steps:1168};
const regions='receiver stack database_globals selector_globals crt_globals';
const common='entry stop instruction_steps trace_sha256 events_sha256 memory_events call_frames final_registers before_memory_sha256 after_memory_sha256';

function stage(s,seed,flag,producer=false){
 keys(s,common+(producer?'':' next_call receiver_global flag_value constructor_returned receiver_written'));
 hex(s.entry);hex(s.stop);hex(s.trace_sha256,64);hex(s.events_sha256,64);uint(s.instruction_steps);
 keys(s.final_registers,'eax ebx ecx edx esi edi ebp esp eip');Object.values(s.final_registers).forEach(uint);
 assert.equal(s.final_registers.eip,parseInt(s.stop,16));
 for(const name of ['before_memory_sha256','after_memory_sha256']){keys(s[name],regions);Object.values(s[name]).forEach(v=>hex(v,64));}
 const selectorBefore=Buffer.alloc(0x2000),selectorAfter=Buffer.alloc(0x2000);
 if(flag&&!producer)selectorBefore.writeUInt32LE(1,0x118);
 if(flag)selectorAfter.writeUInt32LE(1,0x118);
 assert.equal(s.before_memory_sha256.selector_globals,hash(selectorBefore));
 assert.equal(s.after_memory_sha256.selector_globals,hash(selectorAfter),'complete selector globals');
 const receiver=Buffer.from(Array.from({length:0x1000},(_,k)=>(k*13+seed*17)&255));
 for(const name of ['before_memory_sha256','after_memory_sha256']){
  assert.equal(s[name].receiver,hash(receiver));assert.equal(s[name].database_globals,hash(Buffer.alloc(0x1000)));
  assert.equal(s[name].crt_globals,hash(Buffer.alloc(0x2000)));
 }
 for(const e of s.memory_events){assert.equal(e.length,4);hex(e[0]);assert.ok(['read','write'].includes(e[1]));hex(e[2]);uint(e[3]);}
 for(const f of s.call_frames){keys(f,'site target ecx arguments');hex(f.site);hex(f.target);uint(f.ecx);f.arguments.forEach(uint);}
}

export function checkOracle(o){
 keys(o,'unit scope specimen_sha256 synthetic_harness cases coverage');
 assert.deepEqual([o.unit,o.scope,o.specimen_sha256,o.synthetic_harness],['R36-C',SCOPE,SPECIMEN,true]);
 assert.deepEqual(o.coverage,coverage);assert.equal(o.cases.length,48);let steps=0;
 for(const [n,c] of o.cases.entries()){
  keys(c,'seed kind constructor_argument flag_producer stage');
  const seed=Math.floor(n/6),variant=n%6,flag=variant===5,drive=variant<2;
  const entry=drive||flag?'0084b940':['00829dfc','0082cb18','005d5d58'][variant-2];
  assert.deepEqual([c.seed,c.kind,c.constructor_argument],[seed,drive?'constructor_drive':flag?'flag_then_constructor':'caller_allocation',drive?(variant===0?0:0x220000):flag?0:null]);
  const s=c.stage;stage(s,seed,flag);steps+=s.instruction_steps;
  assert.deepEqual([s.entry,s.stop,s.instruction_steps],[entry,drive?'0084b970':'00944ef0',[15,15,23,23,26,43][variant]]);
  assert.deepEqual([s.receiver_global,s.flag_value,s.constructor_returned,s.receiver_written],[0,flag?1:0,false,false]);
  assert.deepEqual(s.next_call,drive?{iat:'009670f8',symbol:'GetLogicalDriveStringsA',arguments:[200,0x308000-0x2e0],executed:false}:
   {iat:'00967154',symbol:'HeapAlloc',arguments:[0,0,16],executed:false},'outgoing OS call');
  if(drive)assert.deepEqual(s.call_frames,[]);
  else{
   const site=flag?'0084ba81':['00829dfe','0082cb1a','005d5d74'][variant-2],request=flag?0:8,ecx=flag?0:0x200000;
   assert.deepEqual(s.call_frames,[{site,target:flag?'00944e46':'00944cf1',ecx,arguments:[request]},
    {site:flag?'00944e50':'00944cf7',target:'00944e58',ecx,arguments:[request,flag?0:1]},
    {site:'00944e63',target:'00944e84',ecx,arguments:[request]}]);
  }
  if(flag){
   stage(c.flag_producer,seed,true,true);steps+=c.flag_producer.instruction_steps;
   assert.deepEqual([c.flag_producer.entry,c.flag_producer.stop,c.flag_producer.instruction_steps],['0081ba8d','0081ba97',1]);
   assert.deepEqual(c.flag_producer.memory_events,[['0081ba8d','write','00dd7118',4]],'original flag write');
   assert.deepEqual(c.flag_producer.call_frames,[]);
   assert.equal(c.flag_producer.after_memory_sha256.selector_globals,s.before_memory_sha256.selector_globals);
  }else assert.equal(c.flag_producer,null);
 }
 assert.equal(steps,1168);
}

export function checkRetained(raw,receiptRaw){
 assert.equal(hash(raw),ORACLE_HASH,'oracle hash');
 assert.equal(hash(receiptRaw),RECEIPT_HASH,'receipt hash');
 const v=JSON.parse(gunzipSync(raw,{maxOutputLength:2000000})),r=JSON.parse(receiptRaw);
 keys(v,'sites oracle');checkOracle(v.oracle);const s=v.sites;
 keys(s,'unit baseline_commit specimen_sha256 scope manifest_sha256 native_sources export_hashes ranges imports zero_tail_globals');
 assert.deepEqual([s.unit,s.baseline_commit,s.specimen_sha256,s.scope],['R36-C','7cd9b45c567654aac3aca99080dea80d03652785',SPECIMEN,SCOPE]);
 assert.equal(s.manifest_sha256.native,'2191fbb3b4e60caf51ab80f614588ecd478aab6220f9de0ddd3bbabc02d1612d');
 assert.equal(s.manifest_sha256.state,'b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a');
 assert.equal(s.ranges.length,12);let native=0,pe=0;
 for(const x of s.ranges){
  keys(x,'entry end_exclusive file_offset bytes sha256 instructions validation');
  for(const name of ['entry','end_exclusive','file_offset'])hex(x[name]);hex(x.sha256,64);
  assert.equal(parseInt(x.end_exclusive,16)-parseInt(x.entry,16),x.bytes);uint(x.instructions);
  if(x.validation==='PE/native operands')native+=x.instructions;
  else{assert.equal(x.validation,'pinned PE decoding only');pe+=x.instructions;}
 }
 assert.deepEqual([native,pe],[535,95]);
 assert.deepEqual(s.imports,{'009670f8':{dll:'KERNEL32.dll',symbol:'GetLogicalDriveStringsA'},
  '00967100':{dll:'KERNEL32.dll',symbol:'GetDriveTypeA'},'00967154':{dll:'KERNEL32.dll',symbol:'HeapAlloc'}});
 assert.deepEqual(s.zero_tail_globals,['00ae235c','00dd7118','00dd7ee4','00de3008','00de4400','00de4404']);
 assert.equal(r.unit,'R36-C');assert.equal(r.status,'passed');assert.equal(r.specimen_sha256,SPECIMEN);
 assert.equal(r.evidence_sha256,hash(raw));assert.equal(r.expanded_canonical_sha256,hash(gunzipSync(raw)));
 assert.deepEqual(r.coverage,coverage);assert.deepEqual([r.native_operand_instructions,r.pe_only_instructions],[native,pe]);
 assert.equal(r.normal_optimized_evidence,'byte-identical original-instruction regeneration');assert.equal(r.negative_probes.length,17);
 keys(r.source_literal,'address bytes sha256');assert.equal(r.source_literal.address,'00a8278c');
 assert.ok(r.source_literal.bytes>=16);hex(r.source_literal.sha256,64);
 for(const probe of ['raw constructor source in container','plain JSON constructor source in expanded evidence',
  'hex constructor source in expanded evidence','base64 constructor source in expanded evidence'])assert.ok(r.negative_probes.includes(probe+' rejected'));
 assert.ok(r.negative_probes.every(p=>p.endsWith(' rejected')));assert.equal(r.limits,SCOPE);
 return v;
}

function main(){
 const raw=readFileSync(new URL('../evidence/action33-selector-state-36-oracle.bin',import.meta.url));
 const receipt=readFileSync(new URL('../evidence/action33-selector-state-36-validation.json',import.meta.url));
 const v=checkRetained(raw,receipt);
 const wrong=structuredClone(v.oracle);wrong.cases[2].stage.next_call.arguments[2]=8;
 assert.throws(()=>checkOracle(wrong),/outgoing OS call/);
 const width=structuredClone(v.oracle);width.cases[5].flag_producer.memory_events[0][3]=1;
 assert.throws(()=>checkOracle(width),/original flag write/);
 console.log('R36-C: 48 separate cases, 1168 original instructions, zero receiver/row writes; integrity and semantic mutations passed');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main();

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33AdjustmentPrefix34} from './action33-adjustment-34.ts';
const root=new URL('../',import.meta.url),hash=(b:Uint8Array)=>createHash('sha256').update(b).digest('hex');
const MATCH=0x4100000,POSITIONS=0x4300000,STACK=0x2000000,SP=STACK+0x8000,TABLE=0xaa2454,GRID=0xa15e44,BASES=[0x4796,0x6a6e];
const prefixBytes=readFileSync(new URL('evidence/action33-prefix-30-oracle.bin',root));
assert.equal(hash(prefixBytes),'08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f');
const prefix=JSON.parse(gunzipSync(prefixBytes));
const randomTable=readFileSync(new URL('evidence/random-validation/random-table.bin',root));
assert.equal(hash(randomTable),'befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db');
class Memory{
 regions:Record<string,{base:number;bytes:Buffer}>={match:{base:MATCH,bytes:Buffer.alloc(65536)},positions:{base:POSITIONS,bytes:Buffer.alloc(4096)},
  stack:{base:STACK,bytes:Buffer.alloc(65536)},random_table:{base:TABLE,bytes:Buffer.from(randomTable)},grid:{base:GRID,bytes:Buffer.alloc(432)}};
 locate(a:number,size:number):[Buffer,number]{for(const r of Object.values(this.regions))if(a>=r.base&&a+size<=r.base+r.bytes.length)return [r.bytes,a-r.base];throw new RangeError('unmapped grid prefix access');}
 read(a:number,size:number){const [b,o]=this.locate(a,size);return b.readUIntLE(o,size);}
 write(a:number,size:number,v:number){const [b,o]=this.locate(a,size);b.writeUIntLE(size===1?v&255:size===2?v&65535:v>>>0,o,size);}
 seed(c:any,task:any){
  for(const [address,size,value] of [[0x96d810,8,1680],[0x96d754,4,9],[0x968e18,8,2.5],[0x967890,8,1]]){const bytes=Buffer.alloc(size);if(size===8)bytes.writeDoubleLE(value);else bytes.writeFloatLE(value);this.regions[address.toString(16).padStart(8,'0')]={base:address,bytes};}
  const w=(o:number,size:number,v:number)=>this.write(MATCH+o,size,v),m=this.regions.match.bytes;
  for(let side=0;side<2;side++){
   for(let k=0;k<20;k++){const q=BASES[side]+k*0x1be;m[q+0x19]=m[q+0x1a]=255;m[q+0x27]=side;w(q+0x19e,4,MATCH);}
   const q=BASES[side];m[q+0x19]=0;m[q+0x102]=4;m[q+0x103]=side===0?11:0;m[q+0xf]=c.counter_raw;m[q+0x2b]=c.selector_mode==='activity-reject'?2:0;
   w(q+0x168,2,c.rating0_raw);w(q+0x16a,2,c.rating1_raw);w(q+0x3b,2,c.fallback_rating_raw);m.writeFloatLE(c.adjustment_float,q+0xd1);
   w(0x8ebc+4*side,4,POSITIONS+side*0x100);this.write(POSITIONS+side*0x100,2,c.selector_mode==='fallback'?0:1);
   let cache=['cache','activity-reject'].includes(c.selector_mode)?MATCH+q:0;if(c.selector_mode==='invalidate')cache=MATCH+q+19*0x1be;w(0xf59e+4*side,4,cache);
  }
  const shooter=BASES[c.side]+3*0x1be;m[shooter+0x19]=3;m[shooter+0x102]=c.x;m[shooter+0x103]=c.y;w(shooter+0x39,2,0xfff1);
  w(shooter+0x198,2,0x33);w(0x8ed0,2,c.clock_word);w(0x4782,4,12345);w(0x4786,4,c.momentum);
  m[0x8ea7]=c.x;m[0x8ea8]=c.y;m[0x8eaa]=c.match_byte_raw;m[0x8ea9]=c.state_byte;
  [0x3000000,0x33,c.quality,0x1f7f,3,0,0].forEach((v,i)=>this.write(SP+i*4,4,v));
  for(let i=0;i<108;i++)this.regions.grid.bytes.writeFloatLE(Math.hypot(i%9,Math.floor(i/9)),i*4);
  if(task.mode==='comparison')w(0x4786,4,task.momentum);
  else if(task.mode!=='baseline'){
   const side=1-c.side,base=MATCH+BASES[side];
   for(let k=0;k<20;k++){
    const active=task.mode==='all-active'||task.mode==='late-active'&&k===19||task.mode==='index-127'&&k===0||task.mode==='flag-set'&&k===task.index;
    const index=task.mode==='index-127'?127:k;this.write(base+k*0x1be+0x19,1,active?index:255);
    if(active)this.write(MATCH+0x91e2+0x18e3*side+0x5b4+index,1,task.flag);
   }
  }
 }
}

const blob=readFileSync(new URL('evidence/action33-adjustment-34-oracle.bin',root));
assert.equal(hash(blob),'b18307489d5adeaa2026ad17f214404b5ac43a400bcecfd0fab6665713511e30');
const oracle=JSON.parse(gunzipSync(blob,{maxOutputLength:12000000}));
assert.equal(oracle.unit,'R34-A');
assert.equal(oracle.sites.specimen_sha256,prefix.specimen_sha256);
assert.equal(oracle.sites.next_call.join(' -> '),'00702241 -> 0090cfc0');
const receiptBytes=readFileSync(new URL('evidence/action33-adjustment-34-integrity.json',root));
assert.equal(hash(receiptBytes),'780965e19ffd240e8fc3b5daf720a30e5e57f16c368c4d68ecf4ac6ae1c51d1f');
const receipt=JSON.parse(receiptBytes);
assert.equal(receipt.unit,'R34-A');assert.equal(receipt.status,'passed');assert.equal(receipt.oracle_sha256,hash(blob));
assert.deepEqual(receipt.coverage,oracle.coverage);assert.equal(Object.keys(receipt.negative_checks).length,12);
assert.equal(receipt.negative_checks.corrupt_actual_output_word,'helper contract mismatch');
const priorBlob=readFileSync(new URL('evidence/action33-conversion-33-oracle.bin',root));
const prior=JSON.parse(gunzipSync(priorBlob,{maxOutputLength:12000000}));
let steps=0,events=0;
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);assert.equal(row.stop,'00702241');
 const memory=new Memory(),input=prefix.cases[row.case.source_case].input;
 memory.seed(input,'distance' in row.case?{...row.case,mode:'baseline'}:row.case);
 if('distance' in row.case)for(let k=0;k<108;k++)memory.regions.grid.bytes.writeFloatLE(row.case.distance,k*4);
 const m=new GridMachine31(row.before,memory);
 assert.equal(runAction33AdjustmentPrefix34(m),0x702241);
 assert.deepEqual(m.state,row.after,`full represented state ${n}`);
 assert.deepEqual(m.trace,row.instruction_trace,`instruction trace ${n}`);
 assert.deepEqual(m.events,row.events,`ordered memory events ${n}`);
 assert.deepEqual(m.calls,row.calls,`call/return ABI ${n}`);
 for(const [name,{bytes}] of Object.entries(memory.regions))assert.equal(hash(bytes),row.memory_sha256[name],`region ${name} ${n}`);
 assert.deepEqual(m.state.rng,row.before.rng);assert.deepEqual(m.state.rng_cells,row.before.rng_cells);
 const old=prior.cases.find((r:any)=>JSON.stringify(r.case)===JSON.stringify(row.case));
 assert.ok(old,`R33-A prior case ${n}`);
 assert.deepEqual(row.checkpoint.state,old.after,`original R33-A state ${n}`);
 assert.deepEqual(row.instruction_trace.slice(0,row.checkpoint.trace_length),old.instruction_trace,`original R33-A trace ${n}`);
 assert.deepEqual(row.events.slice(0,row.checkpoint.event_length),old.events,`original R33-A events ${n}`);
 assert.deepEqual(row.calls.slice(0,row.checkpoint.call_length),old.calls,`original R33-A calls ${n}`);
 for(const [name,digest] of Object.entries(row.checkpoint.memory_sha256))assert.equal(digest,old.memory_sha256[name],`R33-A region ${name} ${n}`);
 steps+=row.instruction_trace.length;events+=row.events.length;
}
assert.deepEqual(oracle.coverage,{cases:oracle.cases.length,instructions:steps,events,rng_calls:0});
assert.equal(oracle.cases.length,232);
console.log(JSON.stringify({unit:'R34-A',status:'passed',node:process.version,...oracle.coverage,
 scope:'original-entry action33 helper and caller to pre-00702241; no RNG or 007022fd join'}));

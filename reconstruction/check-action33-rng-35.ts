import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33AdjustmentPrefix34} from './action33-adjustment-34.ts';
import {runAction33RngPrefix35,runAction33RngSuffix35} from './action33-rng-35.ts';
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

const blob=readFileSync(new URL('evidence/action33-rng-35-oracle.bin',root));
assert.equal(hash(blob),'edb057f22e3b5eec75ca0583a03f0b1c291e2ec96403cbf7efb61bf8d31f3a32');
assert.equal(blob.subarray(0,10).toString('hex'),'1f8b08000000000002ff');
const oracle=JSON.parse(gunzipSync(blob,{maxOutputLength:12000000}));
assert.equal(oracle.unit,'R35-A');assert.equal(oracle.sites.specimen_sha256,prefix.specimen_sha256);
assert.deepEqual(oracle.sites.next_call,['0070230c','006ce110']);
for(const [name,digest] of Object.entries(oracle.sites.dependency_hashes))assert.equal(hash(readFileSync(new URL(name,root))),digest,`dependency ${name}`);
const prior=JSON.parse(gunzipSync(readFileSync(new URL('evidence/action33-adjustment-34-oracle.bin',root)),{maxOutputLength:12000000}));
const composition=JSON.parse(gunzipSync(readFileSync(new URL('evidence/action33-composition-30-oracle.bin',root))));
function prepare(row:any){
 const memory=new Memory(),input=prefix.cases[row.case.source_case].input;
 memory.seed(input,'distance' in row.case?{...row.case,mode:'baseline'}:row.case);
 if('distance' in row.case)for(let k=0;k<108;k++)memory.regions.grid.bytes.writeFloatLE(row.case.distance,k*4);
 return {memory,m:new GridMachine31(row.before,memory)};
}
function digests(memory:Memory){return Object.fromEntries(Object.entries(memory.regions).map(([name,{bytes}])=>[name,hash(bytes)]));}
function capture(m:GridMachine31,memory:Memory){return {state:m.snapshot(),trace_length:m.trace.length,event_length:m.events.length,call_length:m.calls.length,memory_sha256:digests(memory)};}
let steps=0,events=0,suffixCount=0,projections=0;
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);assert.equal(row.stop,'0070230c');
 const {memory,m}=prepare(row),suffixStates:any[]=[];
 let checkpoint:any=null,join:any=null,projection:any=null;
 const at=m.at.bind(m);
 m.at=(pc:number)=>{
  if(pc===0x702241)checkpoint=capture(m,memory);
  if(pc===0x7022fd){
   join=capture(m,memory);
   if(row.case.mode==='baseline'){
    const frame=m.r.esp;
    projection={input:{match:m.r.eax,shooter:m.r.esi,action:memory.read(frame+0x698,1),mode:memory.read(frame+0x6a4,1),
     zeroLocalByte:memory.read(frame+0x30,1),marker260:memory.read(frame+0x19,1),marker375:memory.read(frame+0x1a,1),
     precisionBits:m.state.fpcw===0x27f?53:64},rng:{...m.state.rng},match_sha256:hash(memory.regions.match.bytes),positions_sha256:hash(memory.regions.positions.bytes)};
    const expected=composition.cases[row.case.source_case].checkpoint;
    for(const [key,value] of Object.entries(projection))assert.deepEqual(value,expected[key],`R30-C projection ${key} ${n}`);
   }
  }
  if(checkpoint!==null)suffixStates.push({pc:pc.toString(16).padStart(8,'0'),state:m.snapshot()});
  at(pc);
 };
 assert.equal(runAction33RngPrefix35(m),0x70230c);
 assert.deepEqual(checkpoint,row.checkpoint,`R34-A actual TS checkpoint ${n}`);
 assert.deepEqual(join,row.join_checkpoint,`actual 007022fd checkpoint ${n}`);
 assert.deepEqual(projection,row.projection,`semantic projection ${n}`);
 assert.deepEqual(m.state,row.after,`full represented state ${n}`);
 assert.deepEqual(suffixStates,row.suffix_states,`every suffix instruction state ${n}`);
 assert.deepEqual(m.trace,row.instruction_trace,`instruction trace ${n}`);
 assert.deepEqual(m.events,row.events,`ordered memory events ${n}`);
 assert.deepEqual(m.calls,row.calls,`call/return ABI ${n}`);
 assert.deepEqual(digests(memory),row.memory_sha256,`all mapped regions ${n}`);
 assert.equal(memory.read(m.r.esp,4),row.selector_argument_dword);
 assert.deepEqual(m.state.rng,row.before.rng);assert.deepEqual(m.state.rng_cells,row.before.rng_cells);
 const call=m.calls.at(-1) as any;
 assert.deepEqual([{site:call.site,bound:call.arguments[0],value:call.after.registers.eax,before:call.before.rng,after:call.after.rng,
  cells_before:call.before.rng_cells,cells_after:call.after.rng_cells}],row.rng,`ordered RNG ${n}`);
 const old=prior.cases.find((r:any)=>JSON.stringify(r.case)===JSON.stringify(row.case));assert.ok(old);
 assert.deepEqual(checkpoint.state,old.after);assert.deepEqual(checkpoint.memory_sha256,old.memory_sha256);
 assert.deepEqual(m.trace.slice(0,checkpoint.trace_length),old.instruction_trace);
 assert.deepEqual(m.events.slice(0,checkpoint.event_length),old.events);
 assert.deepEqual(m.calls.slice(0,checkpoint.call_length),old.calls);
 if(projection!==null){
  const original=prefix.cases[row.case.source_case].call_trace.find((c:any)=>c.site==='0070230c');
  assert.deepEqual(m.r,original.before);assert.equal(m.state.fpcw,original.fpcw_before);
  assert.deepEqual([memory.read(m.r.esp,4)],original.args);projections++;
 }
 steps+=m.trace.length;events+=m.events.length;suffixCount+=suffixStates.length;
}
assert.deepEqual(oracle.coverage,{cases:232,instructions:steps,events,rng_calls:232,suffix_states:suffixCount,r30c_projections:160});
assert.equal(projections,160);
for(const mode of ['bound','contact']){
 const {memory,m}=prepare(oracle.cases[0]);assert.equal(runAction33AdjustmentPrefix34(m),0x702241);
 if(mode==='bound')memory.write(m.r.esp,4,1);else memory.write(MATCH+0xf5aa,4,m.r.esi);
 assert.throws(()=>runAction33RngSuffix35(m),mode==='bound'?/0090cfcf/:/0070226b/);
 assert.deepEqual(m.state.rng,oracle.cases[0].before.rng);
}
const receiptBytes=readFileSync(new URL('evidence/action33-rng-35-integrity.json',root));
assert.equal(hash(receiptBytes),'906125f8b2530e532bee168e3cb16ecd2b5015cc10a846c347d05744ccbae3fd');
const receipt=JSON.parse(receiptBytes);assert.equal(receipt.unit,'R35-A');assert.equal(receipt.status,'passed');
assert.equal(receipt.oracle_sha256,hash(blob));assert.deepEqual(receipt.coverage,oracle.coverage);
assert.equal(Object.keys(receipt.negative_checks).length,14);
console.log(JSON.stringify({unit:'R35-A',status:'passed',node:process.version,...oracle.coverage,
 scope:'original-entry machine-state prefix to pre-0070230c; 160 R30-C input projections, no full machine-state join'}));

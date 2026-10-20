import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31} from './action33-grid-31.ts';
import {nextBounded} from './bounded-random.ts';
import {runAction33SelectorPrefix36} from './action33-selector-36.ts';
import {runAction33VariantPrefix37,runAction33VariantSuffix37} from './action33-variant-37.ts';
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
  for(const [address,size,value] of [[0x70a5c5,1,4],[0x70a5a4,4,0x7023e1]]){const bytes=Buffer.alloc(size);bytes.writeUIntLE(value,0,size);this.regions[address.toString(16).padStart(8,'0')]={base:address,bytes};}
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

const blob=readFileSync(new URL('evidence/action33-variant-37-oracle.bin',root));
assert.equal(hash(blob),'e78aa4f325e9737245ea35b6078c113b9b60a599b2e0eace2c1738bd6160bf59');
assert.equal(blob.subarray(0,10).toString('hex'),'1f8b08000000000002ff');
const oracle=JSON.parse(gunzipSync(blob,{maxOutputLength:16000000}));
assert.equal(oracle.unit,'R37-B');assert.equal(oracle.sites.specimen_sha256,prefix.specimen_sha256);
assert.deepEqual(oracle.sites.next_calls,{'00702332':'00944cff','00702416':'00700420'});
assert.equal(oracle.sites.full_r30c_join,false);assert.equal(oracle.sites.first_machine_state_gap,'00702416 -> 00700420');
for(const [name,digest] of Object.entries(oracle.sites.dependency_hashes))assert.equal(hash(readFileSync(new URL(name,root))),digest,`dependency ${name}`);
const prior=JSON.parse(gunzipSync(readFileSync(new URL('evidence/action33-selector-36-oracle.bin',root)),{maxOutputLength:12000000}));
const composition=JSON.parse(gunzipSync(readFileSync(new URL('evidence/action33-composition-30-oracle.bin',root))));
const randomWords=Array.from({length:51000},(_,i)=>randomTable.readUInt32LE(i*4));
function prepare(row:any){
 const memory=new Memory(),input=prefix.cases[row.case.source_case].input;
 memory.seed(input,'distance' in row.case?{...row.case,mode:'baseline'}:row.case);
 if('distance' in row.case)for(let k=0;k<108;k++)memory.regions.grid.bytes.writeFloatLE(row.case.distance,k*4);
 for(const [name,value] of Object.entries(row.before.rng_cells)){const bytes=Buffer.alloc(4);bytes.writeUInt32LE(value as number);memory.regions[name]={base:parseInt(name,16),bytes};}
 return {memory,m:new GridMachine31(row.before,memory)};
}
function digests(memory:Memory,old=false){return Object.fromEntries(Object.entries(memory.regions).filter(([name])=>!old||!['00de1f60','00de1f5c','00de2798','00ad6c30'].includes(name)).map(([name,{bytes}])=>[name,hash(bytes)]));}
function compareFinal(m:GridMachine31,memory:Memory,row:any){
 assert.deepEqual(m.state,row.after,`full represented state ${row.id}`);
 assert.deepEqual(m.trace,row.instruction_trace,`instruction trace ${row.id}`);
 assert.deepEqual(m.events,row.events,`ordered memory ${row.id}`);
 assert.deepEqual(m.calls,row.calls,`call/return ABI ${row.id}`);
 assert.deepEqual(digests(memory),row.memory_sha256,`all mapped regions ${row.id}`);
}
let steps=0,events=0,suffixCount=0,nonnull=0,rngCalls=0,wraps=0,projections=0;
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);
 const {memory,m}=prepare(row),stateHash=createHash('sha256');
 let checkpoint:any=null,stateCount=0;
 const capture=()=>({state:m.snapshot(),trace_length:m.trace.length,event_length:m.events.length,call_length:m.calls.length,memory_sha256:digests(memory,true)});
 const at=m.at.bind(m);
 m.at=(pc:number)=>{
  if(pc===0x7023e3)checkpoint=capture();
  if(checkpoint!==null){stateHash.update(JSON.stringify({pc:pc.toString(16).padStart(8,'0'),state:m.snapshot()})+'\n');stateCount++;}
  at(pc);
 };
 const stop=runAction33VariantPrefix37(m);if(stop===0x702332)checkpoint=capture();
 assert.equal(stop.toString(16).padStart(8,'0'),row.stop);
 assert.deepEqual(checkpoint,row.checkpoint,`original-produced R36-A checkpoint ${n}`);
 compareFinal(m,memory,row);
 assert.equal(stateHash.digest('hex'),row.suffix_state_sha256,`every suffix instruction state ${n}`);assert.equal(stateCount,row.suffix_states);
 const rng=m.calls.filter((c:any)=>c.target==='0090cfc0') as any[];
 assert.deepEqual(rng,row.rng,`ordered RNG calls ${n}`);
 assert.deepEqual(Array.from({length:stop===0x702332?5:6},(_,i)=>memory.read(m.r.esp+4*i,4)),row.boundary.arguments);
 const selected=(m.calls.find((c:any)=>c.target==='006ce110') as any).after.registers.eax;assert.equal(selected,row.selected);
 const old=prior.cases.find((r:any)=>JSON.stringify(r.case)===JSON.stringify(row.case));assert.ok(old);
 assert.deepEqual(checkpoint.state,old.after);assert.deepEqual(checkpoint.memory_sha256,old.memory_sha256);
 assert.deepEqual(m.trace.slice(0,checkpoint.trace_length),old.instruction_trace);
 assert.deepEqual(m.events.slice(0,checkpoint.event_length),old.events);
 assert.deepEqual(m.calls.slice(0,checkpoint.call_length),old.calls);
 if(selected){
  const draw=rng[1];assert.equal(draw.site,'007023e3');assert.deepEqual(draw.arguments,[2]);
  const state={...draw.before.rng},value=nextBounded(2,state,randomWords);
  assert.deepEqual(draw.after.rng,state);assert.equal(draw.after.registers.eax,value);assert.equal(draw.after.registers.edx,value);
  assert.equal(m.r.ecx,selected);assert.equal(row.boundary.arguments[2]&255,value);
  for(const name of ['ebx','ecx','esi','edi','ebp','esp'])assert.equal(draw.after.registers[name],draw.before.registers[name]);
  if(row.case.mode==='baseline'){
   const projection={site:draw.site,bound:2,value,initial:draw.before.rng,final:draw.after.rng};
   assert.deepEqual(projection,row.r30c_variant_projection);assert.deepEqual(projection,composition.cases[row.case.source_case].draws[0]);projections++;
  }else assert.equal(row.r30c_variant_projection,null);
 }else{assert.equal(rng.length,1);assert.equal(row.r30c_variant_projection,null);assert.deepEqual(m.state.rng,row.before.rng);}
 steps+=m.trace.length;events+=m.events.length;suffixCount+=stateCount;nonnull+=Number(selected!==0);rngCalls+=rng.length;
 wraps+=m.calls.filter((c:any)=>c.target==='00946a04').length;
}
assert.deepEqual(oracle.coverage,{cases:232,keeper_boundaries:nonnull,diagnostic_boundaries:232-nonnull,instructions:steps,events,
 suffix_states:suffixCount,rng_calls:rngCalls,crt_wrap_calls:wraps,r30c_variant_projections:projections});
for(const mode of ['bound','limit','cells']){
 const {memory,m}=prepare(oracle.cases[0]);assert.equal(runAction33SelectorPrefix36(m),0x7023e3);
 if(mode==='bound')memory.write(m.r.esp,4,3);
 else if(mode==='limit'){memory.write(0xde2798,4,0xad4134);m.state.rng_cells['00de2798']=0xad4134;}
 else memory.write(0xde1f5c,4,1);
 assert.throws(()=>runAction33VariantSuffix37(m),mode==='bound'?/variant bound must be 2/:mode==='limit'?/unsupported variant RNG state/:/RNG memory\/state cells disagree/);
}
// Meaningful implementation mutations are executed on the same original-entry state.
for(const mode of ['draw','stack']){
 const row=oracle.cases[0],{memory,m}=prepare(row),at=m.at.bind(m);
 m.at=(pc:number)=>{if(pc===0x7023eb&&mode==='draw')m.r.eax^=1;if(pc===0x702414&&mode==='stack')memory.write(m.r.esp+4,4,0);at(pc);};
 runAction33VariantPrefix37(m);assert.throws(()=>compareFinal(m,memory,row),assert.AssertionError);
}
const receiptBytes=readFileSync(new URL('evidence/action33-variant-37-integrity.json',root));
assert.equal(hash(receiptBytes),'cb78e571bceb3dedb8877c25d4af1f2c82a05fa72c880379d43e784e8dadfbd5');
const receipt=JSON.parse(receiptBytes);assert.equal(receipt.unit,'R37-B');assert.equal(receipt.status,'passed');
assert.equal(receipt.oracle_sha256,hash(blob));assert.deepEqual(receipt.coverage,oracle.coverage);assert.equal(Object.keys(receipt.negative_checks).length,23);
console.log(JSON.stringify({unit:'R37-B',status:'passed',node:process.version,...oracle.coverage,
 scope:'original-entry prefix to pre-00702416 or pre-00702332; no keeper call, outcome or full R30-C machine-state join'}));

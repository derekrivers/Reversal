import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31} from './action33-grid-31.ts';
import {nextBounded} from './bounded-random.ts';
import {runAction33VariantPrefix37} from './action33-variant-37.ts';
import {runAction33KeeperPrefix38,runAction33KeeperSuffix38} from './action33-keeper-38.ts';
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
  for(const [address,size,value] of [[0x9688b0,8,10],[0x968950,8,2],[0x968e40,8,0.7],[0x968e80,8,0.3],[0x96d698,8,0.5714285714285714],[0x968ea8,8,20],[0x96d810,8,1680],[0x96d754,4,9],[0x968e18,8,2.5],[0x967890,8,1]]){const bytes=Buffer.alloc(size);if(size===8)bytes.writeDoubleLE(value);else bytes.writeFloatLE(value);this.regions[address.toString(16).padStart(8,'0')]={base:address,bytes};}
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

const blob=readFileSync(new URL('evidence/action33-keeper-38-oracle.bin',root));
assert.equal(hash(blob),'d5e9ed42bae44b49a0c21dc21b6e7e045f7eb724b2b2a3f9770eddecf703a53d');
assert.equal(blob.subarray(0,10).toString('hex'),'1f8b08000000000002ff');
const oracle=JSON.parse(gunzipSync(blob)),priorBytes=readFileSync(new URL('evidence/action33-variant-37-oracle.bin',root));
assert.equal(hash(priorBytes),'e78aa4f325e9737245ea35b6078c113b9b60a599b2e0eace2c1738bd6160bf59');
const prior=JSON.parse(gunzipSync(priorBytes));
const compositionBytes=readFileSync(new URL('evidence/action33-composition-30-oracle.bin',root));
assert.equal(hash(compositionBytes),'e0bf9f5d089597868ae05642fc45e5628f0f268b16a210979f2d299445fb6063');
const composition=JSON.parse(gunzipSync(compositionBytes));
const randomWords=Array.from({length:51000},(_,n)=>randomTable.readUInt32LE(4*n));
const newRegions=['009688b0','00968950','00968e40','00968e80','0096d698','00968ea8'];
function prepare(row:any){
 const memory=new Memory(),input=prefix.cases[row.case.source_case].input;
 memory.seed(input,'distance' in row.case?{...row.case,mode:'baseline'}:row.case);
 if('distance' in row.case)for(let k=0;k<108;k++)memory.regions.grid.bytes.writeFloatLE(row.case.distance,k*4);
 for(const [name,value] of Object.entries(row.before.rng_cells)){const bytes=Buffer.alloc(4);bytes.writeUInt32LE(value as number);memory.regions[name]={base:parseInt(name,16),bytes};}
 return {memory,m:new GridMachine31(row.before,memory)};
}
function digests(memory:Memory,old=false){return Object.fromEntries(Object.entries(memory.regions).filter(([name])=>!old||!newRegions.includes(name)).map(([name,{bytes}])=>[name,hash(bytes)]));}
function compareFinal(m:GridMachine31,memory:Memory,row:any){
 assert.deepEqual(m.state,row.after,`full represented state ${row.id}`);
 assert.deepEqual(m.trace,row.instruction_trace,`instruction trace ${row.id}`);
 assert.deepEqual(m.events,row.events,`ordered memory ${row.id}`);
 assert.deepEqual(m.calls,row.calls,`call/return ABI ${row.id}`);
 assert.deepEqual(digests(memory),row.memory_sha256,`all mapped regions ${row.id}`);
}
let steps=0,events=0,suffixCount=0,nonnull=0,rngCalls=0,wraps=0,projections=0;
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);const {memory,m}=prepare(row),stateHash=createHash('sha256');let checkpoint:any=null,stateCount=0;
 const capture=()=>({state:m.snapshot(),trace_length:m.trace.length,event_length:m.events.length,call_length:m.calls.length,memory_sha256:digests(memory,true)});
 const at=m.at.bind(m);
 m.at=(pc:number)=>{
  if(pc===0x702416)checkpoint=capture();
  if(checkpoint!==null){stateHash.update(JSON.stringify({pc:pc.toString(16).padStart(8,'0'),state:m.snapshot()})+'\n');stateCount++;}
  at(pc);
 };
 const stop=runAction33KeeperPrefix38(m);if(stop===0x702332)checkpoint=capture();
 assert.equal(stop.toString(16).padStart(8,'0'),row.stop);assert.deepEqual(checkpoint,row.checkpoint,`original-produced R37-B checkpoint ${n}`);
 compareFinal(m,memory,row);assert.equal(stateHash.digest('hex'),row.suffix_state_sha256,`every suffix instruction state ${n}`);assert.equal(stateCount,row.suffix_states);
 const rng=m.calls.filter((c:any)=>c.target==='0090cfc0') as any[];assert.deepEqual(rng,row.rng,`ordered RNG calls ${n}`);
 assert.deepEqual(Array.from({length:5},(_,i)=>memory.read(m.r.esp+4*i,4)),row.boundary.arguments);
 const selected=(m.calls.find((c:any)=>c.target==='006ce110') as any).after.registers.eax;assert.equal(selected,row.selected);
 const old=prior.cases.find((r:any)=>JSON.stringify(r.case)===JSON.stringify(row.case));assert.ok(old);
 assert.deepEqual(checkpoint.state,old.after);assert.deepEqual(checkpoint.memory_sha256,old.memory_sha256);
 assert.deepEqual(m.trace.slice(0,checkpoint.trace_length),old.instruction_trace);assert.deepEqual(m.events.slice(0,checkpoint.event_length),old.events);
 assert.deepEqual(m.calls.slice(0,checkpoint.call_length),old.calls);
 for(const draw of rng){const state={...draw.before.rng},value=nextBounded(draw.arguments[0]|0,state,randomWords);assert.deepEqual(draw.after.rng,state);assert.equal(draw.after.registers.eax|0,value);}
 if(selected){
  const keeper=m.calls.find((c:any)=>c.site==='00702416') as any;assert.ok(keeper.after);assert.deepEqual(keeper.arguments,old.boundary.arguments);
  for(const name of ['ebx','esi','edi','ebp'])assert.equal(keeper.after.registers[name],keeper.before.registers[name]);
  assert.equal(keeper.after.registers.esp,keeper.before.registers.esp+24);assert.equal(keeper.after.fpcw,keeper.before.fpcw);
  assert.equal(keeper.after.fptag,65535);assert.deepEqual(keeper.after.active_x87,[]);
  if(row.case.mode==='baseline'){
   const frame=keeper.before.registers.esp+24,word=(keeper.after.registers.eax<<16)>>16;
   const projected={draws:rng.slice(1).map(d=>({site:d.site,bound:d.arguments[0]|0,value:d.after.registers.eax|0,initial:d.before.rng,final:d.after.rng})),
    result:{keeper:selected,variant:keeper.arguments[2]&255,responseWord:word,positionFlag:memory.read(frame+0x20,1),fallbackFlag:memory.read(frame+0x14,1),
     marker260:memory.read(frame+0x19,1),marker375:memory.read(frame+0x1a,1),eligible:m.trace.includes('007004d6'),
     path:!m.trace.includes('007004d6')?'rejected':m.trace.includes('00700b03')?'weighted':m.trace.includes('00700b41')?'redrawn':'retained',outgoingArgumentDwords:row.boundary.arguments},
    final_rng:m.state.rng,final_memory_sha256:Object.fromEntries(['match','positions','random_table','grid'].map(k=>[k,hash(memory.regions[k].bytes)]))};
   assert.deepEqual(projected,row.r30c_projection);const expected=composition.cases[row.case.source_case];
   assert.deepEqual(projected,Object.fromEntries(Object.keys(projected).map(k=>[k,expected[k]])));projections++;
  }else assert.equal(row.r30c_projection,null);
 }else{assert.equal(rng.length,1);assert.equal(row.r30c_projection,null);assert.deepEqual(m.state.rng,row.before.rng);}
 steps+=m.trace.length;events+=m.events.length;suffixCount+=stateCount;nonnull+=Number(selected!==0);rngCalls+=rng.length;
 wraps+=m.calls.filter((c:any)=>c.target==='00946a04').length;
}
assert.deepEqual(oracle.coverage,{cases:232,effect_boundaries:nonnull,diagnostic_boundaries:232-nonnull,instructions:steps,events,
 suffix_states:suffixCount,rng_calls:rngCalls,crt_wrap_calls:wraps,keeper_returns:nonnull,r30c_semantic_projections:projections});
// Mutations enter the real modeled continuation; the complete comparison must fail.
for(const mode of ['return-high-word','output-pointer','x87-status','rng-cell','marker']){
 const row=oracle.cases[0],{memory,m}=prepare(row),at=m.at.bind(m);
 m.at=(pc:number)=>{
  if(mode==='return-high-word'&&pc===0x70241b)m.r.eax^=0x10000;
  if(mode==='output-pointer'&&pc===0x700431)m.r.ebp+=1;
  if(mode==='x87-status'&&pc===0x700b88)m.state.fpsw^=0x100;
  if(mode==='rng-cell'&&pc===0x70241b){m.state.rng.offset^=1;m.state.rng_cells['00de1f5c']^=1;memory.write(0xde1f5c,4,m.state.rng.offset);}
  if(mode==='marker'&&pc===0x70243f)memory.write(m.r.esp+0x19,1,1);
  at(pc);
 };
 runAction33KeeperPrefix38(m);assert.throws(()=>compareFinal(m,memory,row),assert.AssertionError);
}
for(const mode of ['action','x87']){
 const {memory,m}=prepare(oracle.cases[0]);assert.equal(runAction33VariantPrefix37(m),0x702416);
 if(mode==='action')memory.write(m.r.esp+12,1,0xff);else m.state.fpcw=0x17f;
 assert.throws(()=>runAction33KeeperSuffix38(m),mode==='action'?/keeper action33 only/:/keeper requires empty nearest/);
}
// Receipt hash is pinned after regeneration, separately from behavior fixtures.
const receiptBytes=readFileSync(new URL('evidence/action33-keeper-38-integrity.json',root));
assert.equal(hash(receiptBytes),'c54933d1074d6051a2235e7c2833b831bbbb3ad544c76df4a655946fd28c0bb1');const receipt=JSON.parse(receiptBytes);
assert.equal(receipt.unit,'R38-A');assert.equal(receipt.status,'passed');assert.equal(receipt.oracle_sha256,hash(blob));assert.deepEqual(receipt.coverage,oracle.coverage);
assert.equal(Object.keys(receipt.negative_checks).length,44);
for(const source of ['keeper','grid'])for(const width of [33,48,64,96])for(const prefix of [0,1,2])
 assert.equal(receipt.negative_checks[`private_base64_${source}_${width}_prefix${prefix}`],'private original fragment');
console.log(JSON.stringify({unit:'R38-A',status:'passed',node:process.version,...oracle.coverage,
 scope:'original-entry keeper return to pre-007024b4 or pre-00702332; no resolver return, outcome, live reachability or R30-C machine-state join'}));

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31} from './action33-grid-31.ts';
import {nextBounded} from './bounded-random.ts';
import {runAction33KeeperPrefix38} from './action33-keeper-38.ts';
import {runAction33EffectPrefix39,runAction33EffectSuffix39} from './action33-effect-39.ts';
const root=new URL('../',import.meta.url),hash=(b:Uint8Array)=>createHash('sha256').update(b).digest('hex');
const MATCH=0x4100000,POSITIONS=0x4300000,STACK=0x2000000,SP=STACK+0x8000,TABLE=0xaa2454,GRID=0xa15e44,BASES=[0x4796,0x6a6e];
const prefixBytes=readFileSync(new URL('evidence/action33-prefix-30-oracle.bin',root));
assert.equal(hash(prefixBytes),'08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f');
const prefix=JSON.parse(gunzipSync(prefixBytes));
const randomTable=readFileSync(new URL('evidence/random-validation/random-table.bin',root));
assert.equal(hash(randomTable),'befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db');
class Memory{
 regions:Record<string,{base:number;bytes:Buffer}>={match:{base:MATCH,bytes:Buffer.alloc(65536)},positions:{base:POSITIONS,bytes:Buffer.alloc(4096)},
  stack:{base:STACK,bytes:Buffer.alloc(65536)},random_table:{base:TABLE,bytes:Buffer.from(randomTable)},grid:{base:GRID,bytes:Buffer.alloc(432)},'00b63d28':{base:0xb63d28,bytes:Buffer.alloc(4)}};
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

const blob=readFileSync(new URL('evidence/action33-effect-39-oracle.bin',root));
assert.equal(hash(blob),'fc0771a515e0e142b3b1d1d5ffd62bebf6710aa93b258e6fa66a4cab78e8958d');
assert.equal(blob.subarray(0,10).toString('hex'),'1f8b08000000000002ff');
const oracle=JSON.parse(gunzipSync(blob)),priorBytes=readFileSync(new URL('evidence/action33-keeper-38-oracle.bin',root));
assert.equal(hash(priorBytes),'d5e9ed42bae44b49a0c21dc21b6e7e045f7eb724b2b2a3f9770eddecf703a53d');
const prior=JSON.parse(gunzipSync(priorBytes));
for(const [name,digest] of Object.entries(oracle.sites.dependency_hashes))assert.equal(hash(readFileSync(new URL(name,root))),digest);
const randomWords=Array.from({length:51000},(_,n)=>randomTable.readUInt32LE(4*n));
function prepare(row:any){
 const memory=new Memory(),input=prefix.cases[row.case.source_case].input;
 memory.seed(input,'distance' in row.case?{...row.case,mode:'baseline'}:row.case);
 if('distance' in row.case)for(let k=0;k<108;k++)memory.regions.grid.bytes.writeFloatLE(row.case.distance,k*4);
 for(const [name,value] of Object.entries(row.before.rng_cells)){const bytes=Buffer.alloc(4);bytes.writeUInt32LE(value as number);memory.regions[name]={base:parseInt(name,16),bytes};}
 return {memory,m:new GridMachine31(row.before,memory)};
}
function digests(memory:Memory,old=false){return Object.fromEntries(Object.entries(memory.regions).filter(([name])=>!old||name!=='00b63d28').map(([name,{bytes}])=>[name,hash(bytes)]));}
function compareFinal(m:GridMachine31,memory:Memory,row:any){
 assert.deepEqual(m.state,row.after,`full represented state ${row.id}`);
 assert.deepEqual(m.trace,row.instruction_trace,`instruction trace ${row.id}`);
 assert.deepEqual(m.events,row.events,`ordered memory ${row.id}`);
 assert.deepEqual(m.calls,row.calls,`call/return ABI ${row.id}`);
 assert.deepEqual(digests(memory),row.memory_sha256,`all mapped regions ${row.id}`);
}
let steps=0,events=0,suffixCount=0,suffixEvents=0,nonnull=0,rngCalls=0,suffixRng=0,zeroBounds=0,wraps=0,suffixWraps=0;
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);const {memory,m}=prepare(row),stateHash=createHash('sha256'),prefixHash=createHash('sha256');
 const old=prior.cases[n];assert.deepEqual(row.case,old.case);assert.deepEqual(row.before,old.before);
 let checkpoint:any=null,stateCount=0,prefixCount=0,prefixStarted=false;
 const capture=()=>({state:m.snapshot(),trace_length:m.trace.length,event_length:m.events.length,call_length:m.calls.length,memory_sha256:digests(memory,true)});
 const at=m.at.bind(m);
 m.at=(pc:number)=>{
  if(pc===0x7024b4)checkpoint=capture();
  if(pc===0x702416)prefixStarted=true;
  if(prefixStarted&&checkpoint===null){prefixHash.update(JSON.stringify({pc:pc.toString(16).padStart(8,'0'),state:m.snapshot()})+'\n');prefixCount++;}
  if(checkpoint!==null){stateHash.update(JSON.stringify({pc:pc.toString(16).padStart(8,'0'),state:m.snapshot()})+'\n');stateCount++;}
  at(pc);
 };
 const stop=runAction33EffectPrefix39(m);if(stop===0x702332)checkpoint=capture();
 assert.equal(stop.toString(16).padStart(8,'0'),row.stop);assert.deepEqual(checkpoint,row.checkpoint,`original-produced R38-A checkpoint ${n}`);
 assert.equal(prefixHash.digest('hex'),old.suffix_state_sha256);assert.equal(prefixCount,old.suffix_states);
 compareFinal(m,memory,row);assert.equal(stateHash.digest('hex'),row.suffix_state_sha256,`every suffix instruction state ${n}`);assert.equal(stateCount,row.suffix_states);
 assert.deepEqual(checkpoint.state,old.after);assert.deepEqual(checkpoint.memory_sha256,old.memory_sha256);
 assert.deepEqual(m.trace.slice(0,checkpoint.trace_length),old.instruction_trace);assert.deepEqual(m.events.slice(0,checkpoint.event_length),old.events);
 assert.deepEqual(m.calls.slice(0,checkpoint.call_length),old.calls);
 const rng=m.calls.filter((c:any)=>c.target==='0090cfc0') as any[];assert.deepEqual(rng,row.rng,`ordered RNG calls ${n}`);
 for(const draw of rng){const state={...draw.before.rng},value=nextBounded(draw.arguments[0]|0,state,randomWords);assert.deepEqual(draw.after.rng,state);assert.equal(draw.after.registers.eax|0,value);}
 assert.deepEqual(Array.from({length:5},(_,i)=>memory.read(m.r.esp+4*i,4)),row.boundary.arguments);
 assert.equal(row.boundary.target,'00944cff');assert.equal(row.effect_returned,false);
 assert.equal(m.trace.includes(row.stop),false);
 const selected=(m.calls.find((c:any)=>c.target==='006ce110') as any).after.registers.eax;assert.equal(selected,row.selected);
 const pending=m.calls.flatMap((c:any,i:number)=>c.after===null?[i]:[]);assert.deepEqual(pending,row.pending_calls);
 const added=m.calls.slice(checkpoint.call_length) as any[],addedRng=added.filter(c=>c.target==='0090cfc0');
 if(selected){
  assert.equal(stop,0x62ed99);
  assert.deepEqual(pending.map(i=>{const c:any=m.calls[i];return [c.site,c.target];}),[['007024b4','006cfe10'],['006cfec2','0062ed70']]);
  const effect:any=m.calls[pending[0]],lookup:any=m.calls[pending[1]];
  assert.deepEqual(effect.arguments,old.boundary.arguments);assert.deepEqual(effect.arguments,[checkpoint.state.registers.esi,109,0,0x4100000,0]);
  assert.deepEqual(Array.from({length:5},(_,i)=>memory.read(effect.before.registers.esp+4*i,4)),effect.arguments);
  assert.equal(lookup.before.registers.ecx,0);assert.deepEqual(lookup.arguments,[0]);
  assert.equal(memory.read(effect.arguments[0]+0x69,4),0);assert.equal(memory.read(0xb63d28,4),0);
  assert.deepEqual(row.boundary.arguments,[0x9e7f28,0,0,0x2007824,0x2007724]);assert.equal(m.r.esp,0x2007708);
  assert.equal(m.state.fpcw,checkpoint.state.fpcw);assert.equal(m.state.fpsw,checkpoint.state.fpsw);assert.equal(m.state.fptag,65535);assert.deepEqual(m.state.active_x87,[]);
  for(const [name,digest] of Object.entries(checkpoint.memory_sha256))if(!['stack','00de1f60','00de1f5c','00ad6c30'].includes(name))assert.equal(digests(memory)[name],digest);
  for(const event of m.events.slice(checkpoint.event_length))if(event[1]==='write'){
   const address=parseInt(event[2] as string,16);assert.ok(address>=STACK&&address<STACK+65536||[0xde1f60,0xde1f5c,0xad6c30].includes(address));
  }
  // Two nested groups run even with participant2 null; optional draws retain order.
  let index=0;
  for(const sites of [[0x6cfe35,0x6cfe3b,0x6cfe50,0x6cfe5e,0x6cfe64],[0x6cfe74,0x6cfe7a,0x6cfe8c,0x6cfe9a,0x6cfea0]]){
   function take(site:number,bound:number){const draw=addedRng[index++];assert.ok(draw);assert.equal(draw.site,site.toString(16).padStart(8,'0'));assert.deepEqual(draw.arguments,[bound]);return draw.after.registers.eax;}
   const bound=take(sites[0],102),value=take(sites[1],bound);
   if((value<<24)>>24>50){const chance=take(sites[2],3);if(chance!==0)take(sites[4],take(sites[3],76));}
  }
  assert.equal(index,addedRng.length);
 }else{
  assert.equal(stop,0x702332);assert.equal(added.length,0);assert.equal(rng.length,1);assert.deepEqual(m.state.rng,row.before.rng);
 }
 steps+=m.trace.length;events+=m.events.length;suffixCount+=stateCount;suffixEvents+=m.events.length-checkpoint.event_length;nonnull+=Number(selected!==0);
 rngCalls+=rng.length;suffixRng+=addedRng.length;zeroBounds+=addedRng.filter(c=>c.arguments[0]===0).length;
 wraps+=m.calls.filter((c:any)=>c.target==='00946a04').length;suffixWraps+=added.filter(c=>c.target==='00946a04').length;
}
assert.deepEqual(oracle.coverage,{cases:232,lookup_diagnostic_boundaries:nonnull,keeper_diagnostic_boundaries:232-nonnull,effect_returns:0,
 instructions:steps,events,suffix_states:suffixCount,suffix_events:suffixEvents,rng_calls:rngCalls,suffix_rng_calls:suffixRng,suffix_zero_bounds:zeroBounds,
 crt_wrap_calls:wraps,suffix_crt_wrap_calls:suffixWraps});
for(const mode of ['argument-high','selector-byte','rng-cell','lookup-stack']){
 const row=oracle.cases[0],{memory,m}=prepare(row),at=m.at.bind(m);
 m.at=(pc:number)=>{
  if(mode==='argument-high'&&pc===0x6cfe10)memory.write(m.r.esp+16,4,0);
  if(mode==='selector-byte'&&pc===0x6cfe48)m.r.ebx^=1;
  if(mode==='rng-cell'&&pc===0x6cfe40){m.state.rng.offset^=1;m.state.rng_cells['00de1f5c']^=1;memory.write(0xde1f5c,4,m.state.rng.offset);}
  if(mode==='lookup-stack'&&pc===0x62ed85)m.r.esp+=4;
  at(pc);
 };
 runAction33EffectPrefix39(m);assert.throws(()=>compareFinal(m,memory,row),assert.AssertionError);
}
for(const mode of ['participant','lookup','shooter','x87']){
 const {memory,m}=prepare(oracle.cases[0]);assert.equal(runAction33KeeperPrefix38(m),0x7024b4);
 if(mode==='participant')memory.write(m.r.esi+0x69,4,MATCH);
 if(mode==='lookup')memory.write(0xb63d28,4,MATCH);
 if(mode==='shooter')memory.write(m.r.esp,4,0);
 if(mode==='x87')m.state.fptag=0;
 assert.throws(()=>runAction33EffectSuffix39(m),mode==='x87'?/effect requires empty x87/:/effect requires unchanged nonnull shooter/);
}
const receiptBytes=readFileSync(new URL('evidence/action33-effect-39-integrity.json',root));
assert.equal(hash(receiptBytes),'13b034ad68ad3cc103e36f7cb7dc91d4afd2a260eb0c633d0baef3f411eb6c7e');const receipt=JSON.parse(receiptBytes);
assert.equal(receipt.unit,'R39-A');assert.equal(receipt.status,'passed');assert.equal(receipt.oracle_sha256,hash(blob));assert.deepEqual(receipt.coverage,oracle.coverage);
for(const [name,digest] of Object.entries(receipt.verifier_dependency_hashes))assert.equal(hash(readFileSync(new URL(name,root))),digest);
assert.equal(Object.keys(receipt.negative_checks).length,77);
for(const source of ['effect','grid'])for(const width of [12,13,14,21,29,33,48,64,96])for(const prefix of [0,1,2])
 assert.equal(receipt.negative_checks[`private_base64_${source}_${width}_prefix${prefix}`],'private original fragment');
console.log(JSON.stringify({unit:'R39-A',status:'passed',node:process.version,...oracle.coverage,
 scope:'original-entry effect/lookup remain pending before diagnostic; no effect/lookup/resolver return, outcome or live reachability'}));

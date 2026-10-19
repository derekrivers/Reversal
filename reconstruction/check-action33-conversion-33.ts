import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33OpponentPrefix32} from './action33-opponent-32.ts';
import {runConversionCall33,runAction33ConversionContinuation33} from './action33-conversion-33.ts';
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

const priorBytes=readFileSync(new URL('evidence/action33-opponent-32-oracle.bin',root));
assert.equal(hash(priorBytes),'cb721094cdebd96b0ff87f1bae68afe437091c17a0277e52c362a348c5683ab6');
const prior=JSON.parse(gunzipSync(priorBytes));
const blob=readFileSync(new URL('evidence/action33-conversion-33-oracle.bin',root));
assert.equal(hash(blob),'1fc3bf7c687abec08597d8e9eb66d0abb3a871e7a156075d4b195ad8fa4b79ee','R33-A oracle SHA-256');
const oracle=JSON.parse(gunzipSync(blob,{maxOutputLength:12000000}));assert.equal(oracle.unit,'R33-A');
assert.equal(oracle.sites.specimen_sha256,prefix.specimen_sha256);assert.equal(oracle.sites.opponent_oracle_sha256,hash(priorBytes));
const receiptBytes=readFileSync(new URL('evidence/action33-conversion-33-integrity.json',root));
assert.equal(hash(receiptBytes),'339467513bb5ad2d96a58571d28e138f3f9160169b5d4381e26c7ecac0011801','R33-A integrity SHA-256');
const receipt=JSON.parse(receiptBytes),keys=(v:any,s:string)=>assert.deepEqual(Object.keys(v).sort(),s.split(' ').sort());
keys(receipt,'unit status oracle_sha256 specimen_sha256 coverage normal_optimized negative_checks privacy scope');
keys(receipt.negative_checks,'changed_PE independent_native_operand independent_bit04_operand changed_native_file changed_manifest changed_conversion_export changed_focused_export changed_focused_manifest unannounced_bit04_path original_out_of_grid_read appended_json_whitespace alternate_gzip_envelope oversized_expansion changed_oracle_result changed_conversion_rounding private_raw_fragment private_hex_fragment compressed_private_fragment');
assert.equal(receipt.unit,'R33-A');assert.equal(receipt.status,'passed');assert.equal(receipt.oracle_sha256,hash(blob));
assert.equal(receipt.specimen_sha256,oracle.sites.specimen_sha256);assert.deepEqual(receipt.coverage,oracle.coverage);
for(const message of Object.values(receipt.negative_checks))assert.ok(typeof message==='string'&&message.length>0);
for(const [name,field] of [['prefix_30','prefix_setup_source_sha256'],['grid_31','grid_source_sha256'],['opponent_32','opponent_source_sha256']])
 assert.equal(hash(readFileSync(new URL('scripts/emulate_action33_'+name+'.py',root))),oracle.sites[field]);
let steps=0,events=0,clear=0,set=0,rounding=0;
function seeded(row:any){
 const task=row.case,memory=new Memory(),input=prefix.cases[task.source_case].input;
 memory.seed(input,'distance' in task?{...task,mode:'baseline'}:task);
 if('distance' in task)for(let n=0;n<108;n++)memory.regions.grid.bytes.writeFloatLE(task.distance,n*4);
 return memory;
}
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);const memory=seeded(row),before=structuredClone(row.before),probe=row.case.mode==='rounding-probe',fpObservations:any[]=[];
 // Directed-rounding probes are a separate supplied-checkpoint helper test.
 // Rebuild the preceding synthetic memory with the nearest prefix, then admit
 // the original-produced checkpoint CW. The conversion comparisons below start
 // only at the original CALL; no directed-rounding prefix equivalence is claimed.
 if(probe)before.fpcw&=~0xc00;
 const m=new GridMachine31(before,memory),stop=runAction33OpponentPrefix32(m);
 if(probe)m.state.fpcw=row.checkpoint.state.fpcw;
 assert.deepEqual(m.state,row.checkpoint.state,`original-produced R32 checkpoint ${n}`);
 assert.equal(m.trace.length,row.checkpoint.trace_length);assert.equal(m.events.length,row.checkpoint.event_length);assert.equal(m.calls.length,row.checkpoint.call_length);
 for(const [name,digest] of Object.entries(row.checkpoint.memory_sha256))assert.equal(hash(memory.regions[name].bytes),digest,`checkpoint region ${name} ${n}`);
 if(n<220){
  const old=prior.cases[n];assert.deepEqual(row.case,old.case);assert.deepEqual(row.checkpoint.state,old.after);
  assert.deepEqual(row.checkpoint.memory_sha256,old.memory_sha256);assert.deepEqual(m.trace,old.instruction_trace);assert.deepEqual(m.events,old.events);assert.deepEqual(m.calls,old.calls);
 }
 if(stop===0x71614b){assert.equal(row.stop,'0071614b');set++;}
 else{
  assert.equal(stop,0x702193);assert.deepEqual(m.state,row.conversion.state);
  for(const [name,digest] of Object.entries(row.conversion.memory_sha256))assert.equal(hash(memory.regions[name].bytes),digest);
  assert.equal(probe?runConversionCall33(m,fpObservations):runAction33ConversionContinuation33(m,fpObservations),parseInt(row.stop,16));
  if(probe)rounding++;else clear++;
 }
 assert.deepEqual(m.state,row.after,`full admitted state ${n}`);
 assert.deepEqual(fpObservations,row.fp_observations,`save/truncate/restore x87 observations ${n}`);
 const traceStart=probe?row.conversion.trace_length:0,eventStart=probe?row.conversion.event_length:0,callStart=probe?row.conversion.call_length:0;
 assert.deepEqual(m.events.slice(eventStart),row.events.slice(eventStart),`ordered reads/writes ${n}`);
 assert.deepEqual(m.trace.slice(traceStart),row.instruction_trace.slice(traceStart),`instruction path ${n}`);
 assert.deepEqual(m.calls.slice(callStart),row.calls.slice(callStart),`call/return ABI ${n}`);
 for(const [name,{bytes}] of Object.entries(memory.regions))assert.equal(hash(bytes),row.memory_sha256[name],`full ${name} region ${n}`);
 assert.deepEqual(m.state.rng,row.before.rng);assert.deepEqual(m.state.rng_cells,row.before.rng_cells);
 steps+=row.instruction_trace.length;events+=row.events.length;
}
assert.deepEqual(oracle.coverage,{cases:280,guard_clear:clear,guard_set:set,rounding_probes:rounding,instructions:steps,events,rng_calls:0});
function atConversion(){const row=oracle.cases[0],memory=seeded(row),m=new GridMachine31(row.before,memory);assert.equal(runAction33OpponentPrefix32(m),0x702193);return m;}
const noSt0=atConversion();noSt0.state.active_x87=[];assert.throws(()=>runConversionCall33(noSt0),/one normal ST0/);
const wrongPrecision=atConversion();wrongPrecision.state.fpcw=0x7f;assert.throws(()=>runConversionCall33(wrongPrecision),/53\/64-bit/);
const negative=atConversion();negative.state.active_x87[0].exponent|=0x8000;assert.throws(()=>runConversionCall33(negative),/positive caller domain/);
const wrongScalar=atConversion();wrongScalar.memory.write(0x967890+4,4,0);assert.throws(()=>runAction33ConversionContinuation33(wrongScalar),/unsupported additive scalar/);
const wrongAction=atConversion();wrongAction.memory.write(wrongAction.r.esp+0x698,1,3);assert.throws(()=>runAction33ConversionContinuation33(wrongAction),/only action33/);
console.log(JSON.stringify({unit:'R33-A',status:'passed',node:process.version,...oracle.coverage,
 scope:'232 original-entry clear continuations; 32 separate conversion checkpoints; 16 unchanged bit04 stops; no join or shot outcome'}));

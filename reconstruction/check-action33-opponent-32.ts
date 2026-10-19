import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31,runAction33GridPrefix31} from './action33-grid-31.ts';
import {runAction33OpponentContinuation32} from './action33-opponent-32.ts';
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
  for(const [address,size,value] of [[0x96d810,8,1680],[0x96d754,4,9],[0x968e18,8,2.5]]){const bytes=Buffer.alloc(size);if(size===8)bytes.writeDoubleLE(value);else bytes.writeFloatLE(value);this.regions[address.toString(16).padStart(8,'0')]={base:address,bytes};}
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

const gridBlob=readFileSync(new URL('evidence/action33-grid-31-oracle.bin',root));
assert.equal(hash(gridBlob),'9967372e29685c49dc6da1663c5eb4fdd1a5347a846a41b211ce7bbc64dfac07');
const gridOracle=JSON.parse(gunzipSync(gridBlob));
const blob=readFileSync(new URL('evidence/action33-opponent-32-oracle.bin',root));
assert.equal(hash(blob),'cb721094cdebd96b0ff87f1bae68afe437091c17a0277e52c362a348c5683ab6','R32-A oracle SHA-256');
const oracle=JSON.parse(gunzipSync(blob));assert.equal(oracle.unit,'R32-A');assert.equal(oracle.sites.specimen_sha256,prefix.specimen_sha256);
const receiptBytes=readFileSync(new URL('evidence/action33-opponent-32-integrity.json',root));
assert.equal(hash(receiptBytes),'b30a2a682ab1daafdd5b88d3b765b70289bc45f4c520beea10d680a29634bc2b','R32-A integrity SHA-256');
const receipt=JSON.parse(receiptBytes),keys=(v:any,s:string)=>assert.deepEqual(Object.keys(v).sort(),s.split(' ').sort());
keys(oracle,'unit sites cases scope coverage');keys(receipt,'unit status oracle_sha256 specimen_sha256 coverage normal_optimized negative_checks privacy scope');
assert.equal(receipt.unit,'R32-A');assert.equal(receipt.status,'passed');assert.equal(receipt.oracle_sha256,hash(blob));
assert.equal(receipt.specimen_sha256,oracle.sites.specimen_sha256);assert.deepEqual(receipt.coverage,oracle.coverage);
keys(receipt.negative_checks,'changed_PE independent_native_operand changed_native_file changed_manifest unannounced_bit04_path original_out_of_grid_read appended_json_whitespace alternate_gzip_envelope oversized_expansion private_raw_fragment private_hex_fragment compressed_private_fragment');
for(const message of Object.values(receipt.negative_checks))assert.ok(typeof message==='string'&&message.length>0);
assert.equal(hash(readFileSync(new URL('scripts/emulate_action33_prefix_30.py',root))),oracle.sites.prefix_setup_source_sha256);
assert.equal(hash(readFileSync(new URL('scripts/emulate_action33_grid_31.py',root))),oracle.sites.grid_source_sha256);
let steps=0,events=0,clear=0,set=0;
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);const task=row.case,base=prefix.cases[task.source_case],c=base.input;
 assert.deepEqual(row.before,gridOracle.cases[task.source_case].before,'same R31 entry state');
 const memory=new Memory();memory.seed(c,task);const machine=new GridMachine31(row.before,memory);
 assert.equal(runAction33GridPrefix31(machine),0x70210b);
 assert.deepEqual(machine.state,row.checkpoint.state,`original-produced checkpoint ${n}`);
 assert.equal(machine.trace.length,row.checkpoint.trace_length);assert.equal(machine.events.length,row.checkpoint.event_length);
 for(const [name,digest] of Object.entries(row.checkpoint.memory_sha256))assert.equal(hash(memory.regions[name].bytes),digest,`checkpoint region ${name} ${n}`);
 if(task.mode==='baseline'){
  const prior=gridOracle.cases[task.source_case];assert.deepEqual(row.checkpoint.state,prior.after);
  assert.deepEqual(row.checkpoint.memory_sha256,prior.memory_sha256);assert.deepEqual(machine.trace,prior.instruction_trace);assert.deepEqual(machine.events,prior.events);
 }
 assert.equal(runAction33OpponentContinuation32(machine),parseInt(row.stop,16));
 assert.deepEqual(machine.state,row.after,`full admitted state ${n}`);
 assert.deepEqual(machine.events,row.events,`ordered reads/writes including stack ${n}`);
 assert.deepEqual(machine.trace,row.instruction_trace,`instruction path ${n}`);
 assert.deepEqual(machine.calls,row.calls,`call/return ABI ${n}`);
 for(const [name,{bytes}] of Object.entries(memory.regions))assert.equal(hash(bytes),row.memory_sha256[name],`full ${name} region ${n}`);
 assert.deepEqual(machine.state.rng,row.before.rng);assert.deepEqual(machine.state.rng_cells,row.before.rng_cells);
 steps+=machine.trace.length;events+=machine.events.length;if(row.stop==='00702193')clear++;else{assert.equal(row.stop,'0071614b');set++;}
}
assert.deepEqual(oracle.coverage,{cases:220,guard_clear:clear,guard_set:set,instructions:steps,events,rng_calls:0});
const first=oracle.cases[0],badMemory=new Memory();badMemory.seed(prefix.cases[0].input,first.case);
const bad=new GridMachine31(first.before,badMemory);runAction33GridPrefix31(bad);bad.state.fpsw=1;
assert.throws(()=>runAction33OpponentContinuation32(bad),/continuation requires empty x87/);
bad.state.fpsw=0;bad.state.fpcw=0x7f;
assert.throws(()=>runAction33OpponentContinuation32(bad),/53\/64-bit precision/);
const wrongConstant=new Memory();wrongConstant.seed(prefix.cases[0].input,first.case);wrongConstant.write(0x96d754,4,0);
const wrong=new GridMachine31(first.before,wrongConstant);runAction33GridPrefix31(wrong);
assert.throws(()=>runAction33OpponentContinuation32(wrong),/unsupported multiplier/);
const unsupportedDistance=new Memory();unsupportedDistance.seed(prefix.cases[0].input,first.case);
const distanceMachine=new GridMachine31(first.before,unsupportedDistance);runAction33GridPrefix31(distanceMachine);
unsupportedDistance.write(distanceMachine.r.esp+4+0x80,4,0x3f000000);
assert.throws(()=>runAction33OpponentContinuation32(distanceMachine),/requires distance zero or in/);
console.log(JSON.stringify({unit:'R32-A',status:'passed',node:process.version,...oracle.coverage,
 scope:'original-produced prefix to guarded next calls; ordered memory, GPR/flags, active x87 and full regions; no shot outcome'}));

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {GridMachine31,runGridHelper31,runAction33GridPrefix31,gridIndex31} from './action33-grid-31.ts';
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
  for(let i=0;i<108;i++){
   if(task.pattern===0)this.regions.grid.bytes.writeFloatLE(Math.hypot(i%9,Math.floor(i/9)),i*4);
   else this.regions.grid.bytes.writeUInt32LE([0,0x80000000,0x3f800000,0xbf800000,0x00800000,0x7f7fffff,0x80800000,0xff7fffff,0x3eaaaaab][i%9],i*4);
  }
  if(task.kind==='helper'){
   m[shooter+0x102]=task.slot_x;m[shooter+0x103]=task.slot_y;
   [0x3000000,0xa5a50000+task.argument_x,0x5a5a0000+task.argument_y].forEach((v,i)=>this.write(SP+i*4,4,v));
  }
 }
}
const blob=readFileSync(new URL('evidence/action33-grid-31-oracle.bin',root));
assert.equal(hash(blob),'9967372e29685c49dc6da1663c5eb4fdd1a5347a846a41b211ce7bbc64dfac07','R31-A oracle SHA-256');
const oracle=JSON.parse(gunzipSync(blob));assert.equal(oracle.unit,'R31-A');assert.equal(oracle.sites.specimen_sha256,prefix.specimen_sha256);
const receiptBytes=readFileSync(new URL('evidence/action33-grid-31-integrity.json',root));
assert.equal(hash(receiptBytes),'5d4ac7d5e0128eb77956636ba5b6250cd07ee41e62b7feb6b23c169035217127','R31-A integrity receipt SHA-256');
const receipt=JSON.parse(receiptBytes),keys=(v:any,s:string)=>assert.deepEqual(Object.keys(v).sort(),s.split(' ').sort());
keys(oracle,'unit sites cases scope coverage');
keys(receipt,'unit status oracle_sha256 specimen_sha256 coverage normal_optimized negative_checks privacy scope');
assert.equal(receipt.unit,'R31-A');assert.equal(receipt.status,'passed');assert.equal(receipt.oracle_sha256,hash(blob));
assert.equal(receipt.specimen_sha256,oracle.sites.specimen_sha256);assert.deepEqual(receipt.coverage,oracle.coverage);
keys(receipt.negative_checks,'changed_PE independent_native_operand changed_native_file changed_manifest original_out_of_grid_read appended_json_whitespace alternate_gzip_envelope');
for(const message of Object.values(receipt.negative_checks))assert.ok(typeof message==='string'&&message.length>0);
assert.equal(hash(readFileSync(new URL('scripts/emulate_action33_prefix_30.py',root))),oracle.sites.prefix_setup_source_sha256);
let steps=0,events=0;
for(const [n,row] of oracle.cases.entries()){
 assert.equal(row.id,n);const task=row.case,base=prefix.cases[task.source_case],c=base.input;
 assert.deepEqual(row.before.registers,base.initial_registers);
 assert.equal(row.before.eflags,0x202);assert.equal(row.before.fpcw,(task.kind==='prefix'?c.precision_bits:task.precision)===53?0x27f:0x37f);
 assert.deepEqual(row.before.rng,{cursorIndex:c.cursor_index,offset:c.offset,crtState:c.crt_state});
 assert.deepEqual(row.before.rng_cells,{'00de1f60':TABLE+4*c.cursor_index,'00de1f5c':c.offset,'00de2798':TABLE+50999*4,'00ad6c30':c.crt_state});
 const memory=new Memory();memory.seed(c,task);const machine=new GridMachine31(row.before,memory);
 if(task.kind==='prefix')assert.equal(runAction33GridPrefix31(machine),0x70210b);
 else assert.equal(runGridHelper31(machine).target,0x3000000);
 assert.deepEqual(machine.state,row.after,`full admitted state ${n}`);
 assert.deepEqual(machine.events,row.events,`ordered reads/writes including stack ${n}`);
 assert.deepEqual(machine.trace,row.instruction_trace,`instruction path ${n}`);
 assert.deepEqual(machine.calls,row.calls,`call/return ABI ${n}`);
 for(const [name,{bytes}] of Object.entries(memory.regions))assert.equal(hash(bytes),row.memory_sha256[name],`full ${name} region ${n}`);
 assert.deepEqual(machine.state.rng,row.before.rng);assert.deepEqual(machine.state.rng_cells,row.before.rng_cells);
 steps+=machine.trace.length;events+=machine.events.length;
}
assert.deepEqual(oracle.coverage,{prefix_cases:160,helper_cases:590,instructions:steps,events,rng_calls:0});
assert.equal(gridIndex31(127,0,128,1),8,'absolute delta 255 narrows to -1');
assert.equal(gridIndex31(0,0,128,0),-128,'absolute delta 128 narrows to -128');
assert.throws(()=>gridIndex31(256,0,0,0),RangeError);
const invalid=new Memory(),first=oracle.cases[160];invalid.seed(prefix.cases[0].input,first.case);
invalid.write(prefix.cases[0].initial_registers.ecx+0x102,1,128);
assert.throws(()=>runGridHelper31(new GridMachine31(first.before,invalid)),/grid index outside/);
console.log(JSON.stringify({unit:'R31-A',status:'passed',node:process.version,...oracle.coverage,
 scope:'helper returns and resolver entry to pre-0070210b; all ordered memory, GPR/flags, active x87 and full regions; no shot outcome'}));

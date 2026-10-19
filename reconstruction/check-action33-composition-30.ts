import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {composeAction33Segment30} from './action33-composition-30.ts';
import type {KeeperMemory29} from './keeper-selector-29.ts';

const MATCH=0x4100000,POSITIONS=0x4300000,BASES=[0x4796,0x6a6e],STRIDE=0x1be;
const hash=(b:Uint8Array)=>createHash('sha256').update(b).digest('hex');
const root=new URL('../',import.meta.url);
class Memory implements KeeperMemory29 {
  match=new Uint8Array(0x10000);positions=new Uint8Array(0x1000);
  writes:(string|number)[][]=[];
  locate(a:number,size:number):[Uint8Array,number]{
    for(const [base,bytes] of [[MATCH,this.match],[POSITIONS,this.positions]] as const)
      if(a>=base&&a+size<=base+bytes.length)return [bytes,a-base];
    throw new RangeError('unmapped composition memory');
  }
  read(a:number,size:number):number{const [b,o]=this.locate(a,size);let v=0;for(let i=0;i<size;i++)v|=b[o+i]<<(8*i);return v>>>0;}
  put(a:number,size:number,v:number):void{const [b,o]=this.locate(a,size);for(let i=0;i<size;i++)b[o+i]=(v>>>(8*i))&255;}
  read8(a:number){return this.read(a,1);}read16(a:number){return this.read(a,2);}read32(a:number){return this.read(a,4);}
  write8(a:number,v:number){this.put(a,1,v);this.writes.push(['write',a.toString(16).padStart(8,'0'),1,v&255]);}
  write32(a:number,v:number){this.put(a,4,v);this.writes.push(['write',a.toString(16).padStart(8,'0'),4,v>>>0]);}
  seed(c:any):void{
    const w32=(o:number,v:number)=>this.put(MATCH+o,4,v),w16=(o:number,v:number)=>this.put(MATCH+o,2,v);
    for(let side=0;side<2;side++){
      for(let k=0;k<20;k++){
        const q=BASES[side]+k*STRIDE;
        this.match[q+0x19]=this.match[q+0x1a]=255;this.match[q+0x27]=side;w32(q+0x19e,MATCH);
      }
      const q=BASES[side];this.match[q+0x19]=0;this.match[q+0x102]=4;this.match[q+0x103]=side===0?11:0;
      this.match[q+0xf]=c.counter_raw;this.match[q+0x2b]=c.selector_mode==='activity-reject'?2:0;
      w16(q+0x168,c.rating0_raw);w16(q+0x16a,c.rating1_raw);w16(q+0x3b,c.fallback_rating_raw);
      const view=new DataView(this.match.buffer);view.setFloat32(q+0xd1,c.adjustment_float,true);
      w32(0x8ebc+side*4,POSITIONS+side*0x100);
      this.put(POSITIONS+side*0x100,2,c.selector_mode==='fallback'?0:1);
      let cache=['cache','activity-reject'].includes(c.selector_mode)?MATCH+q:0;
      if(c.selector_mode==='invalidate')cache=MATCH+q+19*STRIDE;
      w32(0xf59e+side*4,cache);
    }
    const shooter=BASES[c.side]+3*STRIDE;this.match[shooter+0x19]=3;
    this.match[shooter+0x102]=c.x;this.match[shooter+0x103]=c.y;w16(shooter+0x39,0xfff1);
    w16(shooter+0x198,0x33);w16(0x8ed0,c.clock_word);w32(0x4782,12345);w32(0x4786,c.momentum);
    this.match[0x8ea7]=c.x;this.match[0x8ea8]=c.y;this.match[0x8eaa]=c.match_byte_raw;this.match[0x8ea9]=c.state_byte;
  }
}

const packed=readFileSync(new URL('evidence/action33-composition-30-oracle.bin',root));
assert.equal(hash(packed),'e0bf9f5d089597868ae05642fc45e5628f0f268b16a210979f2d299445fb6063');
assert.equal(packed.subarray(0,10).toString('hex'),'1f8b08000000000002ff');
const raw=gunzipSync(packed),oracle=JSON.parse(raw);
assert.equal(raw.toString().replace(/(-?\d+)\.0(?=[,}])/g,'$1'),JSON.stringify(oracle)+'\n');
assert.equal(oracle.prefix_oracle_sha256,hash(readFileSync(new URL('evidence/action33-prefix-30-oracle.bin',root))));
assert.equal(oracle.prefix_emulator_sha256,hash(readFileSync(new URL('scripts/emulate_action33_prefix_30.py',root))));
assert.equal(oracle.prefix_sites_sha256,hash(readFileSync(new URL('evidence/action33-prefix-30-sites.json',root))));
const receiptBytes=readFileSync(new URL('evidence/action33-composition-30-integrity.json',root));
assert.equal(hash(receiptBytes),'48e764f3f06fd7ab6dda358c07f9fdea759421687f563ea4a029a490bf94f8ee','integrity receipt SHA-256');
const receipt=JSON.parse(receiptBytes);
const keys=(v:any,names:string)=>assert.deepEqual(Object.keys(v).sort(),names.split(' ').sort());
keys(receipt,'unit status oracle_sha256 prefix_oracle_sha256 prefix_emulator_sha256 prefix_sites_sha256 coverage normal_optimized negative_checks privacy scope');
assert.equal(receipt.unit,'R30-C');assert.equal(receipt.status,'passed');assert.equal(receipt.oracle_sha256,hash(packed));
for(const key of ['prefix_oracle_sha256','prefix_emulator_sha256','prefix_sites_sha256'])assert.equal(receipt[key],oracle[key]);
assert.deepEqual(receipt.coverage,oracle.coverage);
keys(receipt.negative_checks,'changed_PE independent_native_operand changed_native_file appended_json_whitespace alternate_gzip_envelope');
for(const message of Object.values(receipt.negative_checks))assert.ok(typeof message==='string'&&message.length>0);
const bytes=readFileSync(new URL('evidence/random-validation/random-table.bin',root));
assert.equal(hash(bytes),'befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db');
const table=Array.from({length:51000},(_,i)=>bytes.readUInt32LE(i*4));
const grid=Array.from({length:108},(_,i)=>Math.fround(Math.hypot(i%9,Math.floor(i/9))));
const gridBytes=Buffer.alloc(432);grid.forEach((v,i)=>gridBytes.writeFloatLE(v,i*4));
assert.equal(hash(gridBytes),'188bb55f439634304279bb566d74ad4adae19b4b405d524c830a5b540b085a9f');
assert.equal(oracle.unit,'R30-C');assert.equal(oracle.cases.length,160);
let draws=0,selectorEvents=0,writes=0;
const paths=new Map<string,number>();
for(const row of oracle.cases){
  const memory=new Memory();memory.seed(row.case);
  for(const [offset,value] of row.checkpoint.patches){assert.ok([0x8d4c,0x8d4d,0x8d4e].includes(offset));memory.match[offset]=value;}
  assert.equal(hash(memory.match),row.checkpoint.match_sha256,'original-produced checkpoint match memory');
  assert.equal(hash(memory.positions),row.checkpoint.positions_sha256,'checkpoint tactical memory');
  const state={...row.checkpoint.rng};
  const actual=composeAction33Segment30(row.checkpoint.input,memory,state,table,grid);
  assert.deepEqual(actual.selectorMemory,row.selector_memory,`selector operands case ${row.case.id}`);
  assert.deepEqual(memory.writes,row.game_writes,`all game-region writes case ${row.case.id}`);
  assert.deepEqual(actual.calls,row.calls,`projected calls case ${row.case.id}`);
  assert.deepEqual(actual.draws,row.draws,`every shared RNG call case ${row.case.id}`);
  const {selectorMemory,calls,draws:actualDraws,gridIndex,...result}=actual;
  assert.deepEqual(result,row.result,`semantic output case ${row.case.id}`);
  assert.deepEqual(state,row.final_rng,`final RNG case ${row.case.id}`);
  assert.equal(hash(memory.match),row.final_memory_sha256.match,'entire match region');
  assert.equal(hash(memory.positions),row.final_memory_sha256.positions,'entire tactical region');
  assert.ok(table.every((v,i)=>v===bytes.readUInt32LE(i*4)),'entire RNG table unchanged');
  assert.ok(grid.every((v,i)=>v===gridBytes.readFloatLE(i*4)),'entire grid unchanged');
  assert.equal(hash(bytes),row.final_memory_sha256.random_table);assert.equal(hash(gridBytes),row.final_memory_sha256.grid);
  draws+=actualDraws.length;selectorEvents+=selectorMemory.length;writes+=memory.writes.length;
  paths.set(result.path,(paths.get(result.path)??0)+1);
}
assert.deepEqual({cases:160,selector_events:selectorEvents,game_writes:writes,draws},oracle.coverage);
assert.equal(hash(bytes),'befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db');
const first=oracle.cases[0],badMemory=new Memory();badMemory.seed(first.case);
for(const bad of [{action:0x35},{mode:4},{zeroLocalByte:1},{precisionBits:24}]){
  const state={...first.checkpoint.rng};
  assert.throws(()=>composeAction33Segment30({...first.checkpoint.input,...bad},badMemory,state,table,grid),RangeError);
  assert.deepEqual(state,first.checkpoint.rng);
}
const nullMemory=new Memory();nullMemory.seed(first.case);
for(let side=0;side<2;side++){
  nullMemory.put(MATCH+0xf59e+side*4,4,0);
  for(let i=0;i<20;i++)nullMemory.match[BASES[side]+i*STRIDE+0x19]=255;
}
const nullState={...first.checkpoint.rng};
assert.throws(()=>composeAction33Segment30(first.checkpoint.input,nullMemory,nullState,table,grid),/00702332/);
assert.deepEqual(nullState,first.checkpoint.rng,'null keeper stops before variant RNG');
console.log(JSON.stringify({status:'passed',node:process.version,cases:160,draws,selectorEvents,writes,paths:Object.fromEntries(paths),
  comparison:'original-entry-produced 007022fd checkpoint to 007024b4; semantic composition, no machine-stack/full-prefix equivalence'}));

import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {lookupCached41, globals41} from './engine-state-41.ts';
import type {Build41, Memory41} from './engine-state-41.ts';

const file = new URL('../evidence/engine-state-41-oracle.json', import.meta.url);
const raw = readFileSync(file);
const oracle = JSON.parse(raw.toString());
const sha = (data: Uint8Array) => createHash('sha256').update(data).digest('hex');
assert.equal(sha(raw),'13c5bded6db0af4c3584977a8c9835000efb0a2d59ccb0783513cb4db1836634',
  'regenerate the original-instruction oracle before accepting changed evidence');
const hx = (n: number) => n.toString(16).padStart(8, '0');
const PLAYER=0x200000, RECEIVER=0x210000, ROWS=0x220000, CACHE=0x230000;
class Memory implements Memory41 {
  bytes = new Map<number, number>();
  events: (number | string)[][] = [];
  put(address: number, width: number, value: number) {
    for (let i=0; i<width; i++) this.bytes.set(address+i, (value >>> (8*i)) & 255);
  }
  peek(address: number, width: number): number {
    let value=0;
    for (let i=0; i<width; i++) {
      const byte=this.bytes.get(address+i);
      if (byte===undefined) throw new RangeError('missing memory at '+hx(address+i));
      value += byte * 2 ** (8*i);
    }
    return value >>> 0;
  }
  read(site: number, address: number, width: number): number {
    const value=this.peek(address,width);
    this.events.push([hx(site),'read',hx(address),width,value]);
    return value;
  }
  write(site: number, address: number, width: number, value: number): void {
    this.events.push([hx(site),'write',hx(address),width,value]);
    this.put(address,width,value);
  }
  region(address: number, size: number): Uint8Array {
    return Uint8Array.from({length:size},(_,i)=>this.peek(address+i,1));
  }
}
function fixture(c: any) {
  const g=globals41[c.build as Build41], p=c.input, memory=new Memory();
  const row=ROWS+31*p.index;
  for (let i=0;i<31;i++) memory.put(row+i,1,0);
  memory.put(0,4,p.old_seh);
  memory.put(PLAYER,4,p.index);memory.put(PLAYER+0x61,4,0x240000);
  memory.put(RECEIVER,4,ROWS);memory.put(RECEIVER+4,4,CACHE);
  memory.put(row,4,p.date);memory.put(row+4,4,0x12345678);memory.put(row+0xe,4,p.mapping);
  memory.put(g.flags,1,p.flags);memory.put(g.count,4,p.count);memory.put(g.date,4,p.date);
  const rg=oracle.mapping.rng_globals[c.build], rs=p.shared_rng;
  memory.put(rg.cursor,4,rg.table+4*rs.cursorIndex);memory.put(rg.offset,4,rs.offset);
  memory.put(rg.limit,4,rg.table+4*50999);memory.put(rg.seed,4,rs.crtState);
  const rngBytes=()=>Uint8Array.from(['cursor','offset','limit','seed'].flatMap(k=>
    [...memory.region(rg[k],4)]));
  return {memory, rngBytes, shared:{rng:{...rs},x87Control:p.x87_control}};
}
function compare(c: any, changed?: (m: Memory, shared: any)=>void) {
  const {memory,shared,rngBytes}=fixture(c);
  changed?.(memory, shared);
  const originalMemory=new Map(memory.bytes), originalRng={...shared.rng};
  const boundaries: any[]=[];
  const got=lookupCached41(c.build,RECEIVER,PLAYER,c.initial.esp,memory,shared,b=>{
    boundaries.push({...b,site:hx(b.site),rng_sha256:sha(rngBytes()),
      row_sha256:sha(memory.region(ROWS+31*c.input.index,31))});
  });
  assert.equal(got.pointer,c.result.pointer,'returned cache pointer');
  assert.equal(got.mapping,c.result.mapping,'mapping');
  assert.equal(got.row,c.result.row,'selected row');
  assert.equal(got.stack,c.final.esp,'RET4');
  assert.equal(got.shared,shared,'same caller shared state object');
  assert.deepEqual(shared.rng,originalRng,'shared RNG unchanged');
  assert.deepEqual(shared.rng,c.result.rng,'original shared RNG state');
  assert.equal(shared.x87Control,c.result.x87_control,'x87 unchanged');
  assert.deepEqual(memory.events,c.events,'ordered original reads and writes');
  assert.deepEqual(boundaries,c.boundaries,'nested call/return state');
  assert.deepEqual(memory.bytes,originalMemory,'nonstack memory restored/unchanged');
}
assert.equal(oracle.schema,'reversal.engine-state-41.synthetic.v1');
assert.equal(oracle.cases.length,18);
assert.equal(oracle.instruction_steps,1566);
for(const c of oracle.cases) compare(c);
let negatives=0;
function reject(action:()=>void) {assert.throws(action);negatives++;}
const c=oracle.cases[1];
for(const field of ['pointer','mapping','row']) {
  const altered=structuredClone(c);altered.result[field]^=1;reject(()=>compare(altered));
}
const altered=structuredClone(c);altered.boundaries[1].rng_sha256='0'.repeat(64);reject(()=>compare(altered));
reject(()=>compare(c,m=>m.put(globals41.pinned.flags,1,6)));
reject(()=>compare(c,m=>m.put(globals41.pinned.date,4,c.input.date^1)));
reject(()=>compare(c,m=>m.put(PLAYER,4,0xffffffff)));
reject(()=>compare(c,m=>m.put(PLAYER+0x61,4,0)));
reject(()=>compare(c,m=>m.put(RECEIVER,4,0)));
reject(()=>compare(c,m=>m.bytes.delete(ROWS+31*c.input.index+0xe)));
reject(()=>compare(c,(_,s)=>{s.x87Control=0x7f;}));
console.log(JSON.stringify({unit:'R41-B',cases:oracle.cases.length,originalSteps:oracle.instruction_steps,
  negativeProbes:negatives,oracleSha256:sha(raw),
  scope:'synthetic separate lookup + cached-refresh call/return; no live state, effect or resolver join'}));

/** Private captured-boundary comparison. Never prints memory or player data. */
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
import {lookupCached41} from './engine-state-41.ts';
import type {Memory41} from './engine-state-41.ts';

const file=process.argv[2];
if (!file) throw new Error('pass the private original replay JSON under results/');
const raw=readFileSync(file), oracle=JSON.parse(raw.toString());
const sha=(data:Uint8Array)=>createHash('sha256').update(data).digest('hex');
const hx=(n:number)=>n.toString(16).padStart(8,'0');
assert.equal(oracle.schema,'reversal.engine-state-41.capture-replay.v1');
assert.equal(oracle.private,true);
assert.equal(oracle.source_capture_sha256,'5359421a6164e301f32a4f406cbebdbe9458d4fcede5fa259c7e977066e90271',
  'this comparison admits only the identified R41-A lookup capture');
assert.equal(oracle.cases.length,1);

class Memory implements Memory41 {
  bytes=new Map<number,number>();
  events:(string|number)[][]=[];
  constructor(regions:{address:number,hex:string}[]) {
    for(const region of regions) {
      const bytes=Buffer.from(region.hex,'hex');
      for(let k=0;k<bytes.length;k++) {
        const old=this.bytes.get(region.address+k);
        if(old!==undefined) assert.equal(old,bytes[k],'captured alias conflict');
        this.bytes.set(region.address+k,bytes[k]);
      }
    }
  }
  peek(address:number,width:number):number {
    let value=0;
    for(let k=0;k<width;k++) {
      const byte=this.bytes.get(address+k);
      if(byte===undefined) throw new RangeError('uncaptured memory');
      value+=byte*2**(8*k);
    }
    return value>>>0;
  }
  read(site:number,address:number,width:number):number {
    const value=this.peek(address,width);
    this.events.push([hx(site),'read',hx(address),width,value]);return value;
  }
  write(site:number,address:number,width:number,value:number) {
    this.events.push([hx(site),'write',hx(address),width,value]);
    for(let k=0;k<width;k++)this.bytes.set(address+k,(value>>>(8*k))&255);
  }
  region(address:number,size:number):Uint8Array {
    return Uint8Array.from({length:size},(_,k)=>this.peek(address+k,1));
  }
}

function compare(c:any) {
  const captured=c.capture, memory=new Memory(captured.regions);
  const before=new Map(memory.bytes);
  const shared={rng:{...captured.rng},x87Control:captured.x87_control,
    x87Status:captured.x87_status,x87Tag:captured.x87_tag};
  const beforeShared=structuredClone(shared);
  const rg=oracle.mapping.rng_globals.gdi;
  const rngBytes=()=>Uint8Array.from(['cursor','offset','limit','seed'].flatMap(k=>
    [...memory.region(rg[k],4)]));
  const boundaries:any[]=[];
  const got=lookupCached41('gdi',captured.receiver,captured.participant,c.initial.esp,memory,shared,b=>{
    boundaries.push({...b,site:hx(b.site),rng_sha256:sha(rngBytes()),
      row_sha256:sha(memory.region(captured.row,31))});
  });
  assert.equal(got.pointer,c.result.pointer,'original return pointer');
  assert.equal(got.mapping,c.result.mapping,'original mapping');
  assert.equal(got.row,c.result.row,'original row');
  assert.equal(got.stack,c.final.esp,'original RET4');
  assert.equal(got.shared,shared,'same shared-state object');
  assert.deepEqual(shared,beforeShared,'shared RNG/x87 metadata unchanged');
  assert.deepEqual(shared.rng,c.result.rng,'original final RNG');
  assert.deepEqual(memory.events,c.events,'ordered original memory effects');
  assert.deepEqual(boundaries,c.boundaries,'original nested call and return');
  assert.deepEqual(memory.bytes,before,'represented nonstack data unchanged');
  return {events:memory.events.length,boundaries:boundaries.length};
}
const c=oracle.cases[0], result=compare(c);
assert.equal(c.instruction_steps,85);
assert.equal(c.result.pointer,0);
assert.equal(c.result.mapping,-1);
let negatives=0;
function reject(mutate:(copy:any)=>void) {
  const altered=structuredClone(c);mutate(altered);assert.throws(()=>compare(altered));negatives++;
}
reject(c=>{c.result.pointer=1;});
reject(c=>{c.result.mapping=0;});
reject(c=>{c.result.rng.cursorIndex++;});
reject(c=>{c.boundaries[0].argument^=4;});
reject(c=>{c.events.splice(4,1);});
reject(c=>{c.capture.regions=c.capture.regions.filter((r:any)=>r.address!==0);});
console.log(JSON.stringify({unit:'R41-B-capture',cases:1,originalSteps:c.instruction_steps,
  orderedMemoryEvents:result.events,nestedBoundaries:result.boundaries,negativeProbes:negatives,
  originalReplaySha256:sha(raw),sourceCaptureSha256:oracle.source_capture_sha256,
  returnedNull:true,sharedStateUnchanged:true,liveReturnObserved:false}));

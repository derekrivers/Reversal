/** Reusable cached-lookup comparator. Inputs may contain private memory;
 * stdout and thrown messages deliberately contain no captured values.
 */
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {pathToFileURL} from 'node:url';
import {lookupCached41} from './engine-state-41.ts';
import type {Memory41} from './engine-state-41.ts';

const sha=(data:Uint8Array)=>createHash('sha256').update(data).digest('hex');
const hx=(n:number)=>n.toString(16).padStart(8,'0');
const rngGlobals={cursor:0xde0ea8,offset:0xde0ea4,limit:0xde16e0,seed:0xad5b80,table:0xaa139c};
function requireValue(ok:unknown, code:string):asserts ok {
  if(!ok)throw new Error(code);
}
function equal(actual:unknown, expected:unknown, code:string) {
  requireValue(isDeepStrictEqual(actual,expected),code);
}
class CapturedMemory implements Memory41 {
  bytes=new Map<number,number>();
  events:(string|number)[][]=[];
  constructor(regions:any[]) {
    requireValue(Array.isArray(regions)&&regions.length>0&&regions.length<=130,'regions');
    let total=0;
    for(const region of regions) {
      requireValue(Number.isInteger(region.address)&&region.address>=0&&
        typeof region.hex==='string'&&/^(?:[0-9a-fA-F]{2})+$/.test(region.hex),'region-shape');
      const bytes=Buffer.from(region.hex,'hex');total+=bytes.length;
      requireValue(bytes.length<=4096&&total<=65536&&region.address+bytes.length<=2**32,'region-budget');
      for(let k=0;k<bytes.length;k++) {
        const old=this.bytes.get(region.address+k);
        requireValue(old===undefined||old===bytes[k],'alias-conflict');
        this.bytes.set(region.address+k,bytes[k]);
      }
    }
  }
  peek(address:number,width:number):number {
    let value=0;
    for(let k=0;k<width;k++) {
      const byte=this.bytes.get(address+k);
      requireValue(byte!==undefined,'missing-memory');
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

function compareCase(c:any) {
  requireValue(c.build==='gdi'&&c.initial.eip===0x62e6e0,'entry');
  const captured=c.capture,memory=new CapturedMemory(captured.regions);
  equal(c.initial,captured.initial,'entry-state');
  requireValue(c.initial.ecx===captured.receiver&&
    memory.peek(c.initial.esp+4,4)===captured.participant,'entry-alias');
  requireValue(memory.peek(c.initial.esp,4)===0x6cf8f7&&c.final.eip===0x6cf8f7,'caller-return');
  const before=new Map(memory.bytes);
  const shared={rng:{...captured.rng},x87Control:captured.x87_control,
    x87Status:captured.x87_status,x87Tag:captured.x87_tag};
  const beforeShared=structuredClone(shared);
  equal(shared.rng,{
    cursorIndex:(memory.peek(rngGlobals.cursor,4)-rngGlobals.table)/4,
    offset:memory.peek(rngGlobals.offset,4),crtState:memory.peek(rngGlobals.seed,4),
  },'shared-rng-input');
  const rngBytes=()=>Uint8Array.from(['cursor','offset','limit','seed'].flatMap(k=>
    [...memory.region(rngGlobals[k as keyof typeof rngGlobals],4)]));
  const boundaries:any[]=[];
  const got=lookupCached41('gdi',captured.receiver,captured.participant,c.initial.esp,memory,shared,b=>{
    boundaries.push({...b,site:hx(b.site),rng_sha256:sha(rngBytes()),
      row_sha256:sha(memory.region(captured.row,31))});
  });
  equal(got.pointer,c.result.pointer,'return-pointer');
  equal(got.pointer,c.final.eax,'return-register');
  equal(got.mapping,c.result.mapping,'mapping');
  equal(got.row,c.result.row,'row');
  equal(got.stack,c.final.esp,'stack-cleanup');
  requireValue(got.shared===shared,'shared-object');
  equal(shared,beforeShared,'shared-state');
  equal(shared.rng,c.result.rng,'final-rng');
  equal(shared.x87Control,c.result.x87_control,'final-x87-control');
  requireValue(c.result.nonstack_memory_unchanged===true,'original-memory-restoration');
  for(const name of ['ebx','esi','edi','ebp'])equal(c.final[name],c.initial[name],'nonvolatile-register');
  equal(memory.events,c.events,'ordered-memory-effects');
  equal(boundaries,c.boundaries,'call-boundaries');
  equal(memory.bytes,before,'memory-restoration');
  requireValue(Number.isInteger(c.instruction_steps)&&c.instruction_steps>0&&
    c.instruction_steps===c.trace.length,'instruction-count');
  return {original_steps:c.instruction_steps,memory_events:memory.events.length,
    call_boundaries:boundaries.length,returned_null:got.pointer===0};
}

export function compareReplay41b2(oracle:any) {
  requireValue(oracle.schema==='reversal.engine-state-41.capture-replay.v1'&&oracle.private===true,'schema');
  requireValue(typeof oracle.source_capture_sha256==='string'&&
    /^[0-9a-f]{64}$/.test(oracle.source_capture_sha256),'capture-digest-shape');
  requireValue(oracle.mapping.specimens.gdi.sha256===
    '0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b','executable-identity');
  equal(oracle.mapping.rng_globals.gdi,rngGlobals,'rng-address-map');
  requireValue(Array.isArray(oracle.cases)&&oracle.cases.length>0&&oracle.cases.length<=32,'case-count');
  const cases=oracle.cases.map(compareCase);
  // These probes alter comparison evidence only, never the simulation inputs.
  // Run against every case so both null and nonnull results must detect changes.
  const rejected:string[]=[];
  const mutations:[string,(c:any)=>void][]=[
    ['return-pointer',c=>{c.result.pointer=(c.result.pointer^1)>>>0;}],
    ['mapping',c=>{c.result.mapping++;}],
    ['final-rng',c=>{c.result.rng.cursorIndex++;}],
    ['call-argument',c=>{c.boundaries[0].argument=(c.boundaries[0].argument^4)>>>0;}],
    ['memory-effect',c=>{c.events.splice(0,1);}],
    ['missing-fs-head',c=>{c.capture.regions=c.capture.regions.filter((r:any)=>r.address!==0);}],
  ];
  for(const [index,original] of oracle.cases.entries()) {
    for(const [name,mutate] of mutations) {
      const changed=structuredClone(original);mutate(changed);
      let refused=false;try{compareCase(changed);}catch{refused=true;}
      requireValue(refused,'altered-result-accepted');
      rejected.push(`${index}:${name}`);
    }
  }
  return {schema:'reversal.engine-state-41b2.comparison.v1',status:'matched',
    source_capture_sha256:oracle.source_capture_sha256,cases,
    altered_result_rejections:rejected,
    shared_rng_unchanged:true,live_return_observed:false};
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    requireValue(process.argv.length===3,'usage');
    const raw=readFileSync(process.argv[2]);
    requireValue(raw.length<=4*1024*1024,'input-budget');
    const result=compareReplay41b2(JSON.parse(raw.toString()));
    console.log(JSON.stringify({...result,original_replay_sha256:sha(raw)}));
  } catch {
    console.log(JSON.stringify({schema:'reversal.engine-state-41b2.comparison.v1',
      status:'rejected',stage:'typescript-comparison',code:'COMPARISON_REJECTED'}));
    process.exitCode=1;
  }
}

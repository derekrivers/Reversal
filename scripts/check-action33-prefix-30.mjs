#!/usr/bin/env node
// Retained original-execution evidence check. This is NOT a TypeScript port.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {strict as assert} from 'node:assert';
const root=new URL('../',import.meta.url);
const digest=b=>createHash('sha256').update(b).digest('hex');
const zipped=readFileSync(new URL('evidence/action33-prefix-30-oracle.bin',root));
assert.equal(digest(zipped),'08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f');
assert.equal(zipped.subarray(0,10).toString('hex'),'1f8b08000000000002ff');
const raw=gunzipSync(zipped),o=JSON.parse(raw);
// Python retains .0 on this schedule's integral float32 adjustments; JS does not.
assert.ok(raw.toString().replace(/(-?\d+)\.0(?=[,}])/g,'$1')===JSON.stringify(o)+'\n','no hidden whitespace or trailing data');
// The pinned digest also rejects additional gzip members/metadata. Recompression
// is not compared because Python and Node can use different zlib implementations.
function keys(v,names){assert.deepEqual(Object.keys(v).sort(),names.split(' ').sort());}
function hex(v,n=8){assert.match(v,new RegExp(`^[0-9a-f]{${n}}$`));}
function uint(v){assert.ok(Number.isSafeInteger(v)&&v>=0&&v<=0xffffffff);}
function registers(v){keys(v,'eax ebx ecx edx esi edi ebp esp');Object.values(v).forEach(uint);}
function state(v){keys(v,'cursorIndex offset crtState');uint(v.cursorIndex);assert.ok(v.cursorIndex<51000);uint(v.offset);uint(v.crtState);}
keys(o,'schema_version unit specimen_sha256 entry stop_before scope emulator synthetic_random_table_sha256 synthetic_grid_sha256 code_ranges static_read_ranges cases coverage');
assert.equal(o.unit,'R30-A');assert.equal(o.entry,'00702050');assert.equal(o.stop_before,'007024b4');
assert.equal(o.specimen_sha256,'0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86');
for(const r of o.code_ranges){keys(r,'start end_exclusive file_offset bytes sha256 instructions');hex(r.start);hex(r.end_exclusive);hex(r.file_offset);hex(r.sha256,64);uint(r.bytes);uint(r.instructions);}
for(const r of o.static_read_ranges){keys(r,'va bytes sha256');hex(r.va);hex(r.sha256,64);uint(r.bytes);}
assert.equal(o.cases.length,160);
const mainSites=['00702088','0070210b','00702193','007021e5','00702222','00702241','0070230c','007023e3','00702416'];
let steps=0,events=0,rngCalls=0;
for(let n=0;n<o.cases.length;n++){
 const r=o.cases[n];keys(r,'input initial_registers boundary_registers outgoing_argument_dwords boundary_fpcw boundary_fpsw boundary_fptag rng final_rng call_trace match_writes keeper_response_raw flags instruction_steps instruction_trace_sha256 memory_events ordered_memory_trace_sha256 memory_sha256');
 keys(r.input,'id side selector_mode precision_bits x y rating0_raw rating1_raw fallback_rating_raw counter_raw adjustment_float match_byte_raw clock_word quality cursor_index offset crt_state momentum state_byte');
 assert.equal(r.input.id,n);assert.equal(r.input.side,n%2);
 assert.equal(r.input.selector_mode,['cache','direct','invalidate','fallback','activity-reject'][Math.floor(n/2)%5]);
 assert.ok([53,64].includes(r.input.precision_bits));
 for(const [k,v] of Object.entries(r.input))if(k!=='selector_mode')assert.ok(Number.isFinite(v));
 registers(r.initial_registers);registers(r.boundary_registers);
 assert.equal(r.boundary_registers.esp,0x2008000-0x694-20);assert.equal(r.boundary_registers.ecx,0x4100000);
 assert.deepEqual(r.outgoing_argument_dwords,[r.initial_registers.ecx,0x6d,0,0x4100000,0]);
 assert.equal(r.boundary_fpcw,r.input.precision_bits===53?0x27f:0x37f);assert.equal(r.boundary_fptag,65535);
 assert.deepEqual(r.call_trace.filter(c=>mainSites.includes(c.site)).map(c=>c.site),mainSites);
 for(const c of r.call_trace){
  keys(c,'site target before args fpcw_before after fpcw_after'+(c.target==='0090cfc0'?' rng_initial rng_final':''));
  hex(c.site);hex(c.target);registers(c.before);registers(c.after);c.args.forEach(uint);
  for(const name of ['ebx','ebp','esi','edi'])assert.equal(c.before[name],c.after[name]);
  assert.equal(c.fpcw_before,c.fpcw_after);
  if(c.target==='0090cfc0'){state(c.rng_initial);state(c.rng_final);}
 }
 let cursor={cursorIndex:r.input.cursor_index,offset:r.input.offset,crtState:r.input.crt_state};
 assert.deepEqual(r.rng.slice(0,2).map(x=>[x.site,x.bound]),[['00702241',0],['007023e3',2]]);
 assert.ok([2,6,9].includes(r.rng.length));
 for(const draw of r.rng){keys(draw,'site bound value initial final');hex(draw.site);state(draw.initial);state(draw.final);assert.deepEqual(draw.initial,cursor);cursor=draw.final;assert.ok(Number.isInteger(draw.bound)&&Math.abs(draw.bound)<=65535);assert.ok(Number.isInteger(draw.value));if(draw.bound===0)assert.deepEqual(draw.initial,draw.final);}
 assert.deepEqual(cursor,r.final_rng);rngCalls+=r.rng.length;
 keys(r.flags,'00000014 00000019 0000001a 0000001c 00000020 00000025');Object.values(r.flags).forEach(uint);
 assert.equal(r.flags['00000020'],0);assert.equal(r.flags['00000025'],0);
 for(const w of r.match_writes){assert.equal(w.length,5);hex(w[0]);assert.equal(w[1],'write');hex(w[2]);assert.ok([1,2,4].includes(w[3]));uint(w[4]);}
 keys(r.memory_sha256,'match positions stack random_table grid');Object.values(r.memory_sha256).forEach(x=>hex(x,64));
 assert.equal(r.memory_sha256.random_table,o.synthetic_random_table_sha256);assert.equal(r.memory_sha256.grid,o.synthetic_grid_sha256);
 hex(r.instruction_trace_sha256,64);hex(r.ordered_memory_trace_sha256,64);steps+=r.instruction_steps;events+=r.memory_events;
}
assert.equal(steps,158784);assert.equal(events,66601);assert.equal(rngCalls,797);
assert.equal(o.coverage.instruction_steps,steps);assert.equal(o.coverage.memory_events,events);
assert.equal(o.coverage.covered_instruction_starts.length,662);
for(const a of o.coverage.covered_instruction_starts)hex(a);
for(const e of o.coverage.covered_edges){assert.equal(e.length,2);e.forEach(a=>hex(a));}
const sites=readFileSync(new URL('evidence/action33-prefix-30-sites.json',root));
assert.equal(digest(sites),'6744c3025127c5ff5aef691f9aa0e3001a2858982ac1affcf6b22c5b9abe26c6');
const s=JSON.parse(sites);assert.equal(s.admitted_instruction_count,808);assert.equal(s.all_admitted_native_operands_match,true);
console.log(JSON.stringify({status:'passed',node:process.version,cases:160,original_instruction_steps:steps,ordered_memory_events:events,rng_calls:rngCalls,
 scope:'retained original-entry prefix evidence and schema/privacy integrity; no TypeScript implementation comparison'}));

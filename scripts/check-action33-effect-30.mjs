#!/usr/bin/env node
// Retained incomplete original-execution frontier; no TypeScript effect model.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {strict as assert} from 'node:assert';
const root=new URL('../',import.meta.url),hash=b=>createHash('sha256').update(b).digest('hex');
const blob=readFileSync(new URL('evidence/action33-effect-30-oracle.bin',root));
assert.equal(hash(blob),'6d6e2cc15ec23077ecc1bb2a199fa37b5ebbe05c4465f3e2a1ad08ec5630c0fc');
assert.equal(blob.subarray(0,10).toString('hex'),'1f8b08000000000002ff');
const raw=gunzipSync(blob),o=JSON.parse(raw);assert.ok(raw.toString()===JSON.stringify(o)+'\n','canonical JSON payload');
const prefixBlob=readFileSync(new URL('evidence/action33-prefix-30-oracle.bin',root));
assert.equal(hash(prefixBlob),o.prefix_oracle_sha256);const baseline=JSON.parse(gunzipSync(prefixBlob));
const keys=(v,s)=>assert.deepEqual(Object.keys(v).sort(),s.split(' ').sort());
const hex=(v,n=8)=>assert.match(v,new RegExp(`^[0-9a-f]{${n}}$`));
const uint=v=>assert.ok(Number.isInteger(v)&&v>=0&&v<=0xffffffff);
const regs=v=>{keys(v,'eax ebx ecx edx esi edi ebp esp');Object.values(v).forEach(uint);};
const rng=v=>{keys(v,'cursorIndex offset crtState');Object.values(v).forEach(uint);assert.ok(v.cursorIndex<51000);};
function snapshot(v){keys(v,'registers fpcw fpsw fptag eflags rng cells memory_sha256');regs(v.registers);rng(v.rng);
 keys(v.cells,'00de1f60 00de1f5c 00de2798 00ad6c30 00b63d28');Object.values(v.cells).forEach(uint);
 keys(v.memory_sha256,'match positions stack random_table grid');Object.values(v.memory_sha256).forEach(x=>hex(x,64));}
keys(o,'schema_version unit specimen_sha256 prefix_baseline prefix_oracle_sha256 scope start stop_before unsupported_callee lookup_global_initialization cases coverage');
assert.equal(o.unit,'R30-B');assert.equal(o.start,'007024b4');assert.equal(o.stop_before,'0062ed99');assert.equal(o.unsupported_callee,'00944cff');
assert.equal(o.specimen_sha256,baseline.specimen_sha256);assert.equal(o.cases.length,160);
let steps=0,events=0,draws=0;
const siteCounts={};
for(const [n,r] of o.cases.entries()){
 keys(r,'prefix_case prefix_record_sha256 status effect_returned before after raw_effect_argument_dwords diagnostic_argument_dwords call_trace rng ordered_external_memory_events instruction_steps ordered_memory_events instruction_trace_sha256 ordered_memory_trace_sha256');
 assert.equal(r.prefix_case,n);hex(r.prefix_record_sha256,64);assert.equal(r.status,'stopped_before_unsupported_diagnostic_call');assert.equal(r.effect_returned,false);
 snapshot(r.before);snapshot(r.after);const b=baseline.cases[n];
 assert.deepEqual(r.before.registers,b.boundary_registers);assert.deepEqual(r.before.rng,b.final_rng);assert.deepEqual(r.before.memory_sha256,b.memory_sha256);
 assert.deepEqual(r.raw_effect_argument_dwords,b.outgoing_argument_dwords);
 assert.deepEqual(r.diagnostic_argument_dwords,[0x9e7f28,0,0,0x2007824,0x2007724]);assert.equal(r.after.registers.esp,0x2007708);
 assert.equal(r.after.cells['00b63d28'],0);assert.equal(r.before.cells['00b63d28'],0);
 for(const name of ['match','positions','random_table','grid'])assert.equal(r.before.memory_sha256[name],r.after.memory_sha256[name]);
 assert.equal(r.before.fpcw,r.after.fpcw);assert.equal(r.after.fptag,65535);
 const pending=[];
 for(const c of r.call_trace){
  keys(c,'site target before args fpcw_before returned'+(c.returned?' after fpcw_after':'')+(c.target==='0090cfc0'?' rng_initial rng_final':''));
  hex(c.site);hex(c.target);regs(c.before);c.args.forEach(uint);
  assert.ok(['006cfe10','0062ed70','0090cfc0'].includes(c.target));
  if(!c.returned)pending.push([c.site,c.target]);else{
   regs(c.after);assert.equal(c.before.esp,c.after.esp);for(const k of ['ebx','ebp','esi','edi'])assert.equal(c.before[k],c.after[k]);
   assert.equal(c.fpcw_before,c.fpcw_after);rng(c.rng_initial);rng(c.rng_final);
  }
 }
 assert.deepEqual(pending,[['007024b4','006cfe10'],['006cfec2','0062ed70']]);
 const lookup=r.call_trace.at(-1);assert.deepEqual(lookup.args,[0]);assert.equal(lookup.before.ecx,0);
 let state=r.before.rng;
 for(const d of r.rng){keys(d,'site bound value initial final');hex(d.site);rng(d.initial);rng(d.final);
  assert.deepEqual(d.initial,state);state=d.final;assert.ok(Number.isInteger(d.bound)&&d.bound>=0&&d.bound<=102);
  assert.ok(Number.isInteger(d.value));if(d.bound===0)assert.deepEqual(d.initial,d.final);siteCounts[d.site]=(siteCounts[d.site]??0)+1;}
 assert.deepEqual(state,r.after.rng);
 // Check the recorded dependent bounds and short-circuit branch order.
 let k=0;
 for(const sites of [['006cfe35','006cfe3b','006cfe50','006cfe5e','006cfe64'],['006cfe74','006cfe7a','006cfe8c','006cfe9a','006cfea0']]){
  let d=r.rng[k++];assert.deepEqual([d.site,d.bound],[sites[0],102]);const first=d.value;
  d=r.rng[k++];assert.deepEqual([d.site,d.bound],[sites[1],first]);
  if(d.value>50){d=r.rng[k++];assert.deepEqual([d.site,d.bound],[sites[2],3]);if(d.value!==0){d=r.rng[k++];assert.deepEqual([d.site,d.bound],[sites[3],76]);const bound=d.value;d=r.rng[k++];assert.deepEqual([d.site,d.bound],[sites[4],bound]);}}
 }
 assert.equal(k,r.rng.length);
 for(const e of r.ordered_external_memory_events){assert.equal(e.length,5);hex(e[0]);hex(e[2]);assert.ok(['read','write'].includes(e[1]));assert.equal(e[3],4);uint(e[4]);
  if(e[1]==='write')assert.ok(['00de1f60','00de1f5c','00ad6c30'].includes(e[2]));}
 hex(r.instruction_trace_sha256,64);hex(r.ordered_memory_trace_sha256,64);steps+=r.instruction_steps;events+=r.ordered_memory_events;draws+=r.rng.length;
}
assert.deepEqual([steps,events,draws],[27390,13793,764]);
assert.equal(o.coverage.covered_instruction_starts.length,101);assert.equal(o.coverage.covered_edges.length,115);assert.equal(o.coverage.effect_returns,0);
for(const site of ['006cfe35','006cfe3b','006cfe74','006cfe7a'])assert.equal(siteCounts[site],160);
const sites=readFileSync(new URL('evidence/action33-effect-30-sites.json',root));assert.equal(hash(sites),'e72a4d4747f6171f08620c83b9fdb6465427c5e9a72936107174981161172c1d');
assert.equal(JSON.parse(sites).admitted_instruction_count,115);
const receiptBytes=readFileSync(new URL('evidence/action33-effect-30-integrity.json',root));
assert.equal(hash(receiptBytes),'41f0a30117a36b5879c3a23523364e10b539b34007026b43adcc0ec577480401','integrity receipt SHA-256');
const receipt=JSON.parse(receiptBytes);
keys(receipt,'unit status specimen_sha256 sites_sha256 oracle_sha256 cases effect_returns diagnostic_stops integrity negative_checks privacy scope');
assert.equal(receipt.unit,'R30-B');assert.equal(receipt.status,'passed');
assert.equal(receipt.specimen_sha256,o.specimen_sha256);assert.equal(receipt.sites_sha256,hash(sites));assert.equal(receipt.oracle_sha256,hash(blob));
assert.deepEqual([receipt.cases,receipt.effect_returns,receipt.diagnostic_stops],[o.cases.length,0,o.cases.length]);
keys(receipt.negative_checks,'changed_PE independently_changed_native_operand changed_native_file invented_player_pointer invented_lookup_object normalized_fourth_dword crossing_diagnostic_boundary');
for(const message of Object.values(receipt.negative_checks))assert.ok(typeof message==='string'&&message.length>0,'negative rejection diagnostic');
console.log(JSON.stringify({status:'passed',node:process.version,cases:160,effect_returns:0,diagnostic_stops:160,additional_original_steps:steps,rng_calls:draws,
 scope:'retained original-execution frontier and schema/privacy checks; no effect completion or TypeScript comparison'}));

import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {swapBytes28,type SwapRegisters} from './sort-swap-28.ts';

if(Number(process.versions.node.split('.')[0])<24)throw new Error('Node 24+ required');
const PINNED='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const SITE_HASH='f3c6917724a2cc0a43bb38e3226bcb54dd9c67cf8c5269842bbd4a523437e3cc';
const ORACLE_HASH='4bf7359badc00d030a434d7e9df723deedc79e25feaefafc14ab217608c7b793';
const sha=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const raw=readFileSync(process.argv[2]??'evidence/sort-helpers-28-swap-oracle.json.gz');
if(sha(raw)!==ORACLE_HASH)throw new Error('oracle SHA-256 mismatch');
const siteRaw=readFileSync('evidence/sort-helpers-28-sites.json');
if(sha(siteRaw)!==SITE_HASH)throw new Error('site evidence SHA-256 mismatch');
const site=JSON.parse(siteRaw.toString());
const oracle=JSON.parse(gunzipSync(raw).toString());
const swap=site.functions.find((f:{entry_va:string})=>f.entry_va==='009454d5');
if(site.specimen_sha256!==PINNED||oracle.specimen_sha256!==PINNED||oracle.sites_sha256!==SITE_HASH||
   oracle.cases_count!==640||oracle.executed_instruction_steps!==47768||
   site.functions.length!==2||site.functions[0].instruction_count!==39||site.functions[0].local_edge_count!==42||
   swap.instruction_count!==23||swap.local_edge_count!==25||oracle.covered_instruction_starts.length!==23||oracle.covered_edges.length!==25)
  throw new Error('provenance/coverage mismatch');
type Input={seed:number;width:number;delta:number;first:number};
type Row={input:Input;initial:SwapRegisters;final:SwapRegisters;events:(string|number)[][];trace:string[];data_sha256:string;stack_sha256:string};
const rows=oracle.cases as Row[];
if(rows.length!==640)throw new Error('case count mismatch');
const widths=[0,1,2,3,4,7,8,15,16,31],deltas=[0,1,2,3,7,16,32,64];
const inputs:Input[]=[];
for(let seed=0;seed<8;seed++)for(const width of widths)for(const delta of deltas)
  inputs.push({seed,width,delta,first:0x300100});
const covered=new Set<string>(),edges=new Set<string>();let steps=0;
for(const [index,row] of rows.entries()){
  if(JSON.stringify(row.input)!==JSON.stringify(inputs[index]))throw new Error(`input schedule mismatch ${index}`);
  const {seed,width,delta,first}=row.input,second=first+delta;
  const data=Uint8Array.from({length:0x1000},(_,i)=>(i*37+seed*23+7)&255);
  const stack=Uint8Array.from({length:0x1000},(_,i)=>(i*19+seed*11+5)&255);
  const sv=new DataView(stack.buffer);const esp=0x400800;
  sv.setUint32(0x800,0x700000,true);sv.setUint32(0x804,first,true);
  sv.setUint32(0x808,second,true);sv.setUint32(0x80c,width,true);
  sv.setUint32(0x7fc,row.initial.esi,true);
  if(first!==second&&width!==0)sv.setUint32(0x7f8,row.initial.ebx,true);
  const events:(string|number)[][]=[];
  const mapped=(address:number)=>{
    if(!Number.isInteger(address)||address<0x300000||address>=0x301000)throw new RangeError('unmapped byte');
    return address-0x300000;
  };
  const memory={read8(address:number){const value=data[mapped(address)];events.push(['read',address.toString(16).padStart(8,'0'),1,value]);return value;},
                write8(address:number,value:number){events.push(['write',address.toString(16).padStart(8,'0'),1,value&255]);data[mapped(address)]=value&255;}};
  const got=swapBytes28(first,second,width,row.initial,memory);
  if(process.argv[3]==='--mutate-result'&&index===0)got.eax^=1;
  if(process.argv[3]==='--mutate-effect'&&index===89)events.pop();
  for(const name of ['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'] as const)
    if(got[name]!==row.final[name])throw new Error(`register mismatch ${index} ${name}`);
  if(JSON.stringify(events)!==JSON.stringify(row.events))throw new Error(`ordered effect mismatch ${index}`);
  if(sha(data)!==row.data_sha256||sha(stack)!==row.stack_sha256)throw new Error(`full memory mismatch ${index}`);
  if(row.initial.esp!==esp||row.initial.eip!==0x9454d5||row.final.esp!==esp+4||row.final.eip!==0x700000)
    throw new Error(`ABI mismatch ${index}`);
  if(row.trace[0]!=='009454d5'||row.trace.at(-1)!=='00945500')throw new Error(`entry/return trace mismatch ${index}`);
  for(const addr of row.trace)covered.add(addr);
  for(let j=0;j+1<row.trace.length;j++)edges.add(`${row.trace[j]}:${row.trace[j+1]}`);
  steps+=row.trace.length;
}
if(steps!==47768||JSON.stringify([...covered].sort())!==JSON.stringify(oracle.covered_instruction_starts))throw new Error('trace coverage mismatch');
const edgeList=[...edges].sort();
if(JSON.stringify(edgeList)!==JSON.stringify(swap.edges.map(([a,b]:string[])=>`${a}:${b}`).sort())||
   JSON.stringify(edgeList)!==JSON.stringify(oracle.covered_edges.map(([a,b]:string[])=>`${a}:${b}`).sort()))
  throw new Error('CFG edge coverage mismatch');
const noop={read8:()=>{throw new Error('unexpected read');},write8:()=>{throw new Error('unexpected write');}};
for(const [first,second,width] of [[0x300100,0x300100,31],[0x300100,0x300140,0]])
  swapBytes28(first,second,width,rows[0].initial,noop);
for(const [first,second,width] of [[0x300100,0x300140,32],[-1,0,1],[0,0,NaN],
  [0x300100,0x4007fc,1],[0x300100,0x9454d5,1],[0x300fff,0x300100,2],[0,0,0]]){
  let rejected=false;try{swapBytes28(first,second,width,rows[0].initial,noop);}catch(e){rejected=e instanceof RangeError;}
  if(!rejected)throw new Error('unsupported input accepted');
}
const malformed={...rows[0].initial};delete (malformed as Partial<SwapRegisters>).edx;
let rejected=false;try{swapBytes28(0x300100,0x300140,1,malformed,noop);}catch(e){rejected=e instanceof RangeError;}
if(!rejected)throw new Error('missing register accepted');
rejected=false;try{swapBytes28(0x300100,0x300140,1,{...rows[0].initial,eip:0},noop);}catch(e){rejected=e instanceof RangeError;}
if(!rejected)throw new Error('unsupported entry accepted');
console.log(`R28-A swap: ${rows.length} original-entry cases, ${steps} x86 steps, ${covered.size} instructions / ${edges.size} edges; ordered data effects, full data/stack memory and ABI match.`);

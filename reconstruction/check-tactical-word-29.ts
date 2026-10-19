import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {tacticalWordEntry,type TacticalRegisters} from './tactical-word-29.ts';

if(Number(process.versions.node.split('.')[0])<24)throw new Error('Node 24+ required');
const PINNED='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const SITE_HASH='1519e5d58bafdfb8afeb0c2a42ae6ba4b21f93377baf13096a7cfc90601311c3';
const ORACLE_HASH='b975e6fe5f2fc97a7157f40e2e6a0fd870547287aa320a9502c3a108ae5c3fab';
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const siteRaw=readFileSync('evidence/tactical-word-29-sites.json');
const oracleRaw=readFileSync(process.argv[2]??'evidence/tactical-word-29-oracle.json.gz');
if(hash(siteRaw)!==SITE_HASH||hash(oracleRaw)!==ORACLE_HASH)throw new Error('sealed evidence SHA-256 mismatch');
const site=JSON.parse(siteRaw.toString('utf8'));
const oracle=JSON.parse(gunzipSync(oracleRaw).toString('utf8'));
if(site.specimen_sha256!==PINNED||oracle.specimen_sha256!==PINNED||
   oracle.sites_sha256!==SITE_HASH||oracle.cases_count!==610||
   site.functions.length!==2||site.functions.some((f:{body_bytes:number;instruction_count:number;matched_native_instructions:number})=>
     f.body_bytes!==42||f.instruction_count!==13||f.matched_native_instructions!==13))
  throw new Error('provenance or static coverage mismatch');
type Input={entry:string;index:number;side:number;seed:number};
type Row={input:Input;initial:TacticalRegisters;final:TacticalRegisters;
  events:(string|number)[][];trace:string[];memory_sha256:string[]};
const rows=oracle.cases as Row[];
const schedule:Input[]=[];
const sides=[0x80,0xfe,0xff,0,1,2,0x7f];
for(const entry of [0x6c38c0,0x6c38f0]){
  const label=entry.toString(16).padStart(8,'0');
  for(let index=0;index<256;index++)schedule.push({entry:label,index,side:sides[index%sides.length],seed:index%4});
  for(const side of sides)for(const index of [0,1,10,11,0x7f,0x80,0xff])
    schedule.push({entry:label,index,side,seed:(side+index)%4});
}
if(rows.length!==schedule.length||rows.length!==610)throw new Error('case count mismatch');
const hex=(n:number)=>n.toString(16).padStart(8,'0');
let steps=0;const starts=new Set<string>();const edges=new Set<string>();
for(const [at,row] of rows.entries()){
  const input=row.input;
  if(Object.entries(schedule[at]).some(([k,v])=>input[k as keyof Input]!==v))
    throw new Error(`input schedule mismatch ${at}`);
  const pages=[[0x300000,0x10000,13,17,7],[0x400000,0x1000,29,11,3],
    [0x500000,0x1000,37,23,5],[0x600000,0x1000,19,31,9]].map(([base,length,mul,seedMul,add])=>
      ({base,bytes:Uint8Array.from({length},(_,i)=>(i*mul+input.seed*seedMul+add)&255)}));
  const locate=(address:number,width:number)=>{
    const p=pages.find(p=>address>=p.base&&address+width<=p.base+p.bytes.length);
    if(!p)throw new RangeError(`unmapped synthetic memory ${hex(address)}`);
    return {p,at:address-p.base};
  };
  const put=(address:number,width:number,value:number)=>{
    const {p,at}=locate(address,width);
    if(width===1)p.bytes[at]=value&255;
    else new DataView(p.bytes.buffer).setUint32(at,value>>>0,true);
  };
  put(0x400019,1,input.index);put(0x400027,1,input.side);
  const signed=input.side<128?input.side:input.side-256;
  const offset=Number.parseInt(input.entry,16)===0x6c38c0?0x8ebc:0x8ec4;
  put(0x300000+offset+signed*4,4,0x500400);
  put(0x600800,4,0x700000);put(0x600804,4,0x400000);
  const events:(string|number)[][]=[];
  const read=(address:number,width:number)=>{
    const {p,at}=locate(address,width);events.push(['read',hex(address),width]);
    const view=new DataView(p.bytes.buffer);
    return width===1?view.getUint8(at):width===2?view.getUint16(at,true):view.getUint32(at,true);
  };
  const got=tacticalWordEntry(Number.parseInt(input.entry,16),row.initial,{
    read8:(address)=>read(address,1),read16:(address)=>read(address,2),read32:(address)=>read(address,4)});
  if(process.argv[3]==='--mutate-result'&&at===0)got.eax^=1;
  if(process.argv[3]==='--mutate-effect'&&at===0)events.pop();
  if(Object.keys(row.final).some(name=>got[name as keyof TacticalRegisters]!==row.final[name as keyof TacticalRegisters]))
    throw new Error(`full register mismatch ${at}`);
  if(JSON.stringify(events)!==JSON.stringify(row.events))throw new Error(`ordered memory events mismatch ${at}`);
  if(JSON.stringify(pages.map(p=>hash(p.bytes)))!==JSON.stringify(row.memory_sha256))
    throw new Error(`full admitted memory mismatch ${at}`);
  if(row.initial.ecx!==0x300000||row.initial.esp!==0x600800||
     row.final.eip!==0x700000||row.final.esp!==0x600808||
     (got.eax&0xffff)!==(row.final.eax&0xffff))throw new Error(`ABI mismatch ${at}`);
  for(const address of row.trace)starts.add(address);
  for(let i=0;i+1<row.trace.length;i++)edges.add(`${row.trace[i]}:${row.trace[i+1]}`);
  steps+=row.trace.length;
}
if(steps!==oracle.executed_instruction_steps||starts.size!==26||
   JSON.stringify([...starts].sort())!==JSON.stringify(oracle.covered_instruction_starts))
  throw new Error('instruction coverage mismatch');
const expected=site.functions.flatMap((f:{edges:string[][]})=>f.edges.map(([a,b])=>`${a}:${b}`)).sort();
if(JSON.stringify([...edges].sort())!==JSON.stringify(expected)||
   JSON.stringify([...edges].sort())!==JSON.stringify(oracle.covered_edges.map(([a,b]:string[])=>`${a}:${b}`).sort()))
  throw new Error('CFG coverage mismatch');
let unsupported=false;try{tacticalWordEntry(0x6c3920,rows[0].initial,{read8:()=>0,read16:()=>0,read32:()=>0});}
catch(e){unsupported=e instanceof RangeError;}if(!unsupported)throw new Error('unsupported entry accepted');
console.log(JSON.stringify({checked_cases:rows.length,executed_instruction_steps:steps,
  covered_instruction_starts:starts.size,covered_edges:edges.size,synthetic_only:true}));

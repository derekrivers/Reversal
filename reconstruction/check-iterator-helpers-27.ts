import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {advanceIterator} from './iterator-helpers-27.ts';

if(Number(process.versions.node.split('.')[0])<24)throw new Error('Node 24+ required');
const ORACLE_HASH='4dd3a87503c2740052162b9cc8cd65f2a0f1ae4827e012737c0d536fe2a538f0';
const SITE_HASH='dc7b69cb999cab05d0c819e8c63ab30100684a342db4c75e47a640207f0edb64';
const PINNED='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const raw=readFileSync(process.argv[2]??'evidence/iterator-helpers-27-oracle.json.gz');
if(hash(raw)!==ORACLE_HASH)throw new Error('oracle SHA-256 mismatch');
const siteRaw=readFileSync('evidence/iterator-helpers-27-sites.json');
if(hash(siteRaw)!==SITE_HASH)throw new Error('site evidence SHA-256 mismatch');
const site=JSON.parse(siteRaw.toString('utf8'));
const oracle=JSON.parse(gunzipSync(raw).toString('utf8'));
if(oracle.specimen_sha256!==PINNED||site.specimen_sha256!==PINNED||
   oracle.sites_sha256!==SITE_HASH||oracle.cases_count!==800||
   oracle.executed_instruction_steps!==5536||oracle.covered_instruction_starts.length!==18||
   site.functions.length!==2||site.functions.some((f:{instruction_count:number;matched_native_instructions:number;body_bytes:number})=>
     f.instruction_count!==9||f.matched_native_instructions!==9||f.body_bytes!==19))
  throw new Error('provenance/coverage mismatch');

type Input={entry:string;link_offset:number;seed:number;cursor:number;payload:number;next:number};
type Row={input:Input;initial:Record<string,number>;final:Record<string,number>;
  events:(string|number)[][];trace:string[];memory_sha256:string[]};
const rows=oracle.cases as Row[];
if(rows.length!==800)throw new Error('fixture count mismatch');
const expectedInputs:Input[]=[];
const values=[0,1,0x12345678,0x7fffffff,0x80000000,0xffffffff];
const links=[0,0x300200,0x7fffffff,0xffffffff];
for(const [entry,offset] of [[0x68d1b0,6],[0x68d1d0,10]]){
  for(let seed=0;seed<16;seed++)expectedInputs.push({entry:entry.toString(16).padStart(8,'0'),link_offset:offset,seed,cursor:0,payload:0,next:0});
  for(let seed=0;seed<16;seed++)for(const payload of values)for(const next of links)
    expectedInputs.push({entry:entry.toString(16).padStart(8,'0'),link_offset:offset,seed,cursor:0x300100,payload,next});
}
let steps=0;const covered=new Set<string>();const edges=new Set<string>();
for(const [index,row] of rows.entries()){
  const input=row.input;
  if(Object.entries(expectedInputs[index]).some(([key,value])=>input[key as keyof Input]!==value))
    throw new Error(`input schedule mismatch ${index}`);
  const pages=[0x200000,0x300000].map((base,which)=>({base,bytes:Uint8Array.from({length:0x1000},(_,i)=>
    which===0?(i*29+input.seed*17+3)&255:(i*37+input.seed*23+7)&255)}));
  const locate=(address:number)=>{
    const page=pages.find(p=>address>=p.base&&address+4<=p.base+0x1000);
    if(!page)throw new RangeError('unmapped synthetic DWORD');
    return {page,offset:address-page.base};
  };
  const put=(address:number,value:number)=>{
    const {page,offset}=locate(address);new DataView(page.bytes.buffer).setUint32(offset,value>>>0,true);
  };
  put(0x20000a,input.cursor);
  if(input.cursor){put(input.cursor,input.payload);put(input.cursor+input.link_offset,input.next);}
  const effects:(string|number)[][]=[];
  const memory={
    read32(address:number){const {page,offset}=locate(address);effects.push(['read',address.toString(16).padStart(8,'0'),4]);
      return new DataView(page.bytes.buffer).getUint32(offset,true);},
    write32(address:number,value:number){const {page,offset}=locate(address);
      effects.push(['write',address.toString(16).padStart(8,'0'),4,value>>>0]);
      new DataView(page.bytes.buffer).setUint32(offset,value>>>0,true);}
  };
  const got=advanceIterator(Number.parseInt(input.entry,16),0x200000,memory);
  if(process.argv[3]==='--mutate-result'&&index===0)got.eax^=1;
  if(process.argv[3]==='--mutate-effect'&&index===16)effects.pop();
  if(['eax','ecx','edx'].some(name=>got[name as 'eax'|'ecx'|'edx']!==row.final[name]))
    throw new Error(`return register mismatch ${index}`);
  if(JSON.stringify(effects)!==JSON.stringify(row.events))throw new Error(`ordered effects mismatch ${index}`);
  if(JSON.stringify(pages.map(p=>hash(p.bytes)))!==JSON.stringify(row.memory_sha256))
    throw new Error(`full memory mismatch ${index}`);
  if(row.initial.ecx!==0x200000||row.initial.esp!==0x400800||row.final.esp!==0x400804||
     row.final.eip!==0x700000||['ebx','esi','edi','ebp'].some(n=>row.final[n]!==row.initial[n]))
    throw new Error(`ABI mismatch ${index}`);
  if(row.trace[0]!==input.entry||!['0068d1bf','0068d1c2','0068d1df','0068d1e2'].includes(row.trace.at(-1)!))
    throw new Error(`entry/return trace mismatch ${index}`);
  for(const address of row.trace)covered.add(address);
  for(let n=0;n+1<row.trace.length;n++)edges.add(`${row.trace[n]}:${row.trace[n+1]}`);
  steps+=row.trace.length;
}
if(steps!==5536||JSON.stringify([...covered].sort())!==JSON.stringify(oracle.covered_instruction_starts))
  throw new Error('trace coverage mismatch');
const nativeEdges=site.functions.flatMap((f:{edges:string[][]})=>f.edges.map(([a,b])=>`${a}:${b}`)).sort();
if(JSON.stringify([...edges].sort())!==JSON.stringify(nativeEdges)||
   JSON.stringify([...edges].sort())!==JSON.stringify(oracle.covered_edges.map(([a,b]:string[])=>`${a}:${b}`).sort()))
  throw new Error('native/oracle CFG edge coverage mismatch');
for(const entry of [0x68d1b0,0x68d1d0]){
  let reads=0;
  const nullMemory={read32:()=>{reads++;return 0;},write32:()=>{throw new Error('null cursor wrote');}};
  const result=advanceIterator(entry,0x200000,nullMemory);
  if(reads!==1||result.eax!==0||result.edx!==0)throw new Error('null cursor contract mismatch');
}
for(const invalid of [0,0x68d1c0,0x68d1f0]){
  let rejected=false;try{advanceIterator(invalid,0x200000,{read32:()=>0,write32:()=>{}});}
  catch(e){rejected=e instanceof RangeError;}
  if(!rejected)throw new Error('unsupported entry accepted');
}
console.log(JSON.stringify({checked_cases:rows.length,executed_instruction_steps:steps,
  covered_instruction_starts:covered.size,covered_edges:edges.size,synthetic_only:true}));

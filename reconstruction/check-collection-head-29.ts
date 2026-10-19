import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {readCurrentCollectionPayload} from './collection-head-29.ts';

if(Number(process.versions.node.split('.')[0])<24)throw new Error('Node 24+ required');
const PINNED='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const SITE_HASH='7df90b7f1fa9cbe246e85d6b2d829098c7f7ddaf9350a2801ca88d8ec2aa820b';
const ORACLE_HASH='61ad24b654668d3b9a7f9c797fc5a7315d9d8068c09316b9834329b21553b3eb';
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const sitesRaw=readFileSync('evidence/collection-continuation-29-sites.json');
const oracleRaw=readFileSync(process.argv[2]??'evidence/collection-continuation-29-oracle.json');
if(hash(sitesRaw)!==SITE_HASH||hash(oracleRaw)!==ORACLE_HASH)throw new Error('site/oracle SHA-256 mismatch');
const sites=JSON.parse(sitesRaw.toString('utf8'));
const oracle=JSON.parse(oracleRaw.toString('utf8'));
const getter=sites.bodies?.['0068d2e0'];
if(sites.specimen_sha256!==PINNED||oracle.specimen_sha256!==PINNED||
   oracle.sites_sha256!==SITE_HASH||getter?.body_bytes!==13||
   getter?.instruction_count!==7||getter?.direct_calls.length!==0||
   oracle.cases_count!==1024||oracle.executed_instruction_steps!==5120||oracle.cases.length!==1024)
  throw new Error('provenance or static body mismatch');
const offsets=[0,1,2,3,7,15,31,63,127,255,511,1023,1535,2047,3071,4082];
const regs=['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'];
const seen=new Set<string>(),edges=new Set<string>();let steps=0;
for(let index=0;index<1024;index++){
  const mode=Math.floor(index/256),seed=Math.floor(index/16)%16,offset=offsets[index%16];
  const receiver=0x200000+offset;
  const cursor=mode===0?0:(mode===1?receiver:0x200800+((seed*31+offset)%0x7f0));
  const row=oracle.cases[index];
  if(JSON.stringify(row.input)!==JSON.stringify({mode,seed,offset,receiver,cursor}))
    throw new Error(`input schedule mismatch ${index}`);
  const pages=[
    {base:0x200000,bytes:Uint8Array.from({length:0x1000},(_,i)=>(i*29+seed*17+mode*11+3)&255)},
    {base:0x400000,bytes:Uint8Array.from({length:0x1000},(_,i)=>(i*19+seed*13+5)&255)}
  ];
  const locate=(address:number,width:number)=>{
    const page=pages.find(p=>address>=p.base&&address+width<=p.base+0x1000);
    if(!page)throw new RangeError('unmapped synthetic memory');
    return {page,offset:address-page.base};
  };
  const set32=(address:number,value:number)=>{const {page,offset}=locate(address,4);
    new DataView(page.bytes.buffer).setUint32(offset,value>>>0,true);};
  set32(receiver+10,cursor);
  if(cursor&&mode>=2)set32(cursor,(seed*0x10203041+mode*0x80000001+offset)>>>0);
  set32(0x400800,0x700000);
  const initial:Record<string,number>={
    eax:(0xdeadbeef+seed*0x10101+offset)>>>0,ebx:(0x87654321^seed)>>>0,
    ecx:receiver,edx:(0x12345678^offset)>>>0,esi:(0x01020304^seed)>>>0,
    edi:(0xfeedface^offset)>>>0,ebp:(0xcafef00d^mode)>>>0,
    esp:0x400800,eip:0x68d2e0
  };
  for(const name of regs)if(row.initial[name]!==initial[name]||!Object.hasOwn(row.final,name))
    throw new Error(`initial ABI mismatch ${index}:${name}`);
  const events:(string|number)[][]=[];
  const memory={read32(address:number){const {page,offset}=locate(address,4);
    events.push(['read',address.toString(16).padStart(8,'0'),4]);
    return new DataView(page.bytes.buffer).getUint32(offset,true);}};
  const got=readCurrentCollectionPayload(receiver,0x400800,memory);
  if(process.argv[3]==='--mutate-result'&&index===0)got.eax^=1;
  if(process.argv[3]==='--mutate-effect'&&index===0)events.reverse();
  if(process.argv[3]==='--mutate-memory'&&index===0)pages[0].bytes[0]^=1;
  if(process.argv[3]==='--mutate-abi'&&index===0)row.final.ebx^=1;
  const final={...initial,...got};
  for(const name of regs)if(final[name]!==row.final[name])
    throw new Error(`final ABI mismatch ${index}:${name}`);
  if(JSON.stringify(events)!==JSON.stringify(row.events))
    throw new Error(`ordered effects mismatch ${index}`);
  if(JSON.stringify(pages.map(p=>hash(p.bytes)))!==JSON.stringify(row.memory_sha256))
    throw new Error(`complete memory mismatch ${index}`);
  const trace=cursor?['0068d2e0','0068d2e3','0068d2e5','0068d2e7','0068d2e9']:
    ['0068d2e0','0068d2e3','0068d2e5','0068d2ea','0068d2ec'];
  if(JSON.stringify(row.trace)!==JSON.stringify(trace))throw new Error(`trace mismatch ${index}`);
  for(const start of trace)seen.add(start);
  for(let i=0;i+1<trace.length;i++)edges.add(`${trace[i]}:${trace[i+1]}`);
  steps+=trace.length;
}
const oracleEdges=oracle.covered_edges.map(([a,b]:string[])=>`${a}:${b}`).sort();
if(steps!==5120||seen.size!==7||edges.size!==6||
   JSON.stringify([...seen].sort())!==JSON.stringify(oracle.covered_instruction_starts)||
   JSON.stringify([...edges].sort())!==JSON.stringify(oracleEdges))
  throw new Error('instruction/CFG coverage mismatch');
for(const bad of [-1,0xfffffff3,0x100000000]){
  let rejected=false;try{readCurrentCollectionPayload(bad,0x400800,{read32:()=>0});}
  catch(e){rejected=e instanceof RangeError;}
  if(!rejected)throw new Error('invalid receiver accepted');
}
for(const bad of [-1,0xfffffffd,0x100000000]){
  let rejected=false;try{readCurrentCollectionPayload(0x200000,bad,{read32:()=>0});}
  catch(e){rejected=e instanceof RangeError;}
  if(!rejected)throw new Error('invalid stack accepted');
}
console.log(JSON.stringify({checked_cases:1024,executed_instruction_steps:steps,
  covered_instruction_starts:seen.size,covered_edges:edges.size,synthetic_only:true}));

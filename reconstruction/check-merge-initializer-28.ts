import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {initializeMergeHeader} from './merge-initializer-28.ts';

if(Number(process.versions.node.split('.')[0])<24)throw new Error('Node 24+ required');
const PINNED='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
const SITE_HASH='a89054f25cd4c6ca54ad10b5d3c193a25b41fc858b56d32048a3d3209617c2a5';
const ORACLE_HASH='b8b7bd2c391875b67acb74477ae4632674d3a84a5bb16a7a9e7aa75fba183457';
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const sitesRaw=readFileSync('evidence/merge-dependencies-28-sites.json');
const oracleRaw=readFileSync(process.argv[2]??'evidence/merge-initializer-28-oracle.json.gz');
if(hash(sitesRaw)!==SITE_HASH||hash(oracleRaw)!==ORACLE_HASH)throw new Error('site/oracle SHA-256 mismatch');
const sites=JSON.parse(sitesRaw.toString('utf8'));
const oracle=JSON.parse(gunzipSync(oracleRaw).toString('utf8'));
if(sites.specimen_sha256!==PINNED||oracle.specimen_sha256!==PINNED||
   oracle.sites_sha256!==SITE_HASH||sites.functions.length!==2||
   sites.functions[0].entry_va!=='0068d020'||sites.functions[0].body_bytes!==17||
   sites.functions[0].instruction_count!==7||sites.functions[0].matched_native_instructions!==7||
   sites.functions[0].calls.length!==0||sites.functions[1].entry_va!=='0068d0d0'||
   sites.functions[1].body_bytes!==221||sites.functions[1].instruction_count!==71||
   sites.functions[1].matched_native_instructions!==71||sites.functions[1].calls.length!==4||
   oracle.cases_count!==256||oracle.executed_instruction_steps!==1792||oracle.cases.length!==256)
  throw new Error('provenance, static body or case count mismatch');
const offsets=[0,1,2,3,4,5,7,8,15,16,31,63,127,255,511,0x7f0];
const expectedTrace=['0068d020','0068d022','0068d024','0068d027','0068d02a','0068d02d','0068d030'];
const regNames=['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'];
const edgeSet=new Set<string>();const starts=new Set<string>();let steps=0;
for(let index=0;index<256;index++){
  const row=oracle.cases[index];
  const seed=Math.floor(index/16),offset=offsets[index%16],receiver=0x200100+offset;
  if(row.input.seed!==seed||row.input.offset!==offset||row.input.receiver!==receiver)
    throw new Error(`input schedule mismatch ${index}`);
  const pages=[
    {base:0x200000,bytes:Uint8Array.from({length:0x1000},(_,i)=>(i*29+seed*17+3)&255)},
    {base:0x400000,bytes:Uint8Array.from({length:0x1000},(_,i)=>(i*19+seed*11+5)&255)}
  ];
  const locate=(address:number,width:number)=>{
    const page=pages.find(p=>address>=p.base&&address+width<=p.base+0x1000);
    if(!page)throw new RangeError('unmapped synthetic memory');
    return {page,offset:address-page.base};
  };
  new DataView(pages[1].bytes.buffer).setUint32(0x800,0x700000,true);
  const initial:Record<string,number>={
    eax:(0xdeadbeef+seed*0x10101+offset)>>>0,ebx:(0x87654321^seed)>>>0,
    ecx:receiver,edx:(0x12345678^offset)>>>0,esi:(0x01020304^seed)>>>0,
    edi:(0xfeedface^offset)>>>0,ebp:(0xcafef00d^seed)>>>0,
    esp:0x400800,eip:0x68d020
  };
  for(const name of regNames){
    if(!Object.hasOwn(row.initial,name)||!Object.hasOwn(row.final,name)||
       row.initial[name]!==initial[name])throw new Error(`initial ABI mismatch ${index}:${name}`);
  }
  const events:(string|number)[][]=[];
  const memory={
    read32(address:number){const {page,offset}=locate(address,4);
      events.push(['read',address.toString(16).padStart(8,'0'),4]);
      return new DataView(page.bytes.buffer).getUint32(offset,true);},
    write32(address:number,value:number){const {page,offset}=locate(address,4);
      events.push(['write',address.toString(16).padStart(8,'0'),4,value>>>0]);
      new DataView(page.bytes.buffer).setUint32(offset,value>>>0,true);},
    write16(address:number,value:number){const {page,offset}=locate(address,2);
      events.push(['write',address.toString(16).padStart(8,'0'),2,value&0xffff]);
      new DataView(page.bytes.buffer).setUint16(offset,value&0xffff,true);}
  };
  const got=initializeMergeHeader(receiver,0x400800,memory);
  if(process.argv[3]==='--mutate-result'&&index===0)got.eax^=1;
  if(process.argv[3]==='--mutate-effect'&&index===0)events.reverse();
  if(process.argv[3]==='--mutate-memory'&&index===0)pages[0].bytes[0]^=1;
  if(process.argv[3]==='--mutate-abi'&&index===0)row.final.ebx^=1;
  const final={...initial,...got};
  for(const name of regNames)if(final[name]!==row.final[name])
    throw new Error(`final ABI mismatch ${index}:${name}`);
  if(JSON.stringify(events)!==JSON.stringify(row.events))
    throw new Error(`ordered effects mismatch ${index}`);
  if(JSON.stringify(pages.map(p=>hash(p.bytes)))!==JSON.stringify(row.memory_sha256))
    throw new Error(`complete memory mismatch ${index}`);
  if(JSON.stringify(row.trace)!==JSON.stringify(expectedTrace))
    throw new Error(`original entry/return trace mismatch ${index}`);
  for(const address of row.trace)starts.add(address);
  for(let i=0;i+1<row.trace.length;i++)edgeSet.add(`${row.trace[i]}:${row.trace[i+1]}`);
  steps+=row.trace.length;
}
const listedEdges=sites.functions[0].edges.map(([a,b]:string[])=>`${a}:${b}`).sort();
const oracleEdges=oracle.covered_edges.map(([a,b]:string[])=>`${a}:${b}`).sort();
if(steps!==1792||starts.size!==7||
   JSON.stringify([...starts].sort())!==JSON.stringify(oracle.covered_instruction_starts)||
   JSON.stringify([...edgeSet].sort())!==JSON.stringify(listedEdges)||
   JSON.stringify([...edgeSet].sort())!==JSON.stringify(oracleEdges))
  throw new Error('instruction/CFG coverage mismatch');
for(const bad of [-1,0xfffffff3,0x100000000]){
  let rejected=false;
  try{initializeMergeHeader(bad,0x400800,{read32:()=>0,write32:()=>{},write16:()=>{}});}
  catch(e){rejected=e instanceof RangeError;}
  if(!rejected)throw new Error('invalid receiver accepted');
}
console.log(JSON.stringify({checked_cases:256,executed_instruction_steps:steps,
  covered_instruction_starts:starts.size,covered_edges:edgeSet.size,synthetic_only:true}));

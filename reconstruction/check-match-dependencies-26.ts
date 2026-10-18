import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {invalidateStatusCallFree} from './match-dependencies-26.ts';
if(Number(process.versions.node.split('.')[0])<24)throw new Error('Node 24+ required');
type Config={kind:string;index:number;count:number;link:number;flag:number;active:number};
type Row={input:Config;seed:number;initial:Record<string,number>;final:Record<string,number>;
  effects:unknown[];trace:string[];memory_sha256:string[]};
const raw=readFileSync(process.argv[2]??'evidence/match-dependencies-26-oracle.json');
const hash=(v:Uint8Array)=>createHash('sha256').update(v).digest('hex');
if(hash(raw)!=='e56df17f43b5a91847b6141eb97007e0ef68f0a75b8a631159c15fc5eace6f98')throw new Error('oracle SHA-256 mismatch');
const oracle=JSON.parse(raw.toString('utf8'));
if(oracle.entry_va!=='0062e700'||oracle.specimen_sha256!=='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
  ||oracle.body_sha256!=='ff6fea6922e4604ba849ab3cefd8173c7f1418dde6e18fb97c6e363168f4c8f6'
  ||oracle.checkpoint_archive_sha256!=='670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a'
  ||oracle.export_manifest_sha256!=='e86692ed3575e204e9e22c5c6d15bba0f5a299d1bc30ce64111b25f0e66cad75'
  ||oracle.annotation_preflight_sha256!=='b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd'
  ||oracle.function_cases!==77||oracle.cases.length!==77||oracle.executed_instruction_steps!==2185
  ||oracle.covered_instruction_starts.length!==44)throw new Error('oracle provenance/coverage mismatch');
const schedule:Config[]=[];
const values=[-2147483648,-2,-1,0,1,5,6,2147483647];
for(const count of values)for(const index of values)if(index>=count)schedule.push({kind:'count',index,count,link:-1,flag:0,active:0});
for(const index of [-2,-1,0,1,5])schedule.push({kind:'sentinel',index,count:6,link:-1,flag:0,active:0});
for(const index of [-2,0,5])for(const link of [-2,0,3])for(const [flag,active] of [[0,0],[0,0x12345678],[1,0],[0xffffffff,0]])
  schedule.push({kind:'invalidate',index,count:6,link,flag,active});
let steps=0;const covered=new Set<string>();
for(const [ordinal,row] of (oracle.cases as Row[]).entries()){
  const c=row.input;
  if(JSON.stringify(c)!==JSON.stringify(schedule[ordinal])||row.seed!==ordinal+1)throw new Error('fixture schedule mismatch');
  const regions:[[number,number],[number,number],[number,number],[number,number],[number,number]]=
    [[0x200000,0x1000],[0x300000,0x1000],[0x400000,0x2000],[0x500000,0x2000],[0xae2000,0x1000]];
  const pages=regions.map(([base,size])=>({base,bytes:Uint8Array.from({length:size},(_,n)=>(n*37+row.seed*11)&255)}));
  const locate=(a:number,n:number)=>{const p=pages.find(p=>a>=p.base&&a+n<=p.base+p.bytes.length);
    if(!p)throw new Error('unmapped synthetic memory');return {p,offset:a-p.base};};
  const init32=(a:number,v:number)=>{const {p,offset}=locate(a,4);new DataView(p.bytes.buffer).setUint32(offset,v>>>0,true);};
  init32(0x200000,c.index);init32(0x200039,c.active);init32(0xae2364,c.count);init32(0x300000,0x401000);init32(0x300004,0x501000);
  if(c.kind!=='count')init32((0x401000+31*c.index+14)>>>0,c.link);
  if(c.kind==='invalidate'){const {p,offset}=locate((0x501000+48*c.link)>>>0,1);p.bytes[offset]=0x51;}
  const effects:unknown[]=[];
  const memory={
    read8(a:number){const {p,offset}=locate(a,1);effects.push(['read',a.toString(16).padStart(8,'0'),1]);return p.bytes[offset];},
    read32(a:number){const {p,offset}=locate(a,4);effects.push(['read',a.toString(16).padStart(8,'0'),4]);return new DataView(p.bytes.buffer).getUint32(offset,true);},
    write8(a:number,v:number){const {p,offset}=locate(a,1);effects.push(['write',a.toString(16).padStart(8,'0'),1,v&255]);p.bytes[offset]=v&255;},
    write32(a:number,v:number){const {p,offset}=locate(a,4);effects.push(['write',a.toString(16).padStart(8,'0'),4,v>>>0]);new DataView(p.bytes.buffer).setUint32(offset,v>>>0,true);},
  };
  const got=invalidateStatusCallFree(0x300000,0x200000,c.flag,row.initial.edx,memory);
  if(process.argv[3]==='--mutate-result')got.edx^=1;
  if(process.argv[3]==='--mutate-effect'&&c.kind==='invalidate')effects.pop();
  if(got.path!==c.kind||['eax','ecx','edx'].some(n=>got[n as 'eax'|'ecx'|'edx']!==row.final[n]))throw new Error('register/path mismatch');
  if(JSON.stringify(effects)!==JSON.stringify(row.effects))throw new Error('ordered memory effect mismatch');
  if(JSON.stringify(pages.map(p=>hash(p.bytes)))!==JSON.stringify(row.memory_sha256))throw new Error('full external memory mismatch');
  if(row.final.esp!==row.initial.esp+12||['ebx','esi','edi','ebp'].some(n=>row.final[n]!==row.initial[n]))throw new Error('ABI mismatch');
  if(row.trace[0]!=='0062e700'||row.trace.at(-1)!=='0062e819')throw new Error('entry/return mismatch');
  for(const a of row.trace)covered.add(a);steps+=row.trace.length;
}
if(steps!==2185||JSON.stringify([...covered].sort())!==JSON.stringify(oracle.covered_instruction_starts))throw new Error('coverage mismatch');
// Deliberately outside the admitted domain: diagnostic, refresh and notification calls.
for(const kind of ['null','update','notification']){
  const memory={read8:()=>kind==='update'?0:0x51,
    read32:(a:number)=>a===0xae2364?1:a===0x300000?0x401000:a===0x300004?0x501000:a===0x200039?1:0,
    write8:()=>{throw new Error('unexpected out-of-domain write');},write32:()=>{throw new Error('unexpected out-of-domain write');}};
  let rejected=false;try{invalidateStatusCallFree(0x300000,kind==='null'?0:0x200000,kind==='notification'?1:0,0,memory);}
  catch(e){rejected=e instanceof RangeError;}if(!rejected)throw new Error('callee domain accepted');
}
console.log(JSON.stringify({checked_cases:77,executed_instruction_steps:steps,covered_instruction_starts:covered.size,external_memory:'all five synthetic regions',no_callees:true}));

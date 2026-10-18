import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {statusRefreshCallFreeExit} from './status-refresh-guard.ts';

type Row = {kind:string; index:number; count:number; seed:number;
  initial:Record<string,number>; final:Record<string,number>;
  external_reads:[string,number][]; external_writes:unknown[];
  seh_reads:[string,number][]; seh_writes:[string,number,number][]; trace:string[]};
type Oracle = {entry_va:string; specimen_sha256:string; checkpoint_archive_sha256:string;
  export_manifest_sha256:string; annotation_preflight_sha256:string; body_sha256:string;
  function_cases:number; executed_instruction_steps:number; covered_instruction_starts:string[];
  cases:Row[]};

const raw=readFileSync(process.argv[2] ?? 'evidence/status-refresh-24-guard-oracle.json');
const digest=createHash('sha256').update(raw).digest('hex');
const expectedDigest='1d36facfaa5e945e4b5c66669f76bcd9ad3d793f3e8a0333728169ce8ef99cfe';
if(digest!==expectedDigest)throw new Error('oracle SHA-256 mismatch');
const oracle=JSON.parse(raw.toString('utf8')) as Oracle;
if(oracle.entry_va!=='0062c680' || oracle.body_sha256!=='10271964e0119f7a886c34ba8741174957ec555c822f8affa7f56acb3dab2fe6'
  || oracle.specimen_sha256!=='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
  || oracle.checkpoint_archive_sha256!=='9cb03ce3740e5529a2f6155aa20b1a61ea4ba321c6d3520e1c91525782703f52'
  || oracle.export_manifest_sha256!=='c3770d9a3b8b99d80454413ea5ec85114aa0f3baa9ec0c661567c30d7bf40e70'
  || oracle.annotation_preflight_sha256!=='1df62ffab8859fa6d1b86e486a26f10f82c82827eb08356caae3ce916694a193'
  || oracle.function_cases!==13 || oracle.cases.length!==13
  || oracle.executed_instruction_steps!==568 || oracle.covered_instruction_starts.length!==58)
  throw new Error('oracle provenance or coverage mismatch');
const expectedSchedule:[string,number,number][]=([
  ['null',0,100],['null',5,-1],
  ['count',0,0],['count',5,5],['count',5,-1],['count',-1,-1],['count',100,99],
  ['slot-null',0,100],['slot-null',1,100],['slot-null',2,100],
  ['cached',0,100],['cached',1,100],['cached',2,100],
]);
const expectedTrace=new Map<string,string[]>();
let steps=0;
for(const [ordinal,row] of oracle.cases.entries()){
  if(JSON.stringify([row.kind,row.index,row.count])!==JSON.stringify(expectedSchedule[ordinal])
    || row.seed!==ordinal+1)throw new Error(`fixture schedule mismatch ${ordinal}`);
  const template=expectedTrace.get(row.kind);
  if(template && JSON.stringify(row.trace)!==JSON.stringify(template))
    throw new Error(`original trace changed within ${row.kind}`);
  expectedTrace.set(row.kind,row.trace);
  if(row.trace[0]!=='0062c680'||row.trace.at(-1)!=='0062cdf2'||row.external_writes.length)
    throw new Error(`original scope/effects mismatch ${ordinal}`);
  const reads:[string,number][]=[];
  const sehReads:[string,number][]=[];
  const sehWrites:[string,number,number][]=[];
  let sehHead=0;
  function record(address:number,size:number,value:number):number{
    reads.push([address.toString(16).padStart(8,'0'),size]);return value;
  }
  const rowAddress=0x310000+31*row.index;
  const memory={
    read8(address:number):number{
      if(address===0xb63d10)return record(address,1,7);
      throw new Error(`unexpected byte read ${address.toString(16)}`);
    },
    read16(address:number):number{
      if(address===0xae2c92)return record(address,2,0x001a);
      if(address===0xae2c90)return record(address,2,0x07ea);
      throw new Error(`unexpected word read ${address.toString(16)}`);
    },
    read32(address:number):number{
      if(address===0){sehReads.push(['00000000',4]);return sehHead;}
      if(address===0x200000)return record(address,4,row.index>>>0);
      if(address===0xae2364)return record(address,4,row.count>>>0);
      if(address===0x200061)return record(address,4,row.kind==='slot-null'?0:0x210000);
      if(address===0x300000)return record(address,4,0x310000);
      if(address===rowAddress)return record(address,4,0x001a07ea);
      if(address===rowAddress+4)return record(address,4,0x12345678);
      throw new Error(`unexpected dword read ${address.toString(16)}`);
    },
    write32(address:number,value:number):void{
      if(address!==0)throw new Error(`unexpected dword write ${address.toString(16)}`);
      sehWrites.push(['00000000',4,value>>>0]);sehHead=value>>>0;
    },
  };
  const got=statusRefreshCallFreeExit(0x300000,row.kind==='null'?0:0x200000,row.initial.edx,row.initial.esp,memory);
  if(process.argv[3]==='--mutate-register')got.edx^=1;
  if(got.path!==row.kind||got.eax!==row.final.eax||got.ecx!==row.final.ecx||got.edx!==row.final.edx)
    throw new Error(`register/path mismatch ${ordinal}`);
  if(JSON.stringify(reads)!==JSON.stringify(row.external_reads))
    throw new Error(`read order mismatch ${ordinal}`);
  if(JSON.stringify(sehReads)!==JSON.stringify(row.seh_reads)
    || JSON.stringify(sehWrites)!==JSON.stringify(row.seh_writes) || sehHead!==0)
    throw new Error(`SEH frame effect mismatch ${ordinal}`);
  if(row.final.esp!==row.initial.esp+8
    || ['ebx','ebp','esi','edi'].some(register=>row.final[register]!==row.initial[register]))
    throw new Error(`native nonvolatile/RET4 mismatch ${ordinal}`);
  steps+=row.trace.length;
}
if(steps!==oracle.executed_instruction_steps||expectedTrace.size!==4)
  throw new Error('coverage mismatch');
for(const [player,memory] of [
  [0x200000,{read8:()=>0,read16:()=>0,read32:()=>0,write32:()=>{}}],
  [0x200000,{read8:()=>7,read16:()=>0,read32:(address:number)=>address===0x200000?0:100,write32:()=>{}}],
] as const){
  let rejected=false;
  try{statusRefreshCallFreeExit(0x300000,player,0,0x108000,memory);}
  catch(error){rejected=error instanceof RangeError;}
  if(!rejected)throw new Error('out-of-domain path accepted');
}
console.log(JSON.stringify({checked_cases:oracle.function_cases,executed_instruction_steps:steps,body_sha256:oracle.body_sha256}));

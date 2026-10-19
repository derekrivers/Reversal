import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {strlenRuntime27, type Registers27, type Read27} from './strlen-runtime-27.ts';

type Case = {case:number; alignment:number; nul:number; fill:number;
  source:number[]; stack_before:number[]; initial:Registers27; final:Registers27;
  eip:number; events:Read27[]; steps:number; return_site:string};
type Oracle = {unit:string; entry_va:string; specimen_sha256:string;
  checkpoint_archive_sha256:string; export_manifest_sha256:string;
  annotation_preflight_sha256:string; body_sha256:string; cases_count:number;
  executed_instruction_steps:number; covered_instruction_starts:string[];
  covered_cfg_edges:string[][]; eflags_compared:boolean; cases:Case[]};
const equal = (a:unknown,b:unknown) => JSON.stringify(a) === JSON.stringify(b);
const raw = readFileSync(process.argv[2] ?? 'evidence/strlen-runtime-27-oracle.json.gz');
if (createHash('sha256').update(raw).digest('hex') !==
    '2a6f932806c3e4b30bf8764c693a059d3c40965409480f5214a2d1faa042466b')
  throw new Error('original-instruction oracle SHA-256 mismatch');
const oracle = JSON.parse(gunzipSync(raw).toString('utf8')) as Oracle;
if (oracle.unit !== 'R27-B' || oracle.entry_va !== '009488e0' ||
    oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86' ||
    oracle.checkpoint_archive_sha256 !== '4acf11ca1ab79b275436c6365813904d87634436de1723ce24a2274f83a087c4' ||
    oracle.export_manifest_sha256 !== 'bbd00280029a738f4f4dfa6462c7d34a4379887626749d9f20eef20873655f14' ||
    oracle.annotation_preflight_sha256 !== 'fb1be5075c72e92045f4d802f649665801d8ebc85b049a25e0f652e282f6015d' ||
    oracle.body_sha256 !== 'ee3a394138000e43710e1f46da55d9eed3240ac7510488da765689c5aea446c7' ||
    oracle.cases_count !== 576 || oracle.cases.length !== 576 ||
    oracle.executed_instruction_steps !== 58526 ||
    oracle.covered_instruction_starts.length !== 44 ||
    oracle.covered_cfg_edges.length !== 48 || oracle.eflags_compared !== false)
  throw new Error('oracle provenance or coverage mismatch');
const nuls = [...Array(20).keys(),23,24,25,31,32,33,47,48,63,64,65,79,80,93,94,95];
const schedule = [];
for (let a=0;a<4;a++) for (const n of nuls) for (const f of [1,127,128,255])
  schedule.push([a,n,f]);
let steps=0; const returns=new Set<string>();
for (const [index,row] of oracle.cases.entries()) {
  if (row.case !== index || !equal([row.alignment,row.nul,row.fill],schedule[index]) ||
      row.source.length !== 104 || row.stack_before.length !== 36 ||
      row.initial.esp !== 0x10000800 || row.source.indexOf(0) !== row.nul)
    throw new Error('synthetic case schedule mismatch');
  const address=0x200f00+row.alignment;
  const got=strlenRuntime27(Uint8Array.from(row.source),address,row.initial,
                            Uint8Array.from(row.stack_before));
  const mutation=process.argv[3];
  if (index===0 && mutation==='--mutate-length') got.length ^= 1;
  if (index===0 && mutation==='--mutate-register') got.registers.edx ^= 1;
  if (index===0 && mutation==='--mutate-stack') got.stack[0] ^= 1;
  if (index===0 && mutation==='--mutate-return') got.eip ^= 1;
  if (index===0 && mutation==='--mutate-read') got.events.splice(0,1);
  if (index===0 && mutation==='--mutate-width') got.events[0][3]=1;
  if (got.length !== row.nul || !equal(got.registers,row.final) ||
      !equal(got.events,row.events) || !equal([...got.stack],row.stack_before) ||
      got.eip !== row.eip)
    throw new Error(`original-instruction mismatch at case ${index}`);
  steps+=row.steps; returns.add(row.return_site);
}
if (steps!==58526 || !equal([...returns].sort(),
    ['0094893c','00948946','00948950','0094895a']))
  throw new Error('original entry-to-return census differs');
const row=oracle.cases[0], src=Uint8Array.from(row.source), st=Uint8Array.from(row.stack_before);
function rejected(f:()=>unknown) {
  try {f();} catch (e) {if (e instanceof RangeError) return; throw e;}
  throw new Error('unsupported domain incorrectly admitted');
}
rejected(()=>strlenRuntime27(src,0x200f00,row.initial,st.slice(1)));
rejected(()=>strlenRuntime27(src,0x200f00,{...row.initial,edx:NaN},st));
rejected(()=>strlenRuntime27(src,0x200f00,{...row.initial,esp:0},st));
rejected(()=>strlenRuntime27(src.fill(1),0x200f00,row.initial,st));
rejected(()=>strlenRuntime27(Uint8Array.of(0),0x200f00,row.initial,st));
rejected(()=>strlenRuntime27(Uint8Array.from(row.source),0xfffffff0,row.initial,st));
rejected(()=>strlenRuntime27(Uint8Array.from(row.source),0x100007ff,row.initial,st));
rejected(()=>strlenRuntime27(Uint8Array.from(row.source),0x200f01,row.initial,st));
console.log('R27-B: 576 original-entry cases; 58526 x86 steps; 44 instructions / 48 CFG edges; length, stack, eight registers, return PC and ordered reads match. Eight unsupported-input checks pass.');

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { queryMatchScalar, type ScalarMemory } from './match-scalar.ts';

type Case = {index:number;count:number;seed:number;eax:number;edx:number;instruction_steps:number;ordered_reads:number[][]};
type Oracle = {entry_va:string; specimen_sha256:string; export_manifest_sha256:string; annotation_preflight_sha256:string; checkpoint_archive_sha256:string; file_offset:string; case_count:number; cases:Case[]; body_sha256:string; instruction_starts_seen:number; executed_instruction_steps:number};
const raw = readFileSync(process.argv[2] ?? 'evidence/match-scalar-22-oracle.json');
const expectedDigest = '21b574d659832b463f260f8719acabe4223169e33f5d3d230716c15533a4ce1d';
if (createHash('sha256').update(raw).digest('hex') !== expectedDigest) throw new Error('oracle SHA-256 mismatch');
const oracle = JSON.parse(raw.toString('utf8')) as Oracle;
if (oracle.entry_va !== '0062c3d0'
  || oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
  || oracle.export_manifest_sha256 !== 'a73c3300131cc5162d3f0122dd04d622fe6581505cea12c499ad4794ce79e239'
  || oracle.annotation_preflight_sha256 !== '16760db81594c51f88b877aa98a8703ccbcc928a9fae7cad935e32ced6c8d5fe'
  || oracle.checkpoint_archive_sha256 !== 'bf4e1739d0c1ab1780fca5f95ec9bf0f9447d7cbe28520366a79aa36b6cc5971'
  || oracle.file_offset !== '0x22c3d0'
  || oracle.body_sha256 !== 'bdc128ab628b7cf38356bac5a23a3911009e92080e9c6260c09b4ac2766f2eb2'
  || oracle.case_count !== 274 || oracle.cases.length !== 274
  || oracle.instruction_starts_seen !== 12 || oracle.executed_instruction_steps !== 2312)
  throw new Error('oracle provenance or coverage mismatch');
const expectedRows:number[][]=[];
for (const count of [-5,0,1,5,20,100]) for (let index=-20;index<25;index++)
  expectedRows.push([index>>>0,count>>>0,expectedRows.length]);
for (const index of [0x7fffffff,0xffffffff,0x100,0xffff]) expectedRows.push([index,20,expectedRows.length]);
if (expectedRows.length !== 274) throw new Error('fixture schedule mismatch');
const RECEIVER = 0x10000020, TABLE = 0x11000800, SP = 0x20000800;
let steps = 0;
for (const [ordinal,row] of oracle.cases.entries()) {
  if (JSON.stringify([row.index,row.count,row.seed]) !== JSON.stringify(expectedRows[ordinal]))
    throw new Error(`fixture coverage mismatch at case ${ordinal}`);
  const table = Uint8Array.from({length:4096},(_,i)=>(i*13 + row.seed*7 + 83)&255);
  for (let i=-20;i<25;i++) {
    const v=(i*13037 + row.seed*577 + 0x8135)&65535;
    const position=0x800+i*31+12;
    table[position]=v&255; table[position+1]=v>>>8;
  }
  const reads:number[][]=[];
  const memory:ScalarMemory={
    read32(address) {
      reads.push([address,4]);
      if (address===0x00ae2364) return row.count;
      if (address===RECEIVER) return TABLE;
      throw new Error('unexpected DWORD read');
    },
    read16(address) {
      reads.push([address,2]);
      const offset=address-0x11000000;
      if (offset<0 || offset+2>table.length) throw new Error('unmapped WORD read');
      return (table[offset] | (table[offset+1]<<8)) ^ (process.argv[3]==='--mutate-word' ? 1 : 0);
    },
  };
  const got=queryMatchScalar(RECEIVER,row.index,memory);
  if (got.eax!==row.eax || got.edx!==row.edx) throw new Error(`register mismatch at case ${ordinal}`);
  const native=row.ordered_reads.slice(1,-1);
  if (JSON.stringify(reads)!==JSON.stringify(native)) throw new Error(`read order mismatch at case ${ordinal}`);
  if (row.ordered_reads[0][0]!==SP+4 || row.ordered_reads.at(-1)?.[0]!==SP) throw new Error(`stack read mismatch at case ${ordinal}`);
  steps+=row.instruction_steps;
}
if (steps!==oracle.executed_instruction_steps) throw new Error('instruction step count mismatch');
console.log(JSON.stringify({checked_cases:oracle.case_count,executed_instruction_steps:steps,body_sha256:oracle.body_sha256}));

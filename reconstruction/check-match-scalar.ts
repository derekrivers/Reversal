import { readFileSync } from 'node:fs';
import { queryMatchScalar, type ScalarMemory } from './match-scalar.ts';

type Case = {index:number;count:number;seed:number;eax:number;edx:number;instruction_steps:number;ordered_reads:number[][]};
type Oracle = {entry_va:string; case_count:number; cases:Case[]; body_sha256:string; instruction_starts_seen:number; executed_instruction_steps:number};
const oracle = JSON.parse(readFileSync(process.argv[2] ?? 'evidence/match-scalar-22-oracle.json','utf8')) as Oracle;
if (oracle.entry_va !== '0062c3d0' || oracle.case_count !== oracle.cases.length || oracle.instruction_starts_seen !== 12) throw new Error('oracle metadata mismatch');
const RECEIVER = 0x10000020, TABLE = 0x11000800, SP = 0x20000800;
let steps = 0;
for (const [ordinal,row] of oracle.cases.entries()) {
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

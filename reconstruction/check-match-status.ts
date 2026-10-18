import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { matchStatusCountGuard } from './match-status.ts';

type Case = {index:number; count:number; seed:number;
  initial:{eax:number;ecx:number;edx:number;esi:number;edi:number;esp:number};
  final:{eax:number;ecx:number;edx:number;esi:number;edi:number;esp:number};
  external_reads:[string,number][]; external_writes:unknown[]; trace:string[]};
type Oracle = {entry_va:string; specimen_sha256:string; checkpoint_archive_sha256:string;
  export_manifest_sha256:string; annotation_preflight_sha256:string; body_sha256:string;
  function_cases:number; executed_instruction_steps:number; covered_instruction_starts:string[]; cases:Case[]};

const raw = readFileSync(process.argv[2] ?? 'evidence/match-status-23-guard-oracle.json');
const expectedDigest = '55a960c68ff9d7d01ceba32b49da7cd1e902a2c6291a36e706ccf33cb846a36c';
if (createHash('sha256').update(raw).digest('hex') !== expectedDigest) throw new Error('oracle SHA-256 mismatch');
const oracle = JSON.parse(raw.toString('utf8')) as Oracle;
if (oracle.entry_va !== '0062c400'
  || oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
  || oracle.checkpoint_archive_sha256 !== 'ea4c9888f34fe4282434e41a38e842cabec61ded30d064d0417a166e18f7fcc2'
  || oracle.export_manifest_sha256 !== 'b8d302c629ba6fbb98cb45315ee5df6f238b5b9a8e02a1c8220db3e2f384844d'
  || oracle.annotation_preflight_sha256 !== 'c7128da6c29d92931c1e096fc17112f28b73a4cd0276f7869e80a6800aee9e3a'
  || oracle.body_sha256 !== 'd46c16dcd2399b668c86134339f40e225a4575e09318fac4d09e2a0de236babc'
  || oracle.function_cases !== 43 || oracle.cases.length !== 43
  || oracle.executed_instruction_steps !== 688 || oracle.covered_instruction_starts.length !== 16)
  throw new Error('oracle provenance or coverage mismatch');
const trace = ['0062c400','0062c406','0062c407','0062c40e','0062c40f','0062c411','0062c413',
  '0062c47e','0062c480','0062c485','0062c487','0062c471','0062c472','0062c474','0062c475','0062c47b'];
const counts = [-2147483648,-5,-1,0,1,5,100,2147483647];
const indices = [-2147483648,-6,-5,-1,0,1,5,99,100,2147483647];
const expectedPairs = counts.flatMap(count => indices.filter(index => index >= count).map(index => [index>>>0,count>>>0]));
if (expectedPairs.length !== 43) throw new Error('fixture schedule mismatch');
let steps = 0;
for (const [ordinal,row] of oracle.cases.entries()) {
  if (JSON.stringify([row.index,row.count]) !== JSON.stringify(expectedPairs[ordinal]) || row.seed !== ordinal+1)
    throw new Error(`fixture mismatch ${ordinal}`);
  if (JSON.stringify(row.trace) !== JSON.stringify(trace)) throw new Error(`original trace mismatch ${ordinal}`);
  if (JSON.stringify(row.external_reads) !== JSON.stringify([['00200000',4],['00ae2364',4]])
    || row.external_writes.length !== 0) throw new Error(`original memory effect mismatch ${ordinal}`);
  const reads:[number,number][] = [];
  const memory = {read32(address:number):number {
    reads.push([address,4]);
    if (address === 0x200000) return row.index;
    if (address === 0xae2364) return row.count;
    throw new Error('unexpected read');
  }};
  const got = matchStatusCountGuard(0x200000,memory);
  if (process.argv[3] === '--mutate-low-byte') got.eax ^= 1;
  if (got.eax !== row.final.eax || got.ecx !== row.final.ecx)
    throw new Error(`register mismatch ${ordinal}`);
  if (JSON.stringify(reads) !== JSON.stringify([[0x200000,4],[0xae2364,4]]))
    throw new Error(`read order mismatch ${ordinal}`);
  if (row.final.edx !== row.initial.edx || row.final.esi !== row.initial.esi
    || row.final.edi !== row.initial.edi || row.final.esp !== row.initial.esp+8)
    throw new Error(`native preservation or RET4 mismatch ${ordinal}`);
  steps += row.trace.length;
}
if (steps !== oracle.executed_instruction_steps) throw new Error('instruction step count mismatch');
for (const invoke of [
  () => matchStatusCountGuard(0,{read32:()=>0}),
  () => matchStatusCountGuard(0x200000,{read32:(address)=>address===0x200000 ? 0 : 1}),
]) {
  let rejected = false;
  try { invoke(); } catch (error) { rejected = error instanceof RangeError; }
  if (!rejected) throw new Error('out-of-domain input accepted');
}
console.log(JSON.stringify({checked_cases:oracle.function_cases,executed_instruction_steps:steps,body_sha256:oracle.body_sha256}));

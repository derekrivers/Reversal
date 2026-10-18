import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { statusByteTable, statusByteCondition, refreshedStatusRecordCountGuard } from './status-lookup-helpers.ts';

type Row = {input:Record<string,number|boolean>; initial:Record<string,number>; final:Record<string,number>;
  external_reads:[string,number][]; external_writes:unknown[]; trace:string[]};
type Entry = {body_sha256:string;function_cases:number;executed_instruction_steps:number;
  covered_instruction_starts:string[];cases:Row[]};
type Oracle = {specimen_sha256:string;checkpoint_archive_sha256:string;export_manifest_sha256:string;
  annotation_preflight_sha256:string;entries:Record<string,Entry>};
const raw = readFileSync(process.argv[2] ?? 'evidence/status-lookup-25-oracle.json');
const digest = '188f069ba861e142c0cc6f204b674b4ca19031cd9842c0e2e13cbb5519db66df';
if (createHash('sha256').update(raw).digest('hex') !== digest) throw new Error('oracle SHA-256 mismatch');
const oracle = JSON.parse(raw.toString('utf8')) as Oracle;
if (oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
  || oracle.checkpoint_archive_sha256 !== '77fb2072a25ff030ab3c0e58c5cd289730a9a8c5345ceaaf56e948e727c1dd0b'
  || oracle.export_manifest_sha256 !== '9f7e0de5968e38bac77fe8438678596f82ab31abee5e820c7ccb36b2f1ce531c'
  || oracle.annotation_preflight_sha256 !== '34ca2e277634b5a4bdbde668ffcc7d3b91a65a4c1689844f54c454b644834899')
  throw new Error('oracle provenance mismatch');
const spec:Record<string,[string,number,number,number]> = {
  '0062ec00':['06fb4b000e61a9e4ae2626878867e975ed0031909adf76af9813988d46c3e61e',256,1024,4],
  '0062ece0':['78b2038a612f23e96eb5f6a6a813c5242fa40385f82ffbd5a9dd3e9affd99588',32,713,28],
  '0062ed70':['1d8ecca16d2ad835d32f01edf9ad8e56d93fa99519c37eea523815c7bae5e8e2',43,688,16],
};
if (JSON.stringify(Object.keys(oracle.entries).sort()) !== JSON.stringify(Object.keys(spec).sort()))
  throw new Error('entry set changed');
let cases = 0, steps = 0;
for (const [site,entry] of Object.entries(oracle.entries)) {
  const [body,count,expectedSteps,starts] = spec[site];
  if (entry.body_sha256 !== body || entry.function_cases !== count || entry.cases.length !== count
    || entry.executed_instruction_steps !== expectedSteps || entry.covered_instruction_starts.length !== starts)
    throw new Error(`coverage or body mismatch ${site}`);
  const covered = new Set<string>();
  for (const [ordinal,row] of entry.cases.entries()) {
    const input = row.input;
    const reads:[string,number][] = [];
    const read8 = (address:number):number => {
      reads.push([address.toString(16).padStart(8,'0'),1]);
      if (site === '0062ec00') {
        const index = input.input as number;
        if (address !== (0x9e7ad9 + 13*index) >>> 0) throw new Error('unexpected table address');
        return ((index*73+41)^0x5a)&0xff;
      }
      const index = input.index as number;
      const rowAddress = (0x300100 + 31*index) >>> 0;
      if (address === (rowAddress+0x12) >>> 0) return input.sentinel as number;
      if (address === (rowAddress+0x13) >>> 0) return (input.value as number)&0xff;
      throw new Error('unexpected byte read');
    };
    const read32 = (address:number):number => {
      reads.push([address.toString(16).padStart(8,'0'),4]);
      if (address === 0x200000) return (input.index as number) >>> 0;
      if (address === 0xae2364) return (input.count as number) >>> 0;
      if (address === 0x200061) return input.active as number;
      if (address === 0x300000) return 0x300100;
      throw new Error('unexpected DWORD read');
    };
    const memory = {read8,read32};
    let got:{eax:number;ecx:number;edx?:number};
    if (site === '0062ec00') {
      if (input.input !== ordinal-128) throw new Error('table input schedule changed');
      got = statusByteTable((input.input as number) >>> 0,memory);
    } else if (site === '0062ece0') {
      got = statusByteCondition(input.nonnull ? 0x200000 : 0,0x300000,row.initial.eax,memory);
    } else {
      got = refreshedStatusRecordCountGuard(0x200000,memory);
      if (((input.index as number) | 0) < ((input.count as number) | 0))
        throw new Error('guard schedule reaches refresh callee');
    }
    if (process.argv[3] === '--mutate-result' && site === '0062ece0' && ordinal === 0) got.eax ^= 1;
    if (got.eax !== row.final.eax || got.ecx !== row.final.ecx
      || (got.edx !== undefined && got.edx !== row.final.edx))
      throw new Error(`register mismatch ${site} case ${ordinal}`);
    if (JSON.stringify(reads) !== JSON.stringify(row.external_reads) || row.external_writes.length !== 0)
      throw new Error(`memory effect mismatch ${site} case ${ordinal}`);
    if (row.final.esi !== row.initial.esi || row.final.edi !== row.initial.edi
      || row.final.esp !== row.initial.esp+8) throw new Error('native preservation or RET4 mismatch');
    for (const start of row.trace) covered.add(start);
    steps += row.trace.length;
    cases++;
  }
  if (JSON.stringify([...covered].sort()) !== JSON.stringify(entry.covered_instruction_starts))
    throw new Error(`covered site mismatch ${site}`);
  if (entry.cases.reduce((sum,row)=>sum+row.trace.length,0) !== entry.executed_instruction_steps)
    throw new Error(`step count mismatch ${site}`);
}
for (const action of [
  () => refreshedStatusRecordCountGuard(0,{read8:()=>0,read32:()=>0}),
  () => refreshedStatusRecordCountGuard(0x200000,{read8:()=>0,read32:(a)=>a===0x200000?0:1}),
]) {
  let rejected = false;
  try { action(); } catch (error) { rejected = error instanceof RangeError; }
  if (!rejected) throw new Error('out-of-domain lookup accepted');
}
console.log(JSON.stringify({checked_cases:cases,executed_instruction_steps:steps}));

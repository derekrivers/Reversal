import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {copyWithLeadByteTable} from './copy-helper.ts';

type Registers = Record<'eax'|'ebx'|'ecx'|'edx'|'ebp'|'esi'|'edi'|'esp',number>;
type Event = ['source'|'table'|'dest',number,number,number];
type Row = {case:number;pattern:number;count:number;source:number[];
  dest_before:number[];dest_after:number[];table_flags:number[];
  initial:Registers;final:Registers;events:Event[];trace:string[]};
type Oracle = {entry_va:string;specimen_sha256:string;checkpoint_archive_sha256:string;
  export_manifest_sha256:string;annotation_preflight_sha256:string;body_sha256:string;
  mode_zero_callee_executed:boolean;cases_count:number;executed_instruction_steps:number;
  covered_instruction_starts:string[];cases:Row[]};

const path = process.argv[2] ?? 'evidence/copy-helper-25-oracle.json';
const raw = readFileSync(path);
if (createHash('sha256').update(raw).digest('hex') !==
    'c44c407bd62e30b11818320bd05eb657dd449e523669db9e597ea37de872f15e')
  throw new Error('original-instruction oracle SHA-256 mismatch');
const oracle = JSON.parse(raw.toString('utf8')) as Oracle;
if (oracle.entry_va !== '00948851' ||
    oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86' ||
    oracle.checkpoint_archive_sha256 !== '77fb2072a25ff030ab3c0e58c5cd289730a9a8c5345ceaaf56e948e727c1dd0b' ||
    oracle.export_manifest_sha256 !== '9f7e0de5968e38bac77fe8438678596f82ab31abee5e820c7ccb36b2f1ce531c' ||
    oracle.annotation_preflight_sha256 !== '34ca2e277634b5a4bdbde668ffcc7d3b91a65a4c1689844f54c454b644834899' ||
    oracle.body_sha256 !== 'bb0dd1f9dc927140bc857b8b48b2c621c272cbd9fbc67f3f0b1e693185aecf3f' ||
    oracle.mode_zero_callee_executed !== false || oracle.cases_count !== 180 ||
    oracle.cases.length !== 180 || oracle.executed_instruction_steps !== 11619 ||
    oracle.covered_instruction_starts.length !== 57)
  throw new Error('oracle provenance or coverage mismatch');

let steps = 0;
const reached = new Set<string>();
let truncated = 0, leadZero = 0, padded = 0;
for (const [index, row] of oracle.cases.entries()) {
  if (row.case !== index || row.count !== index%18 || row.pattern !== Math.floor(index/18) ||
      row.source.length !== 32 || row.dest_before.length !== 32 ||
      row.dest_after.length !== 32 || JSON.stringify(row.table_flags) !== '[129,224]' ||
      row.initial.esp !== 0x10000800 || row.initial.ebx !== ((0xd4500000+index)>>>0))
    throw new Error('synthetic case schedule mismatch');
  if (row.trace[0] !== '00948851' || row.trace.at(-1) !== '009488da' ||
      row.trace.includes('0094886b'))
    throw new Error('mode-zero call or incomplete original trace');
  row.trace.forEach(x => reached.add(x));
  steps += row.trace.length;
  if (row.trace.includes('009488b0')) truncated++;
  if (row.trace.includes('009488b6')) leadZero++;
  if (row.trace.includes('009488cc')) padded++;
  const table = new Uint8Array(256);
  table[0x81] = 4;
  table[0xe0] = 0x84;
  const got = copyWithLeadByteTable(
    Uint8Array.from(row.source), Uint8Array.from(row.dest_before), row.count,
    table, 0x200f00, 0x210f00, row.initial.ecx);
  if (process.argv[3] === '--mutate-result' && index === 0) got.destination[0] ^= 1;
  if (JSON.stringify([...got.destination]) !== JSON.stringify(row.dest_after) ||
      JSON.stringify(got.events) !== JSON.stringify(row.events) ||
      got.eax !== row.final.eax || got.ecx !== row.final.ecx ||
      got.edx !== row.final.edx || got.espDelta !== row.final.esp-row.initial.esp)
    throw new Error(`original-instruction mismatch at case ${index}`);
  for (const register of ['ebx','ebp','esi','edi'] as const)
    if (row.initial[register] !== row.final[register])
      throw new Error(`native callee-saved register changed in case ${index}`);
}
if (steps !== oracle.executed_instruction_steps || reached.size !== 57 ||
    JSON.stringify([...reached].sort()) !== JSON.stringify(oracle.covered_instruction_starts) ||
    !truncated || !leadZero || !padded)
  throw new Error('original instruction coverage mismatch');
console.log(`R25-C: ${oracle.cases_count} original-entry cases, ${steps} x86 steps, ${reached.size} instruction starts; output, ordered memory events and ABI match.`);

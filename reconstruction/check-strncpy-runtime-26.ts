import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {strncpyRuntime26, type Registers26, type Event26} from './strncpy-runtime-26.ts';

type Case = {case:number; source_alignment:number; dest_alignment:number;
  count:number; nul:number; fill:number; source:number[]; dest_before:number[];
  dest_after:number[]; stack_before:number[]; stack_after:number[];
  initial:Registers26; final:Registers26; eip:number; events:Event26[];
  steps:number; return_site:string};
type Oracle = {unit:string; entry_va:string; specimen_sha256:string;
  checkpoint_archive_sha256:string; export_manifest_sha256:string;
  annotation_preflight_sha256:string; body_sha256:string;
  cases_count:number; executed_instruction_steps:number;
  covered_instruction_starts:string[]; covered_cfg_edges:string[][];
  eflags_compared:boolean; cases:Case[]};
const equal = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const raw = readFileSync(process.argv[2] ?? 'evidence/strncpy-runtime-26-oracle.json.gz');
if (createHash('sha256').update(raw).digest('hex') !==
    'fbee331c5b29691dda02c91ab5492d31cb20b4f254ee8d7a1febde457ca29169')
  throw new Error('original-instruction oracle SHA-256 mismatch');
const oracle = JSON.parse(gunzipSync(raw).toString('utf8')) as Oracle;
if (oracle.unit !== 'R26-B' || oracle.entry_va !== '009466d0' ||
    oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86' ||
    oracle.checkpoint_archive_sha256 !== '670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a' ||
    oracle.export_manifest_sha256 !== 'e86692ed3575e204e9e22c5c6d15bba0f5a299d1bc30ce64111b25f0e66cad75' ||
    oracle.annotation_preflight_sha256 !== 'b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd' ||
    oracle.body_sha256 !== '0318574df8288c6fc0e543c779d4c1098344731f9acf2a7c790c2176ab7bdf4c' || oracle.cases_count !== 6912 ||
    oracle.cases.length !== 6912 || oracle.executed_instruction_steps !== 580732 ||
    oracle.covered_instruction_starts.length !== 109 || oracle.covered_cfg_edges.length !== 130 ||
    oracle.eflags_compared !== false)
  throw new Error('oracle provenance or coverage mismatch');
const counts = [...Array(18).keys(),31,32,33,63,64,65];
const patterns = [-1,0,1,2,3,4,7,15,16,17,31,32,63,64,65].map(n => [n,-1]);
patterns.push([-1,128],[-1,255],[-1,1]);
const schedule = [];
for (let sa = 0; sa < 4; sa++) for (let da = 0; da < 4; da++)
  for (const n of counts) for (const [nul,fill] of patterns) schedule.push([sa,da,n,nul,fill]);
let steps = 0;
const returns = new Set<string>();
for (const [index, row] of oracle.cases.entries()) {
  if (row.case !== index || !equal(schedule[index],
      [row.source_alignment,row.dest_alignment,row.count,row.nul,row.fill]) ||
      row.source.length !== 96 || row.dest_before.length !== 96 ||
      row.stack_before.length !== 36 || row.initial.esp !== 0x10000800)
    throw new Error('synthetic case schedule mismatch');
  const sourceAddress = 0x200f00+row.source_alignment;
  const destinationAddress = 0x210f00+row.dest_alignment;
  const got = strncpyRuntime26(Uint8Array.from(row.source), Uint8Array.from(row.dest_before),
    row.count, sourceAddress, destinationAddress, row.initial, Uint8Array.from(row.stack_before));
  // Mutations deliberately perturb distinct comparisons to prove these gates run.
  const mutation = process.argv[3];
  if (index === 0 && mutation === '--mutate-output') got.destination[0] ^= 1;
  if (index === 0 && mutation === '--mutate-register') got.registers.edx ^= 1;
  if (index === 0 && mutation === '--mutate-stack') got.stack[0] ^= 1;
  if (index === 0 && mutation === '--mutate-return') got.eip ^= 1;
  if (row.count === 4 && row.source_alignment === 0 && mutation === '--mutate-read') {
    const at = got.events.findIndex(e => e[0] === 'read' && e[1] === 'source');
    got.events.splice(at, 1);
  }
  if (row.count === 4 && mutation === '--mutate-write-width') {
    const at = got.events.findIndex(e => e[0] === 'write' && e[1] === 'dest');
    got.events[at][3] = got.events[at][3] === 4 ? 1 : 4;
  }
  if (!equal([...got.destination], row.dest_after) || !equal([...got.stack], row.stack_after) ||
      !equal(got.events, row.events) || !equal(got.registers, row.final) || got.eip !== row.eip)
    throw new Error(`original-instruction mismatch at case ${index}`);
  steps += row.steps; returns.add(row.return_site);
}
if (steps !== 580732 || !equal([...returns].sort(), ['00946729','00946758','009467cd']))
  throw new Error('original entry-to-return census differs');

// Admission checks are separate from claims about native faults or C undefined behavior.
const row = oracle.cases[0], src = Uint8Array.from(row.source), dst = Uint8Array.from(row.dest_before);
const stack = Uint8Array.from(row.stack_before);
function rejected(f: () => unknown) {
  try { f(); } catch (e) { if (e instanceof RangeError) return; throw e; }
  throw new Error('unsupported domain incorrectly admitted');
}
rejected(() => strncpyRuntime26(src,dst,-1,0x200f00,0x210f00,row.initial,stack));
rejected(() => strncpyRuntime26(src,dst,66,0x200f00,0x210f00,row.initial,stack));
rejected(() => strncpyRuntime26(src,src,0,0x200f00,0x210f00,row.initial,stack));
rejected(() => strncpyRuntime26(src,dst,0,0x200f00,0x200f01,row.initial,stack));
rejected(() => strncpyRuntime26(src,dst,0,0xfffffff0,0x210f00,row.initial,stack));
rejected(() => strncpyRuntime26(src,dst,0,0x200f00,0x210f00,row.initial,stack.slice(1)));
rejected(() => strncpyRuntime26(src,dst,0,0x200f00,0x210f00,{...row.initial,edx:NaN},stack));
const short = oracle.cases.find(r => r.count === 4 && r.nul === 0 && r.source_alignment === 0)!;
rejected(() => strncpyRuntime26(Uint8Array.of(0),dst,4,0x200f00,0x210f00,
  short.initial,Uint8Array.from(short.stack_before)));
console.log(`R26-B: 6912 original-entry cases; 580732 x86 steps; 109 instructions / 130 CFG edges; destination, stack, all eight registers, return PC and ordered accesses match. Eight unsupported-input checks pass.`);

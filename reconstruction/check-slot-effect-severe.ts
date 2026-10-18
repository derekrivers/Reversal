import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {applySevereSlotEffect} from './slot-effect-severe.ts';

type Row = {counter:number;latch:number;severity:number;initial_float:number;
  other_present:boolean;other_word:number;seed:number;
  initial:Record<string,number>;final:Record<string,number>;
  result:Record<string,number>;writes:(string|number)[][];trace:string[]};
type Oracle = {entry_va:string;specimen_sha256:string;checkpoint_archive_sha256:string;
  export_manifest_sha256:string;annotation_preflight_sha256:string;body_sha256:string;
  function_cases:number;executed_instruction_steps:number;covered_instruction_starts:string[];
  cases:Row[]};

const file = process.argv[2] ?? 'evidence/slot-effect-25-oracle.json';
const raw = readFileSync(file);
const digest = createHash('sha256').update(raw).digest('hex');
if (digest !== '26ffaca654946f429188fb39b97c176af10399163cf88ac242735cb0b4d6f66f')
  throw new Error('original-instruction oracle SHA-256 mismatch');
const oracle = JSON.parse(raw.toString('utf8')) as Oracle;
if (oracle.entry_va !== '006d0980'
    || oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
    || oracle.checkpoint_archive_sha256 !== '77fb2072a25ff030ab3c0e58c5cd289730a9a8c5345ceaaf56e948e727c1dd0b'
    || oracle.export_manifest_sha256 !== '9f7e0de5968e38bac77fe8438678596f82ab31abee5e820c7ccb36b2f1ce531c'
    || oracle.annotation_preflight_sha256 !== '34ca2e277634b5a4bdbde668ffcc7d3b91a65a4c1689844f54c454b644834899'
    || oracle.body_sha256 !== '8a618f5a01c2e2a0796c5a564d642b7ff40618d07fa814ba9be4934353d2f74b'
    || oracle.function_cases !== 144 || oracle.cases.length !== 144
    || oracle.executed_instruction_steps !== 8568 || oracle.covered_instruction_starts.length !== 65)
  throw new Error('oracle provenance or coverage mismatch');
let steps = 0;
const starts = new Set<string>();
for (const [n,row] of oracle.cases.entries()) {
  if (row.seed !== n+1 || row.initial.ecx !== 0x300000 || row.initial.esp !== 0x108000
      || row.trace[0] !== '006d0980' || row.trace.at(-1) !== '006d0b56'
      || row.trace.includes('006d09ed') || row.trace.includes('006d0ada')
      || row.trace.includes('006d0ae5') || row.trace.includes('006d0a41'))
    throw new Error(`case domain or native trace mismatch ${n}`);
  row.trace.forEach(s=>starts.add(s));
  steps += row.trace.length;
  const got = applySevereSlotEffect({counter:row.counter,latch:row.latch,
    severity:row.severity,initialFloat:row.initial_float,
    otherPresent:row.other_present,otherWord:row.other_word});
  if (process.argv[3] === '--mutate-value' && n === 0) got.result.target_float_bits ^= 1;
  if (process.argv[3] === '--mutate-order' && n === 0) got.writes.reverse();
  if (JSON.stringify(got.result) !== JSON.stringify(row.result)
      || JSON.stringify(got.writes) !== JSON.stringify(row.writes)
      || got.espDelta !== row.final.esp-row.initial.esp)
    throw new Error(`original-entry effect mismatch ${n}`);
  for (const key of ['ebx','ebp','esi','edi'])
    if (row.final[key] !== row.initial[key]) throw new Error(`callee-saved register changed ${n}`);
  if (row.final.eax !== 257 || row.final.ecx !== 0)
    throw new Error(`unexpected native return register ${n}`);
}
if (steps !== oracle.executed_instruction_steps
    || JSON.stringify([...starts].sort()) !== JSON.stringify(oracle.covered_instruction_starts))
  throw new Error('native instruction coverage mismatch');
console.log(`slot effect severe path: ${oracle.function_cases} original-entry cases, ${steps} steps, ${starts.size} starts`);

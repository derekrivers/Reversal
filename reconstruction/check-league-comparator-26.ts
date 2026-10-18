import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {leagueCompareStableMemory} from './league-comparator-26.ts';
import type {Registers} from './league-comparator-26.ts';

type Event = ['r'|'w',number,number,number];
type Row = {case:number;label:string;left_address:number;right_address:number;shared_address:number;
  left_record:number[];right_record:number[];rules:number[];alias:boolean;
  initial:Registers;final:Registers;stack_before:number[];stack_after:number[];events:Event[];trace:string[]};
const path = process.argv[2] ?? 'evidence/league-comparator-26-oracle.json.gz';
const packed = readFileSync(path);
if (createHash('sha256').update(packed).digest('hex') !== '61d70223745ee7f928dcb6aa16fecfc74d16050cdab16309dd4d53118790f61f')
  throw new Error('original-instruction oracle SHA-256 mismatch');
const raw = gunzipSync(packed);
if (createHash('sha256').update(raw).digest('hex') !==
    '515149d388520acfab141cf9c229edf8bd6676a6d30def46c6d3809d2cdb1775')
  throw new Error('original-instruction oracle SHA-256 mismatch');
const oracle = JSON.parse(raw.toString('utf8'));
if (oracle.unit !== 'R26-C' || oracle.entry_va !== '006834f0' ||
    oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86' ||
    oracle.checkpoint_archive_sha256 !== '670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a' ||
    oracle.export_manifest_sha256 !== 'e86692ed3575e204e9e22c5c6d15bba0f5a299d1bc30ce64111b25f0e66cad75' ||
    oracle.annotation_preflight_sha256 !== 'b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd' ||
    oracle.body_sha256 !== '6d08215550e4a70622f50d9cf87e401edb59c20037c272a815697a5a722ada33' ||
    oracle.switch_table_sha256 !== 'db1835fa55fd6b84aa49555e828ac096edf165e009215802a8cfc5abf01d8c7e' ||
    oracle.cases_count !== 840 || oracle.cases.length !== 840 || oracle.executed_instruction_steps !== 40128 ||
    oracle.covered_instruction_starts.length !== 67 || oracle.all_branch_and_switch_edges_executed !== true)
  throw new Error('oracle provenance or coverage mismatch');

let steps = 0;
const covered = new Set<string>(), edges = new Set<string>();
for (const row of oracle.cases as Row[]) {
  const bytes = new Map<number,number>();
  const load = (address:number, data:number[]) => data.forEach((value,index) => bytes.set(address+index, value));
  const word = (address:number, value:number) => load(address, [value&255, (value>>>8)&255, (value>>>16)&255, value>>>24]);
  load(row.left_address, row.left_record);
  load(row.right_address, row.right_record);
  load(row.shared_address+0xc5, row.rules);
  word(0xb679fc, row.shared_address);
  [0x683550, 0x68356a, 0x683586, 0x683592, 0x683578].forEach((target,index) => word(0x6835a4+index*4, target));
  load(row.initial.esp-16, row.stack_before);
  const events:Event[] = [];
  const memory = {
    read(address:number, width:number) {
      let value = 0;
      for (let i=0; i<width; i++) {
        const byte = bytes.get((address+i)>>>0);
        if (byte === undefined) throw new Error('read outside synthetic memory');
        value += byte * 2**(8*i);
      }
      events.push(['r',address,width,value]);
      return value;
    },
    write(address:number, width:number, value:number) {
      if (width !== 4 || address < row.initial.esp-16 || address+width > row.initial.esp)
        throw new Error('write outside stack save slots');
      events.push(['w',address,width,value]);
      word(address,value);
    }
  };
  const got = leagueCompareStableMemory(memory, row.initial);
  if (process.argv[3] === '--mutate-result' && row.case === 0) got.registers.eax ^= 1;
  if (process.argv[3] === '--mutate-read-order' && row.case === 1) {
    const indices = events.flatMap((event,index) => event[0] === 'r' ? [index] : []);
    [events[indices[0]],events[indices[1]]] = [events[indices[1]],events[indices[0]]];
  }
  if (JSON.stringify(got.registers) !== JSON.stringify(row.final) || got.returnAddress !== 0x30000000 ||
      JSON.stringify(events) !== JSON.stringify(row.events) ||
      JSON.stringify(Array.from({length:28}, (_,i) => bytes.get(row.initial.esp-16+i))) !== JSON.stringify(row.stack_after))
    throw new Error(`original-instruction mismatch at case ${row.case}`);
  for (const register of ['ebx','ebp','esi','edi'] as const)
    if (row.initial[register] !== row.final[register]) throw new Error('callee-saved register changed');
  if (row.final.esp !== row.initial.esp+4 || row.trace[0] !== '006834f0' ||
      !['00683527','006835a1'].includes(row.trace.at(-1)!)) throw new Error('entry-to-return ABI mismatch');
  steps += row.trace.length;
  row.trace.forEach((address,index) => {
    covered.add(address);
    if (index) edges.add(row.trace[index-1]+':'+address);
  });
}
if (steps !== 40128 || JSON.stringify([...covered].sort()) !== JSON.stringify(oracle.covered_instruction_starts) ||
    JSON.stringify([...edges].sort()) !== JSON.stringify(oracle.covered_edges.map((p:string[]) => p.join(':')).sort()))
  throw new Error('original CFG coverage mismatch');
const witness = oracle.cases.filter((row:Row) => row.label.startsWith('transitivity-')).map((row:Row) => row.final.eax);
if (JSON.stringify(witness) !== '[0,0,1]') throw new Error('zero-key equivalence-transitivity witness missing');
console.log(`R26-C: 840 original-entry cases, ${steps} x86 steps, all 67 instruction starts and branch/switch edges; full ordered reads/writes and integer ABI match.`);

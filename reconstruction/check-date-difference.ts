import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {dateDifferenceDirect} from './date-difference.ts';

type Regs = Record<'eax'|'ebx'|'ecx'|'edx'|'ebp'|'esi'|'edi'|'esp',number>;
type Row = {receiver_day:number;receiver_year:number;argument_day:number;argument_year:number;
  global_high:number;seed:number;initial:Regs;final:Regs;output:number[];global_pair:number[];
  reads:[string,number][];writes:[string,number,number][];
  events:(['read',string,number]|['write',string,number,number])[];trace:string[]};
type Oracle = {entry_va:string;specimen_sha256:string;checkpoint_archive_sha256:string;
  export_manifest_sha256:string;annotation_preflight_sha256:string;body_sha256:string;
  function_cases:number;executed_instruction_steps:number;covered_instruction_starts:string[];
  cases:Row[]};

const path = process.argv[2] ?? 'evidence/date-difference-24-oracle.json';
const raw = readFileSync(path);
const digest = createHash('sha256').update(raw).digest('hex');
if (digest !== 'a62a75ec46f27ec20de69032e4189e787690917f2fc90a88280ad4609abbb0b9')
  throw new Error('original-instruction oracle SHA-256 mismatch');
const oracle = JSON.parse(raw.toString('utf8')) as Oracle;
if (oracle.entry_va !== '0054cc30'
  || oracle.specimen_sha256 !== '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
  || oracle.checkpoint_archive_sha256 !== '9cb03ce3740e5529a2f6155aa20b1a61ea4ba321c6d3520e1c91525782703f52'
  || oracle.export_manifest_sha256 !== 'c3770d9a3b8b99d80454413ea5ec85114aa0f3baa9ec0c661567c30d7bf40e70'
  || oracle.annotation_preflight_sha256 !== '1df62ffab8859fa6d1b86e486a26f10f82c82827eb08356caae3ce916694a193'
  || oracle.body_sha256 !== 'd73e8cd4f09bf3b5859ea806051e0f5c0e86d0521573729594358ddc32e82143'
  || oracle.function_cases !== 95 || oracle.cases.length !== 95
  || oracle.executed_instruction_steps !== 5100 || oracle.covered_instruction_starts.length !== 86)
  throw new Error('oracle provenance or coverage mismatch');
const s16 = (x:number) => (x << 16) >> 16;
let steps = 0;
const union = new Set<string>();
let borrowed = 0;
for (const [n,row] of oracle.cases.entries()) {
  if (row.seed !== n+1 || row.initial.ecx !== 0x200000 || row.initial.esp !== 0x108000)
    throw new Error('case schedule changed');
  if (!(row.argument_year < row.receiver_year ||
        row.argument_year === row.receiver_year && s16(row.argument_day) <= s16(row.receiver_day)))
    throw new Error('oracle case reaches recursive path');
  if (row.trace[0] !== '0054cc30' || row.trace.at(-1) !== '0054cd93'
      || row.trace.includes('0054ccc3') || row.trace.includes('0054cc8b'))
    throw new Error('original execution path changed');
  row.trace.forEach(x => union.add(x));
  steps += row.trace.length;
  if (row.trace.includes('0054ccee')) borrowed++;
  const reads:[string,number][] = [];
  const writes:[string,number,number][] = [];
  const events:(['read',string,number]|['write',string,number,number])[] = [];
  let low = 0x19720028, high = row.global_high;
  const memory = {
    read8(address:number):number {
      const a = address.toString(16).padStart(8,'0');
      reads.push([a,1]); events.push(['read',a,1]);
      if (address !== 0xae249d) throw new Error('unexpected byte read');
      return 1;
    },
    read16(address:number):number {
      const a = address.toString(16).padStart(8,'0');
      reads.push([a,2]); events.push(['read',a,2]);
      if (address === 0x200000) return row.receiver_day;
      if (address === 0x200002) return row.receiver_year;
      throw new Error('unexpected WORD read');
    },
    read32(address:number):number {
      const a = address.toString(16).padStart(8,'0');
      reads.push([a,4]); events.push(['read',a,4]);
      if (address === 0xae2428) return low;
      if (address === 0xae242c) return high;
      throw new Error('unexpected DWORD read');
    },
    write16(address:number,value:number):void {
      const a = address.toString(16).padStart(8,'0');
      writes.push([a,2,value]); events.push(['write',a,2,value]);
      if (address === 0xae2428) low = (low & 0xffff0000) | value;
      else if (address === 0xae242a) low = ((value << 16) | (low & 0xffff)) >>> 0;
      else throw new Error('unexpected WORD write');
    },
    write32(address:number,value:number):void {
      const a = address.toString(16).padStart(8,'0');
      writes.push([a,4,value]); events.push(['write',a,4,value]);
      if (address === 0x210000 && value === low) return;
      if (address === 0x210004 && value === high) return;
      throw new Error('unexpected DWORD write');
    },
  };
  const fsHead = (0x61234567 ^ row.seed) >>> 0;
  const got = dateDifferenceDirect(0x200000,0x210000,row.argument_day,row.argument_year,fsHead,memory);
  if (process.argv[3] === '--mutate-result' && n === 0) got.edx ^= 1;
  if (got.eax !== row.final.eax || got.ecx !== row.final.ecx
      || got.edx !== row.final.edx || got.espDelta !== row.final.esp-row.initial.esp)
    throw new Error(`register/stack mismatch case ${n}`);
  if (JSON.stringify(reads) !== JSON.stringify(row.reads)
      || JSON.stringify(writes) !== JSON.stringify(row.writes)
      || JSON.stringify(events) !== JSON.stringify(row.events)
      || JSON.stringify([low,high]) !== JSON.stringify(row.output)
      || JSON.stringify(row.output) !== JSON.stringify(row.global_pair))
    throw new Error(`memory mismatch case ${n}`);
  for (const name of ['ebx','ebp','esi','edi'] as const)
    if (row.final[name] !== row.initial[name]) throw new Error(`native register preservation ${n}`);
}
if (steps !== 5100 || union.size !== 86 || borrowed === 0)
  throw new Error('original instruction coverage changed');
let rejected = false;
try { dateDifferenceDirect(0x200000,0x210000,2,2024,0,{read8:()=>1,read16:(a)=>a===0x200002?2024:1,
  read32:()=>0,write16:()=>{},write32:()=>{}}); } catch(e) { rejected = e instanceof RangeError; }
if (!rejected) throw new Error('recursive path was accepted');
console.log(JSON.stringify({checked_cases:95,original_instruction_steps:steps,distinct_instruction_starts:union.size,
  borrowed_cases:borrowed,oracle_sha256:digest}));

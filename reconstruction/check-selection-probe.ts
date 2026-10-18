import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {probeSelectionRecord, type ProbeMemory} from './selection-probe.ts';

type Case = {pointer_mode:string;slot:number;status:number;field:number;record_id:number;
  eax:number;ecx:number;edx:number;instruction_steps:number;branch_schedule:number[][];ordered_data_reads:number[][]};
type Oracle = {specimen_sha256:string;export_manifest_sha256:string;annotation_preflight_sha256:string;
  entry_va:string;body_sha256:string;case_count:number;instruction_starts_seen:number;
  branch_sites_seen:number;executed_instruction_steps:number;cases:Case[]};
const bytes=readFileSync(process.argv[2] ?? 'evidence/selection-probe-23-oracle.json');
const expectedHash='df379919c89eb91a66fd300cc76219fb22dfe16c26b159d3f08909838bb6c7ac';
if (createHash('sha256').update(bytes).digest('hex')!==expectedHash) throw new Error('oracle SHA-256 mismatch');
const oracle=JSON.parse(bytes.toString('utf8')) as Oracle;
if (oracle.specimen_sha256!=='0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86'
 || oracle.export_manifest_sha256!=='b8d302c629ba6fbb98cb45315ee5df6f238b5b9a8e02a1c8220db3e2f384844d'
 || oracle.annotation_preflight_sha256!=='c7128da6c29d92931c1e096fc17112f28b73a4cd0276f7869e80a6800aee9e3a'
 || oracle.entry_va!=='00601070' || oracle.body_sha256!=='b355a540ab9162d662b4dfd5198d2f9dca594f0ff1a01b886fba26d64a5ffa2f'
 || oracle.case_count!==288 || oracle.cases.length!==288 || oracle.executed_instruction_steps!==16200
 || oracle.instruction_starts_seen!==66 || oracle.branch_sites_seen!==8)
  throw new Error('oracle provenance/coverage mismatch');

const RECORD=0x12000000, RECEIVER=0x10000000, TABLE=0x11020000;
let n=0, steps=0;
for (const pointerMode of ['direct','fallback']) for (const slot of [0,1,3])
 for (const status of [0,1,2,255]) for (const field of [0,1,49]) for (const id of [-1,0,5,65535]) {
  const row=oracle.cases[n++];
  if (JSON.stringify([row.pointer_mode,row.slot,row.status,row.field,row.record_id])
      !==JSON.stringify([pointerMode,slot,status,field,id])) throw new Error(`fixture sequence mismatch at ${n}`);
  const reads:number[][]=[];
  const stride=Math.imul(slot,0xa6ef);
  const statusAddress=TABLE+stride+0x9a69;
  const effectiveStatus=status===1?0:status===255?-1:status;
  const lookup=TABLE+stride+0x1e05+effectiveStatus*0x1ecd+field*4;
  const memory:ProbeMemory={
    read8(address) {
      reads.push([address,1]);
      if (address!==statusAddress) throw new Error('unexpected byte read');
      return status;
    },
    read16(address) {
      reads.push([address,2]);
      if (address!==0x00b77c7a) throw new Error('unexpected word read');
      return 1;
    },
    read32(address) {
      reads.push([address,4]);
      if (address===0x00b74c26+0x300) return RECORD;
      if (address===RECORD) return (0x12000100-16+slot)>>>0;
      if (address===0x00ae2364) return 0x12000100;
      if (address===RECEIVER+4) return 4;
      if (address===RECEIVER) return TABLE;
      if (address===lookup) return (id ^ (process.argv.includes('--mutate-record') ? 1 : 0))>>>0;
      if (address===0x00ae23bc) return 0x13000000;
      throw new Error(`unexpected DWORD read ${address.toString(16)}`);
    }
  };
  const got=probeSelectionRecord(RECEIVER,field,pointerMode==='direct'?RECORD:0,memory);
  if (got.eax!==row.eax || got.ecx!==row.ecx || got.edx!==row.edx) throw new Error(`register mismatch at ${n}`);
  if (JSON.stringify(got.branchSchedule)!==JSON.stringify(row.branch_schedule)) throw new Error(`branch schedule mismatch at ${n}`);
  if (JSON.stringify(reads)!==JSON.stringify(row.ordered_data_reads)) throw new Error(`ordered reads mismatch at ${n}`);
  steps+=row.instruction_steps;
}
if (n!==288 || steps!==16200) throw new Error('case/step count mismatch');
console.log(JSON.stringify({checked_cases:n,executed_instruction_steps:steps,body_sha256:oracle.body_sha256}));

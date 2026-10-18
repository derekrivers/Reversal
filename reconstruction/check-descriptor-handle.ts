import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { descriptorToHandle, type DescriptorMemory } from './descriptor-handle.ts';

const [oraclePath, output] = process.argv.slice(2);
if (!output) throw new Error('Usage: node check-descriptor-handle.ts oracle.json result.json');
const oracle = JSON.parse(readFileSync(oraclePath, 'utf8'));
assert.equal(oracle.schema, 1);
assert.equal(oracle.specimen_sha256, '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86');
assert.equal(oracle.emulator, 'Unicorn 2.1.4');
assert.equal(oracle.body.sha256, 'bc15fa380be7e1320498ba101d1f41e7bf28ecdfa284dfc1438c4a44ff0cc1c9');
assert.equal(oracle.inputs.length, oracle.outputs.length);
const BOUND = 0xde43e0, TABLE = 0xde42e0, ERR = 0xde2f8c, DOSERR = 0xde2f90;
const SP = 0x20000800, STOP = 0x30000000;
const sentinels = { ebx: 0x12340000, ebp: 0x12341111, esi: 0x12342222, edi: 0x12343333, edx: 0x12344444 };
type Input = [string, number, number, number, number, number, number, number, boolean];
class UnmappedRead extends Error {}
class SyntheticMemory implements DescriptorMemory {
  regions: Map<number, Uint8Array>;
  reads: number[][] = [];
  writes: number[][] = [];
  constructor(row: Input) {
    const [label, descriptor, bound, flag, handle, page, errno, doserrno, fault] = row;
    const slot = (TABLE + (descriptor >> 5) * 4) >>> 0;
    const bases = [...new Set([0xde2000, 0xde3000, 0xde4000, 0x10000000, 0x10001000,
      0x11000000, 0x20000000, 0, 0xfffff000, Math.floor(slot / 4096) * 4096])].sort((a, b) => a - b);
    this.regions = new Map(bases.map(base => [base, Uint8Array.from({ length: 4096 },
      (_, i) => (i * 29 + (base / 4096) * 7 + 0x53) & 255)]));
    for (let address = TABLE - 16; address < TABLE + 256; address += 4) this.put32(address, 0x11000000);
    this.put32(BOUND, bound); this.put32(slot, page); this.put32(BOUND, bound);
    this.put32(ERR, errno); this.put32(DOSERR, doserrno);
    const entry = (page + (descriptor & 31) * 8) >>> 0;
    if (!fault && descriptor < bound) {
      this.put32(entry, handle); this.put8((entry + 4) >>> 0, flag);
    } else if (label === 'unmapped-handle') this.put8((entry + 4) >>> 0, flag);
    this.put32(SP, STOP); this.put32(SP + 4, descriptor);
  }
  region(address: number): Uint8Array {
    const region = this.regions.get(Math.floor(address / 4096) * 4096);
    if (!region) throw new UnmappedRead(`unmapped ${address.toString(16)}`);
    return region;
  }
  put8(address: number, value: number): void { this.region(address)[address & 4095] = value; }
  put32(address: number, value: number): void {
    for (let i = 0; i < 4; i++) this.put8((address + i) >>> 0, value >>> (i * 8));
  }
  get32(address: number): number {
    let result = 0;
    for (let i = 0; i < 4; i++) {
      const at = (address + i) >>> 0;
      result |= this.region(at)[at & 4095] << (i * 8);
    }
    return result >>> 0;
  }
  read8(address: number): number {
    this.reads.push([address, 1]); return this.region(address)[address & 4095];
  }
  read32(address: number): number {
    this.reads.push([address, 4]); return this.get32(address);
  }
  write32(address: number, value: number): void {
    this.writes.push([address, 4, value]); this.put32(address, value);
  }
  hash(): string {
    const hash = createHash('sha256');
    for (const bytes of this.regions.values()) hash.update(bytes);
    return hash.digest('hex');
  }
}
const reached = new Set<number>();
let failures = 0, storedMinusOne = 0, faults = 0;
for (let i = 0; i < oracle.inputs.length; i++) {
  const row = oracle.inputs[i] as Input, expected = oracle.outputs[i], memory = new SyntheticMemory(row);
  assert.equal(memory.hash(), expected.before_sha256, `${row[0]} initial synthetic memory`);
  let eax: number | null = null, fault: string | null = null;
  try { eax = descriptorToHandle(row[1], memory); }
  catch (error) { if (!(error instanceof UnmappedRead)) throw error; fault = 'read-unmapped'; }
  assert.equal(eax, expected.eax, `${row[0]} EAX`);
  assert.equal(fault, expected.fault, `${row[0]} fault`);
  assert.deepEqual([memory.get32(ERR), memory.get32(DOSERR)], expected.errors, `${row[0]} errors`);
  assert.deepEqual(memory.reads, expected.reads, `${row[0]} ordered reads`);
  assert.deepEqual(memory.writes, expected.writes, `${row[0]} ordered writes`);
  assert.equal(memory.hash(), expected.after_sha256, `${row[0]} all synthetic memory`);
  // ABI observations belong to the original-instruction run; TS returns the EAX
  // value and exposes memory effects rather than simulating x86 registers.
  assert.deepEqual(expected.abi.preserved, sentinels, `${row[0]} original preserved registers`);
  assert.equal(expected.abi.esp, fault ? SP : SP + 4, `${row[0]} original cdecl stack`);
  assert.ok(expected.trace.length > 0 && expected.trace.length <= 16);
  for (const instruction of expected.trace) { assert.ok(instruction >= 0 && instruction < 16); reached.add(instruction); }
  if (fault) faults++;
  else if (memory.writes.length) failures++;
  else if (eax === 0xffffffff) storedMinusOne++;
}
assert.equal(reached.size, 16);
assert.equal(oracle.coverage.cases, oracle.inputs.length);
assert.equal(oracle.coverage.faults, faults);
assert.equal(new Set(oracle.inputs.filter((row: Input) => row[0].startsWith('flag-')).map((row: Input) => row[3])).size, 256);
assert.ok(failures > 0 && storedMinusOne > 0 && faults === 2);
// Reject JS inputs outside the explicitly supported unsigned DWORD interface.
for (const descriptor of [-1, 0x100000000, 0.5, NaN, Infinity]) {
  const memory = new SyntheticMemory(oracle.inputs[0]);
  assert.throws(() => descriptorToHandle(descriptor, memory), RangeError);
  assert.equal(memory.reads.length + memory.writes.length, 0);
}
const result = { status: 'passed', node: process.version, specimen_sha256: oracle.specimen_sha256,
  oracle_sha256: createHash('sha256').update(readFileSync(oraclePath)).digest('hex'),
  cases: oracle.inputs.length, error9: failures, stored_minus_one_successes: storedMinusOne,
  read_faults: faults, original_instructions_reached: reached.size,
  comparisons: 'EAX, both errors, ordered reads/writes and all mapped synthetic memory; original ABI observations',
  limitations: oracle.limitations };
writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));

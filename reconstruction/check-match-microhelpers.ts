import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { resetMatchMicrostate, addReceiverByte, setReceiverByte, type MicroMemory, type MicroRegisters } from './match-microhelpers.ts';

const [directory, output, mutation] = process.argv.slice(2);
if (!output) throw new Error('Usage: node check-match-microhelpers.ts ORACLE_DIRECTORY RESULT.json [MUTATION]');
const oracle = JSON.parse(readFileSync(`${directory}/oracle.json`, 'utf8'));
const records = readFileSync(`${directory}/registers.bin`);
assert.equal(oracle.schema, 1);
assert.equal(oracle.specimen_sha256, '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86');
assert.equal(oracle.emulator, 'Unicorn 2.1.4');
assert.equal(createHash('sha256').update(records).digest('hex'), oracle.registers_sha256);
assert.deepEqual(oracle.original_instructions_reached, [12, 5, 3]);
const SP = 0x20000800, STOP = 0x30000000, RECEIVER = 0x10000000, MATCH = 0x11000000;
type Row = [number, number, number, number, number, number];
const rows: Row[] = [];
for (let a = 0; a < 256; a++) for (let b = 0; b < 256; b++) rows.push([1, RECEIVER + (b % 4) * 13, MATCH, a, b, rows.length]);
for (let b = 0; b < 256; b++) rows.push([2, RECEIVER + (b % 4) * 13, MATCH, 255 - b, b, rows.length]);
for (const receiver of [RECEIVER, RECEIVER + 1, RECEIVER + 0xe5e])
  for (const match of [MATCH, MATCH + 1, MATCH + 0xa7a])
    for (const seed of [0, 1, 255, 0xffff]) rows.push([0, receiver, match, 0xa5, 0, seed]);
for (const kind of [1, 2]) for (const arg of [0, 0xff, 0x100, 0x7fffffff, 0x80000000, 0xffffffff])
  rows.push([kind, RECEIVER + 0xfd4, MATCH, 255, arg, rows.length]);
assert.equal(rows.length, oracle.cases);
assert.equal(records.length, rows.length * 12);
const templates = new Map<string, Uint8Array>();
class Memory implements MicroMemory {
  regions: Map<number, Uint8Array>;
  reads: number[][] = [];
  writes: number[][] = [];
  constructor(row: Row) {
    const [kind, receiver, match, initial, argument, seed] = row;
    this.regions = new Map((kind === 0 ? [RECEIVER, MATCH, 0x20000000] : [RECEIVER, 0x20000000]).map(base => {
      const key = `${base}-${seed & 255}`;
      if (!templates.has(key)) templates.set(key, Uint8Array.from({ length: base === MATCH ? 65536 : 4096 },
        (_, i) => (i * 29 + (base / 4096) * 7 + seed * 3 + 0x53) & 255));
      return [base, templates.get(key)!.slice()];
    }));
    this.put(receiver + 0x2b, 1, initial);
    if (kind === 0) this.put(receiver + 0x19e, 4, match);
    this.put(SP, 4, STOP); this.put(SP + 4, 4, argument);
  }
  locate(address: number, size: number): [Uint8Array, number] {
    for (const [base, bytes] of this.regions) if (base <= address && address + size <= base + bytes.length) return [bytes, address - base];
    throw new RangeError('outside synthetic memory');
  }
  put(address: number, size: number, value: number): void {
    const [bytes, offset] = this.locate(address, size);
    for (let i = 0; i < size; i++) bytes[offset + i] = value >>> (i * 8);
  }
  read8(address: number): number { this.reads.push([address, 1, 0]); const [b, i] = this.locate(address, 1); return b[i]; }
  read32(address: number): number {
    this.reads.push([address, 4, 0]); const [b, i] = this.locate(address, 4);
    return new DataView(b.buffer).getUint32(i, true);
  }
  write(address: number, size: number, value: number): void { this.writes.push([address, size, value]); this.put(address, size, value); }
  write8(a: number, v: number): void { this.write(a, 1, v); }
  write16(a: number, v: number): void { this.write(a, 2, v); }
  write32(a: number, v: number): void { this.write(a, 4, v); }
  snapshot(): Buffer { return Buffer.concat([...this.regions.values()]); }
}
const hashes = Object.fromEntries(['before_memory', 'after_memory', 'reads', 'writes'].map(name => [name, createHash('sha256')]));
function encode(accesses: number[][]): Buffer {
  const bytes = Buffer.alloc(4 + accesses.length * 12);
  bytes.writeUInt32LE(accesses.length, 0);
  for (let i = 0; i < accesses.length; i++) for (let j = 0; j < 3; j++) bytes.writeUInt32LE(accesses[i][j], 4 + i * 12 + j * 4);
  return bytes;
}
function state(seed: number): MicroRegisters {
  return { eax: (0xa1230000 + seed * 0x10201) >>> 0, edx: (0xb2340000 + seed * 0x20103) >>> 0,
    eflags: [0x202, 0xad7, 0x246, 0x293][seed % 4] };
}
const counts = [0, 0, 0];
for (let index = 0; index < rows.length; index++) {
  const row = rows[index], [kind, receiver, , , argument, seed] = row;
  const memory = new Memory(row), before = memory.snapshot(), initial = state(seed);
  if (kind !== 0) memory.reads.push([SP + 4, 1, 0]);
  const value = kind === 0 ? resetMatchMicrostate(receiver, initial, memory)
    : kind === 1 ? addReceiverByte(receiver, argument, initial, memory) : setReceiverByte(receiver, argument, initial, memory);
  memory.reads.push([SP, 4, 0]);
  if (mutation === 'upper-eax-cleared' && kind !== 0) value.eax &= 255;
  if (mutation === 'edx-preserved-on-add' && kind === 1) value.edx = initial.edx;
  if (mutation === 'flags-preserved-on-add' && kind === 1) value.eflags = initial.eflags;
  if (mutation === 'no-byte-wrap' && kind === 1) value.edx = ((initial.edx & 0xffffff00) + row[3] + (argument & 255)) >>> 0;
  assert.deepEqual([value.eax, value.edx, value.eflags], [records.readUInt32LE(index * 12), records.readUInt32LE(index * 12 + 4), records.readUInt32LE(index * 12 + 8)], `case ${index} registers`);
  // Access order/width has a per-case independent contract and aggregate native digest.
  if (kind === 0) {
    assert.deepEqual(memory.reads, [...Array.from({ length: 4 }, () => [receiver + 0x19e, 4, 0]), [SP, 4, 0]]);
    const match = row[2];
    assert.deepEqual(memory.writes, [[match + 0x4786, 4, 0], [match + 0x8eae, 1, 255], [match + 0xf582, 4, 0], [match + 0x1a7, 1, 0], [receiver + 0x29, 2, 0], [receiver + 0x19c, 2, 0]]);
  } else {
    assert.deepEqual(memory.reads, kind === 1 ? [[SP + 4, 1, 0], [receiver + 0x2b, 1, 0], [SP, 4, 0]] : [[SP + 4, 1, 0], [SP, 4, 0]]);
    assert.deepEqual(memory.writes, [[receiver + 0x2b, 1, kind === 1 ? (row[3] + (argument & 255)) & 255 : argument & 255]]);
  }
  // Access mutants must fail the retained native digest, independently of the
  // authored per-case access contracts above.
  if (mutation === 'wrong-byte-offset' && kind !== 0) memory.writes[0][0]++;
  if (mutation === 'wrong-write-width' && kind === 0) memory.writes[0][1] = 2;
  if (mutation === 'reset-write-order' && kind === 0) [memory.writes[0], memory.writes[1]] = [memory.writes[1], memory.writes[0]];
  if (mutation === 'cached-reset-pointer' && kind === 0) memory.reads.splice(1, 3);
  hashes.before_memory.update(before); hashes.after_memory.update(memory.snapshot());
  hashes.reads.update(encode(memory.reads)); hashes.writes.update(encode(memory.writes)); counts[kind]++;
}
for (const [name, hash] of Object.entries(hashes)) assert.equal(hash.digest('hex'), oracle.whole_memory_and_access_sha256[name], name);
assert.deepEqual(counts, oracle.counts);
let invalidInputs = 0;
for (const invalid of [-1, 0x100000000, 0.5, NaN, Infinity]) {
  for (const helper of [resetMatchMicrostate, addReceiverByte, setReceiverByte]) {
    const memory = new Memory(rows[0]);
    if (helper === resetMatchMicrostate) assert.throws(() => resetMatchMicrostate(invalid, state(0), memory), RangeError);
    else assert.throws(() => helper(RECEIVER, invalid, state(0), memory), RangeError);
    assert.equal(memory.reads.length + memory.writes.length, 0); invalidInputs++;
  }
}
writeFileSync(output, JSON.stringify({ status: 'passed', node: process.version, cases: oracle.cases, counts,
  invalid_js_inputs_rejected_before_effects: invalidInputs, original_instructions_reached: oracle.original_instructions_reached,
  oracle_sha256: createHash('sha256').update(readFileSync(`${directory}/oracle.json`)).digest('hex'),
  comparisons: 'EAX/EDX/EFLAGS, ordered reads/writes with widths, all mapped synthetic memory; native ECX/callee-saved/ESP/EIP observations',
  limitations: oracle.limitations }, null, 2) + '\n');
console.log(`Match microhelpers: ${oracle.cases} original-instruction cases passed.`);

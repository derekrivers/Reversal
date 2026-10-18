import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { crtStep, nextBounded } from './bounded-random.ts';

const [oraclePath, tablePath, output] = process.argv.slice(2);
if (!output) throw new Error('Usage: node check-random.ts oracle.json random-table.bin result.json');
const oracle = JSON.parse(readFileSync(oraclePath, 'utf8'));
const bytes = readFileSync(tablePath);
assert.equal(createHash('sha256').update(bytes).digest('hex'), oracle.table.sha256);
const table = Array.from({ length: bytes.length / 4 }, (_, i) => bytes.readUInt32LE(i * 4));
let crtSteps = 0, boundedCalls = 0;
for (const test of oracle.crt) {
  const state = { cursorIndex: 0, offset: 0, crtState: test.seed };
  for (const step of test.steps) {
    assert.equal(crtStep(state), step.value);
    assert.equal(state.crtState, step.state);
    crtSteps++;
  }
}
for (const test of oracle.bounded_cases) {
  const state = { ...test.initial };
  assert.equal(nextBounded(test.bound, state, table), test.value);
  assert.deepEqual(state, test.final);
  boundedCalls++;
}
const stream = { ...oracle.sequential_cases[0].initial };
for (const test of oracle.sequential_cases) {
  assert.deepEqual(stream, test.initial);
  assert.equal(nextBounded(test.bound, stream, table), test.value);
  assert.deepEqual(stream, test.final);
  boundedCalls++;
}
const result = { status: 'passed', sha256: oracle.sha256, oracle: oracle.oracle,
  node: process.version, crtSteps, boundedCalls, comparisons: 'return values and all exposed RNG state',
  limitations: oracle.limitations };
writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));

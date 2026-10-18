import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { eventMinute } from './match-clock.ts';
const [metaPath, bytesPath, output] = process.argv.slice(2);
if (!output) throw new Error('Usage: node check-clock.ts clock-oracle.json clock-oracle.bin result.json');
const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
const oracle = readFileSync(bytesPath);
assert.equal(createHash('sha256').update(oracle).digest('hex'), meta.oracle_sha256);
assert.equal(oracle.length, meta.modes.length * 65536);
let cases = 0;
for (const mode of meta.modes) {
  for (let raw = 0; raw <= 65535; raw++) {
    assert.equal(eventMinute(mode, raw), oracle[cases], `mode=${mode}, rawClock=${raw}`);
    cases++;
  }
}
const result = { status: 'passed', sha256: meta.sha256, cases, modes: meta.modes,
  oracle: meta.oracle, slice: [meta.slice_start, meta.slice_end_exclusive],
  node: process.version, limitations: meta.limitations };
writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result, null, 2));

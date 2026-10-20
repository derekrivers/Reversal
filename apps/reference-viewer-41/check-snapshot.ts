import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { parseSnapshot } from './snapshot.ts';

const original = JSON.parse(readFileSync(new URL('./synthetic-example.json', import.meta.url), 'utf8'));
assert.equal(parseSnapshot(original).profile.playerId, 'example-keeper');
const unchanged = JSON.stringify(original);
parseSnapshot(original);
assert.equal(JSON.stringify(original), unchanged, 'Parsing must preserve supplied values');
const rejected: string[] = [];
for (const [name, change] of [
  ['duplicate player ID', (v: any) => { v.squad.rows[1].id = v.squad.rows[0].id; }],
  ['orphan profile', (v: any) => { v.profile.playerId = 'unknown'; }],
  ['missing capture', (v: any) => { v.profile.captureId = 'unknown'; }],
  ['unsupported game command', (v: any) => { v.command = 'advance'; }],
  ['missing captured identities', (v: any) => { v.kind = 'captured-read-only'; }],
  ['oversized text', (v: any) => { v.squad.rows[0].name = 'x'.repeat(181); }],
  ['wrong resolution', (v: any) => { v.provenance.resolution.width = 1024; }],
  ['unbounded rows', (v: any) => { v.squad.rows = Array(51).fill(v.squad.rows[0]); }],
] as const) {
  const changed = structuredClone(original);
  change(changed);
  assert.throws(() => parseSnapshot(changed), undefined, name);
  rejected.push(name);
}
console.log(JSON.stringify({ snapshotValidation: 'pass', meaningfulRejections: rejected }));

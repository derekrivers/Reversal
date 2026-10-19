#!/usr/bin/env node
// Check the bounded action33 dependency map. This is a provenance/schema check,
// not evidence that the listed path reaches a complete gameplay result.
import {strict as assert} from 'node:assert';
import {readFileSync, existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';

const read = path => JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), 'utf8'));
const present = path => existsSync(new URL(`../${path}`, import.meta.url));
const hex = value => typeof value === 'string' && /^[0-9a-f]{8}$/.test(value);
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const unique = (rows, key) => assert.equal(new Set(rows.map(row => row[key])).size, rows.length, `duplicate ${key}`);
const source = path => {
  assert.match(path, /^(reports|docs|evidence)\/[a-zA-Z0-9/_-]+\.(md|json)$/);
  assert.ok(present(path), `missing source ${path}`);
};

const map = read('evidence/code-atlas/action33-frontier.json');
const specimen = '0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86';
assert.equal(map.schema, 1);
assert.equal(map.specimen_sha256, specimen);
assert.ok(nonempty(map.scenario) && nonempty(map.claim));
assert.match(map.claim, /synthetic mapped state/);
assert.match(map.claim, /no full-entry TypeScript equivalence or completed outcome/);
for (const key of ['structural', 'local_static', 'typescript', 'original_instruction', 'connected_execution', 'original_game_lifecycle', 'outcome'])
  assert.ok(nonempty(map.milestone_status[key]), `missing milestone status ${key}`);
assert.equal(map.milestone_status.original_game_lifecycle, 'unobserved');
assert.equal(map.milestone_status.outcome, 'unresolved');
assert.ok(Array.isArray(map.sources) && map.sources.length > 0);
unique(map.sources.map(path => ({path})), 'path');
map.sources.forEach(source);

assert.ok(Array.isArray(map.functions) && map.functions.length > 0);
unique(map.functions, 'address');
const functions = new Set(map.functions.map(row => row.address));
for (const row of map.functions) {
  assert.ok(hex(row.address) && nonempty(row.role));
  assert.ok(nonempty(row.local_status) && nonempty(row.execution_status));
}
for (const address of ['006be710', '00700bd0', '00702050', '006ce110', '006cfe10', '0062ed70'])
  assert.ok(functions.has(address), `missing dependency ${address}`);

assert.ok(Array.isArray(map.ordered_constraints) && map.ordered_constraints.length > 0);
unique(map.ordered_constraints, 'site');
for (const row of map.ordered_constraints) {
  assert.ok(hex(row.site) && functions.has(row.owner), `invalid call site or owner ${row.site}`);
  if (row.target !== undefined) assert.ok(functions.has(row.target), `unknown target ${row.target}`);
  assert.ok(nonempty(row.event) && nonempty(row.when));
  source(row.source);
}
const observed = map.edge_observation.original_instruction_synthetic_sites;
const staticOrUnreached = map.edge_observation.static_or_unreached_sites;
assert.ok(Array.isArray(observed) && Array.isArray(staticOrUnreached));
const classified = [...observed, ...staticOrUnreached];
unique(classified.map(site => ({site})), 'site');
assert.deepEqual(new Set(classified), new Set(map.ordered_constraints.map(row => row.site)));
assert.ok(staticOrUnreached.includes('0062ed99'), 'diagnostic call must remain unreached');
const pinnedOracle = (path, sha256) => {
  const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256, `changed ${path}`);
  return JSON.parse(gunzipSync(bytes));
};
const prefixOracle = pinnedOracle('evidence/action33-prefix-30-oracle.bin', '08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f');
const effectOracle = pinnedOracle('evidence/action33-effect-30-oracle.bin', 'ddf4a92864ef02dd7027d9311e5e615b7b0c75a2625eb9cb87dd6e915bc21472');
const bySite = new Map(map.ordered_constraints.map(row => [row.site, row]));
const reached = new Set();
const callTargets = new Map();
for (const trace of [...prefixOracle.cases, ...effectOracle.cases]) {
  for (const call of trace.call_trace) {
    if (!bySite.has(call.site)) continue;
    reached.add(call.site);
    if (callTargets.has(call.site)) assert.equal(callTargets.get(call.site), call.target, `varying target ${call.site}`);
    callTargets.set(call.site, call.target);
  }
  for (const draw of trace.rng) if (bySite.has(draw.site)) reached.add(draw.site);
}
assert.deepEqual(new Set(observed), reached, 'observed sites must be reached in retained original traces');
for (const [site, target] of callTargets) assert.equal(bySite.get(site).target, target, `wrong observed target ${site}`);
for (const site of observed) if (!callTargets.has(site)) assert.equal(bySite.get(site).target, undefined, `draw cannot have a call target ${site}`);
assert.ok(Array.isArray(map.state_requirements) && map.state_requirements.length > 0);
unique(map.state_requirements, 'field');
for (const row of map.state_requirements)
  assert.ok(nonempty(row.field) && nonempty(row.producer) && nonempty(row.gap));

const prefix = read('evidence/action33-prefix-30-integrity.json');
const effect = read('evidence/action33-effect-30-integrity.json');
const composition = read('evidence/action33-composition-30-integrity.json');
const grid = read('evidence/action33-grid-31-integrity.json');
const lifecycle = read('evidence/action33-lifecycle-31-validation.json');
assert.equal(prefix.specimen_sha256, specimen);
assert.equal(effect.specimen_sha256, specimen);
assert.equal(grid.specimen_sha256, specimen);
assert.equal(lifecycle.specimen_sha256, specimen);
assert.equal(map.completed_prefix.entry, '00702050');
assert.equal(map.completed_prefix.stop_before, '007024b4');
assert.equal(map.completed_prefix.cases, prefix.cases);
assert.equal(map.completed_prefix.original_instruction_steps, prefix.original_instruction_steps);
assert.equal(map.continued_effect.entry, '007024b4');
assert.equal(map.continued_effect.stop_before, '0062ed99');
assert.equal(map.continued_effect.cases, effect.cases);
assert.equal(effect.effect_returns, 0);
assert.equal(effect.diagnostic_stops, effect.cases);
assert.equal(map.continued_effect.additional_original_instruction_steps, 27390);
assert.equal(map.continued_effect.additional_rng_calls, 764);
for (const section of [map.completed_prefix, map.continued_effect]) {
  assert.ok(nonempty(section.domain));
  source(section.source);
}
const entry = map.typescript_entry_prefix;
assert.equal(entry.entry, '00702050');
assert.equal(entry.stop_before, '0070210b');
assert.equal(entry.cases, grid.coverage.prefix_cases);
assert.equal(entry.helper_cases, grid.coverage.helper_cases);
assert.equal(entry.original_instruction_steps, grid.coverage.instructions);
assert.equal(entry.ordered_data_events, grid.coverage.events);
assert.equal(entry.rng_calls, grid.coverage.rng_calls);
assert.match(entry.domain, /unjoined/);
assert.ok(nonempty(entry.domain));
source(entry.source);
const gridOracle = readFileSync(new URL('../evidence/action33-grid-31-oracle.bin', import.meta.url));
assert.equal(createHash('sha256').update(gridOracle).digest('hex'), grid.oracle_sha256);
assert.equal(map.typescript_composition.start, '007022fd');
assert.equal(map.typescript_composition.stop_before, '007024b4');
assert.equal(map.typescript_composition.first_full_entry_gap, '0070210b -> 006d59b0');
source(map.typescript_composition.first_full_entry_gap_source);
assert.match(readFileSync(new URL(`../${map.typescript_composition.first_full_entry_gap_source}`, import.meta.url), 'utf8'), /0070210b.*006d59b0/);
assert.equal(map.typescript_composition.cases, composition.coverage.cases);
assert.equal(map.typescript_composition.selector_events, composition.coverage.selector_events);
assert.equal(map.typescript_composition.game_writes, composition.coverage.game_writes);
assert.equal(map.typescript_composition.rng_calls, composition.coverage.draws);
assert.match(composition.scope, /supplied original-produced 007022fd checkpoint through 007024b4/);
assert.ok(nonempty(map.typescript_composition.domain));
source(map.typescript_composition.source);
const fixture = map.lifecycle_fixture;
assert.equal(fixture.lookup_returns, lifecycle.coverage.lookup_returns);
assert.equal(fixture.placement_frontiers, lifecycle.coverage.placement_frontiers);
assert.equal(fixture.nonnull_status_frontiers, lifecycle.coverage.normal_status_frontiers);
assert.equal(fixture.null_diagnostic_frontiers, lifecycle.coverage.null_diagnostic_frontiers);
assert.equal(fixture.constructor_os_frontiers, lifecycle.coverage.constructor_os_frontiers);
assert.equal(fixture.original_instruction_steps, lifecycle.coverage.instruction_steps);
assert.match(fixture.domain, /separate.*synthetic/);
source(fixture.source);
const lifecycleOracle = readFileSync(new URL('../evidence/action33-lifecycle-31-oracle.bin', import.meta.url));
assert.equal(createHash('sha256').update(lifecycleOracle).digest('hex'), lifecycle.evidence_sha256);

assert.ok(Array.isArray(map.frontier) && map.frontier.length > 0);
unique(map.frontier, 'id');
for (const row of map.frontier) {
  assert.ok(nonempty(row.id) && hex(row.first_site));
  assert.ok(nonempty(row.requirement) && nonempty(row.next_assignment));
}
const rendered = execFileSync(process.execPath, [fileURLToPath(new URL('./render-action33-frontier.mjs', import.meta.url))], {encoding: 'utf8'});
assert.equal(readFileSync(new URL('../reports/action33-frontier-30.md', import.meta.url), 'utf8').replace(/\r\n/g, '\n'), rendered, 'stale generated frontier report');
process.stdout.write(`Action33 frontier: ${map.functions.length} functions, ${map.ordered_constraints.length} ordered constraints, ${map.frontier.length} unresolved dependencies; synthetic prefix only.\n`);

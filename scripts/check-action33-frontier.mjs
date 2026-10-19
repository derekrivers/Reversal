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
for (const address of ['006be710', '00700bd0', '00702050', '006ce110', '006cfe10', '0062ed70', '0084be20', '0094bef1', '006b7f20', '004cf5f0', '004c7040'])
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
assert.ok(observed.includes('006eafa0'), 'R34-B entered the contract call');
assert.ok(staticOrUnreached.includes('004cf62b'), 'auxiliary row read remains unreached');
assert.ok(staticOrUnreached.includes('004c7073'), 'constructor OS call remains unreached');
assert.ok(staticOrUnreached.includes('0094bf49'), 'selector CRT HeapSize remains unreached');
const pinnedOracle = (path, sha256) => {
  const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256, `changed ${path}`);
  return JSON.parse(gunzipSync(bytes));
};
const prefixOracle = pinnedOracle('evidence/action33-prefix-30-oracle.bin', '08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f');
const effectOracle = pinnedOracle('evidence/action33-effect-30-oracle.bin', 'ddf4a92864ef02dd7027d9311e5e615b7b0c75a2625eb9cb87dd6e915bc21472');
const ownerOracle = pinnedOracle('evidence/action33-owner-33-oracle.bin', 'f5dbbdff245eda8bbe946430461a93c76b8dd971e0d2d52e89d667c45681eafd');
const conversionOracle = pinnedOracle('evidence/action33-conversion-33-oracle.bin', '1fc3bf7c687abec08597d8e9eb66d0abb3a871e7a156075d4b195ad8fa4b79ee');
const adjustmentOracle = pinnedOracle('evidence/action33-adjustment-34-oracle.bin', 'b18307489d5adeaa2026ad17f214404b5ac43a400bcecfd0fab6665713511e30');
const contractOracle = pinnedOracle('evidence/action33-contract-34-oracle.bin', '82e51c46fe98ba06551c184d2d3e811ffdb67dde9aad171c8a7ef05f68f344e5');
const rngOracle = pinnedOracle('evidence/action33-rng-35-oracle.bin', 'edb057f22e3b5eec75ca0583a03f0b1c291e2ec96403cbf7efb61bf8d31f3a32');
const auxOracle = pinnedOracle('evidence/action33-aux-35-oracle.bin', 'bfd41a4760cd2f1b32e83a48c03a37e298f2e9de2448b425c12d1d23863d3d43');
const selectorOracle = pinnedOracle('evidence/action33-fixture-35-oracle.bin', '85625c272b1c8383805a8a1169ab2e4fc5eb12f541a5ac370ae06774b906a53a');
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
for (const specimenCase of ownerOracle.oracle.cases) {
  for (const stage of [specimenCase.binding, specimenCase.placement]) {
    for (const [site,target] of stage.calls) {
      if (!bySite.has(site)) continue;
      reached.add(site);
      if (callTargets.has(site)) assert.equal(callTargets.get(site), target, `varying target ${site}`);
      callTargets.set(site,target);
    }
  }
}
let secondGridCalls = 0;
for (const specimenCase of conversionOracle.cases) {
  for (const call of specimenCase.calls) {
    if (!bySite.has(call.site)) continue;
    if (call.site === '007021e5') secondGridCalls++;
    reached.add(call.site);
    if (callTargets.has(call.site)) assert.equal(callTargets.get(call.site), call.target, `varying target ${call.site}`);
    callTargets.set(call.site, call.target);
  }
}
assert.equal(secondGridCalls, 232, 'R33-A clear cases must reach the second grid call');
let adjustmentCalls = 0;
for (const specimenCase of adjustmentOracle.cases) {
  for (const call of specimenCase.calls) {
    if (call.site === '00702222') adjustmentCalls++;
    if (!bySite.has(call.site)) continue;
    reached.add(call.site);
    if (callTargets.has(call.site)) assert.equal(callTargets.get(call.site), call.target, `varying target ${call.site}`);
    callTargets.set(call.site, call.target);
  }
}
assert.equal(adjustmentCalls, 232, 'R34-A clear cases must enter the early adjustment');
let contractCalls = 0;
for (const specimenCase of contractOracle.oracle.placement_calls) {
  for (const [site, target] of specimenCase.continuation.calls) {
    if (site === '006eafa0') contractCalls++;
    if (!bySite.has(site)) continue;
    reached.add(site);
    if (callTargets.has(site)) assert.equal(callTargets.get(site), target, `varying target ${site}`);
    callTargets.set(site, target);
  }
}
assert.equal(contractCalls, 80, 'R34-B placement must enter the contract lookup');
let zeroBoundCalls = 0;
for (const specimenCase of rngOracle.cases) {
  for (const call of specimenCase.calls) {
    if (call.site === '00702241') zeroBoundCalls++;
    if (!bySite.has(call.site)) continue;
    reached.add(call.site);
    if (callTargets.has(call.site)) assert.equal(callTargets.get(call.site), call.target, `varying target ${call.site}`);
    callTargets.set(call.site, call.target);
  }
}
assert.equal(zeroBoundCalls, 232, 'R35-A clear cases must execute zero-bound RNG');
assert.equal(selectorOracle.oracle.cases.length, 8);
for (const specimenCase of selectorOracle.oracle.cases) {
  assert.equal(specimenCase.next_call.site, '0094bf49');
  assert.equal(specimenCase.next_call.symbol, 'HeapSize');
  assert.equal(specimenCase.next_call.executed, false);
}
assert.equal(auxOracle.oracle.unit, 'R35-B');
assert.deepEqual(new Set(observed), reached, 'observed sites must be reached in retained original traces');
for (const [site, target] of callTargets) assert.equal(bySite.get(site).target, target, `wrong observed target ${site}`);
for (const site of observed) if (!callTargets.has(site)) assert.equal(bySite.get(site).target, undefined, `draw cannot have a call target ${site}`);
assert.ok(Array.isArray(map.state_requirements) && map.state_requirements.length > 0);
unique(map.state_requirements, 'field');
for (const row of map.state_requirements)
  assert.ok(nonempty(row.field) && nonempty(row.producer) && nonempty(row.gap));
const fixturePointer = map.state_requirements.find(row => row.field === 'match/context+0x4792 fixture pointer -> fixture/owner+0x1c/+0x20 club state');
assert.ok(fixturePointer, 'fixture pointer and club fields must retain distinct bases');
assert.match(fixturePointer.producer, /0084c266.*0084c3e8.*006b7f20/);
assert.doesNotMatch(JSON.stringify(map), /owner\+0x4792/, 'owner is not the base of the +0x4792 field');

const prefix = read('evidence/action33-prefix-30-integrity.json');
const effect = read('evidence/action33-effect-30-integrity.json');
const composition = read('evidence/action33-composition-30-integrity.json');
const grid = read('evidence/action33-grid-31-integrity.json');
const lifecycle = read('evidence/action33-lifecycle-31-validation.json');
const opponent = read('evidence/action33-opponent-32-integrity.json');
const slot = read('evidence/action33-slot-32-validation.json');
const conversion = read('evidence/action33-conversion-33-integrity.json');
const owner = read('evidence/action33-owner-33-validation.json');
const adjustment = read('evidence/action33-adjustment-34-integrity.json');
const contract = read('evidence/action33-contract-34-validation.json');
const rng = read('evidence/action33-rng-35-integrity.json');
const aux = read('evidence/action33-aux-35-validation.json');
const selector = read('evidence/action33-fixture-35-validation.json');
assert.equal(prefix.specimen_sha256, specimen);
assert.equal(effect.specimen_sha256, specimen);
assert.equal(grid.specimen_sha256, specimen);
assert.equal(lifecycle.specimen_sha256, specimen);
assert.equal(opponent.specimen_sha256, specimen);
assert.equal(slot.specimen_sha256, specimen);
assert.equal(conversion.specimen_sha256, specimen);
assert.equal(owner.specimen_sha256, specimen);
assert.equal(adjustment.specimen_sha256, specimen);
assert.equal(contract.specimen_sha256, specimen);
assert.equal(rng.specimen_sha256, specimen);
assert.equal(aux.specimen_sha256, specimen);
assert.equal(selector.specimen_sha256, specimen);
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
const guarded = map.typescript_guarded_continuation;
assert.equal(guarded.entry, '00702050');
assert.equal(guarded.clear_stop_before, '00702193');
assert.equal(guarded.guard_set_stop_before, '0071614b');
for (const [field, receiptField] of [['cases','cases'], ['guard_clear','guard_clear'], ['guard_set','guard_set'], ['original_instruction_steps','instructions'], ['ordered_data_events','events'], ['rng_calls','rng_calls']])
  assert.equal(guarded[field], opponent.coverage[receiptField]);
assert.equal(guarded.source, 'reports/action33-opponent-32.md');
assert.match(guarded.domain, /unjoined/);
source(guarded.source);
const opponentOracle = readFileSync(new URL('../evidence/action33-opponent-32-oracle.bin', import.meta.url));
assert.equal(createHash('sha256').update(opponentOracle).digest('hex'), opponent.oracle_sha256);
const continued = map.typescript_conversion_continuation;
assert.equal(continued.entry, '00702050');
assert.equal(continued.clear_stop_before, '00702222');
assert.equal(continued.guard_set_stop_before, '0071614b');
for (const [field, receiptField] of [['cases','cases'], ['guard_clear','guard_clear'], ['guard_set','guard_set'], ['separate_rounding_probes','rounding_probes'], ['original_instruction_steps','instructions'], ['ordered_data_events','events'], ['rng_calls','rng_calls']])
  assert.equal(continued[field], conversion.coverage[receiptField]);
assert.equal(continued.source, 'reports/action33-conversion-33.md');
assert.match(continued.domain, /unjoined/);
assert.match(continued.domain, /hardware x87 exception\/status equivalence excluded/);
source(continued.source);
assert.equal(conversion.oracle_sha256, '1fc3bf7c687abec08597d8e9eb66d0abb3a871e7a156075d4b195ad8fa4b79ee');
assert.equal(adjustment.oracle_sha256, 'b18307489d5adeaa2026ad17f214404b5ac43a400bcecfd0fab6665713511e30');
const adjusted = map.typescript_adjustment_continuation;
assert.equal(adjusted.entry, '00702050');
assert.equal(adjusted.clear_stop_before, '00702241');
for (const [field, receiptField] of [['cases','cases'], ['original_instruction_steps','instructions'], ['ordered_data_events','events'], ['rng_calls','rng_calls']])
  assert.equal(adjusted[field], adjustment.coverage[receiptField]);
assert.equal(adjusted.source, 'reports/action33-adjustment-34.md');
assert.match(adjusted.domain, /unjoined/);
source(adjusted.source);
assert.equal(rng.oracle_sha256, 'edb057f22e3b5eec75ca0583a03f0b1c291e2ec96403cbf7efb61bf8d31f3a32');
const drawn = map.typescript_rng_continuation;
assert.equal(drawn.entry, '00702050');
assert.equal(drawn.clear_stop_before, '0070230c');
for (const [field, receiptField] of [['cases','cases'], ['original_instruction_steps','instructions'], ['ordered_data_events','events'], ['rng_calls','rng_calls'], ['suffix_states','suffix_states'], ['r30c_input_projections','r30c_projections']])
  assert.equal(drawn[field], rng.coverage[receiptField]);
assert.equal(drawn.source, 'reports/action33-rng-35.md');
assert.match(drawn.domain, /full machine-state join.*unproven/);
source(drawn.source);
assert.equal(map.typescript_composition.start, '007022fd');
assert.equal(map.typescript_composition.stop_before, '007024b4');
assert.equal(map.typescript_composition.first_full_entry_gap, '0070230c -> 006ce110 (clear); 0071614b -> 005b58e0 (bit-04 set)');
assert.equal(map.typescript_composition.first_full_entry_gap_source, 'reports/action33-rng-35.md');
source(map.typescript_composition.first_full_entry_gap_source);
const gapReport = readFileSync(new URL(`../${map.typescript_composition.first_full_entry_gap_source}`, import.meta.url), 'utf8');
assert.match(gapReport, /0070230c.*006ce110/);
assert.match(gapReport, /0071614b.*005b58e0/);
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
const slotFixture = map.slot_fixture;
for (const [field, receiptField] of [['initializer_returns','initializer_returns'], ['lookup_returns','lookup_returns'], ['placement_frontiers','placement_frontiers'], ['nonnull_status_frontiers','normal_status_frontiers'], ['original_instruction_steps','instruction_steps']])
  assert.equal(slotFixture[field], slot.coverage[receiptField]);
assert.equal(slotFixture.first_placement_gap, '006eaf8f');
assert.equal(slotFixture.source, 'reports/action33-slot-32.md');
assert.match(slotFixture.domain, /separate.*synthetic/);
source(slotFixture.source);
const slotOracle = readFileSync(new URL('../evidence/action33-slot-32-oracle.bin', import.meta.url));
assert.equal(createHash('sha256').update(slotOracle).digest('hex'), slot.evidence_sha256);
const producer = map.fixture_producer_continuation;
for (const field of ['interior_fixture_producers', 'interior_caller_bindings', 'initializer_returns', 'lookup_returns', 'placement_frontiers'])
  assert.equal(producer[field], owner.coverage[field]);
assert.equal(producer.original_instruction_steps, owner.coverage.instruction_steps);
assert.equal(producer.first_placement_gap, '006eafa0');
assert.equal(producer.source, 'reports/action33-owner-33.md');
assert.match(producer.domain, /interior.*separate.*synthetic/);
source(producer.source);
assert.equal(owner.evidence_sha256, 'f5dbbdff245eda8bbe946430461a93c76b8dd971e0d2d52e89d667c45681eafd');
assert.equal(contract.evidence_sha256, '82e51c46fe98ba06551c184d2d3e811ffdb67dde9aad171c8a7ef05f68f344e5');
const lookup = map.contract_lookup_continuation;
for (const [field, receiptField] of [['placement_call_prefixes','placement_call_prefixes'], ['constructor_os_frontiers','constructor_os_frontiers'], ['original_instruction_steps','instruction_steps']])
  assert.equal(lookup[field], contract.coverage[receiptField]);
assert.equal(lookup.first_lookup_gap, '004cf62b');
assert.match(bySite.get('004cf62b').event, /signed primary row index.*auxiliary record\+0/);
assert.equal(lookup.constructor_os_gap, '004c7073');
assert.equal(lookup.source, 'reports/action33-contract-34.md');
assert.match(lookup.domain, /separate constructor entry/);
source(lookup.source);
assert.equal(aux.evidence_sha256, 'bfd41a4760cd2f1b32e83a48c03a37e298f2e9de2448b425c12d1d23863d3d43');
const allocation = map.auxiliary_allocation_frontier;
assert.equal(allocation.allocation_request_windows, aux.coverage.allocation_request_windows);
assert.equal(allocation.original_instruction_steps, aux.coverage.instruction_steps);
assert.equal(allocation.native_compared_instructions, aux.native_compared_instructions);
assert.equal(allocation.pe_only_decoded_instructions, aux.pe_only_decoded_instructions);
assert.equal(allocation.new_setup_gap, '008284ad');
assert.equal(allocation.save_load_gap, '0082af61');
assert.match(map.state_requirements.find(row => row.field === 'global 00ae2d0c auxiliary record base')?.producer ?? '', new RegExp(auxOracle.sites.static_lifecycle.load_publish));
assert.equal(allocation.source, 'reports/action33-aux-35.md');
source(allocation.source);
assert.equal(selector.evidence_sha256, '85625c272b1c8383805a8a1169ab2e4fc5eb12f541a5ac370ae06774b906a53a');
const selecting = map.fixture_selector_entry;
for (const [field, receiptField] of [['selector_entries','selector_entries'], ['caller_interior_windows','caller_interior_windows'], ['produced_date_initializers','produced_date_initializers'], ['original_instruction_steps','instruction_steps']])
  assert.equal(selecting[field], selector.coverage[receiptField]);
assert.equal(selecting.native_operand_instructions, selector.native_operand_instructions);
assert.equal(selecting.pe_only_instructions, selector.pe_only_instructions);
assert.equal(selecting.first_os_gap, '0094bf49');
assert.equal(selecting.source, 'reports/action33-fixture-35.md');
assert.match(selecting.domain, /no selection.*entry-to-R33-B interior connection/);
source(selecting.source);
assert.equal(map.frontier.find(row => row.id === 'typescript_prefix')?.first_site, '0070230c');
assert.equal(map.frontier.find(row => row.id === 'early_guard')?.first_site, '0071614b');
assert.equal(map.frontier.find(row => row.id === 'normal_participant_state')?.first_site, '004cf62b');
assert.equal(map.frontier.find(row => row.id === 'fixture_selector_lifecycle')?.first_site, '0094bf49');

assert.ok(Array.isArray(map.frontier) && map.frontier.length > 0);
unique(map.frontier, 'id');
for (const row of map.frontier) {
  assert.ok(nonempty(row.id) && hex(row.first_site));
  assert.ok(nonempty(row.requirement) && nonempty(row.next_assignment));
}
const queue = readFileSync(new URL('../coordination/QUEUE.md', import.meta.url), 'utf8');
for (const [id, assignment] of [['typescript_prefix', 'R36-A'], ['normal_participant_state', 'R36-B'], ['fixture_selector_lifecycle', 'R36-C']]) {
  assert.match(queue, new RegExp(`\\| ${assignment} \\|`), `missing queue assignment ${assignment}`);
  assert.match(map.frontier.find(row => row.id === id)?.next_assignment ?? '', new RegExp(`^${assignment}\\b`), `stale frontier assignment ${id}`);
}
const rendered = execFileSync(process.execPath, [fileURLToPath(new URL('./render-action33-frontier.mjs', import.meta.url))], {encoding: 'utf8'});
assert.equal(readFileSync(new URL('../reports/action33-frontier-30.md', import.meta.url), 'utf8').replace(/\r\n/g, '\n'), rendered, 'stale generated frontier report');
process.stdout.write(`Action33 frontier: ${map.functions.length} functions, ${map.ordered_constraints.length} ordered constraints, ${map.frontier.length} unresolved dependencies; synthetic prefix only.\n`);

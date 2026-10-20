# R41-B2: reusable headless cached-lookup comparison

The [headless runner](../scripts/check_engine_state_41b2.py) accepts a capture
path, admits its state, executes the identified original GDI instructions and
compares the result with the existing TypeScript cached-lookup model. It
emits one JSON object and an exit status. Capture hashes identify runs; they
are not an admission allow-list. There is no fixed instruction count, staff
index, row mapping or requirement that the result be null.

This unit starts from main `d9ba4ade59e800d51bf9305b150b7aa9da38e43d`. It reuses
R41's original replay, exact two-build instruction map and `lookupCached41`
model. It changes no simulation semantics. The earlier one-capture checker
and retained evidence stay available as historical regressions.

## Running a comparison

Requirements: Python 3 with Capstone 5.0.7 and Unicorn 2.1.4, Node 24, the
identified pinned/GDI executables and a local capture file. Invoke from the
repository root:

```text
python -B scripts/check_engine_state_41b2.py --input PRIVATE_CAPTURE.json --pinned PINNED_EXE --gdi GDI_EXE --node NODE24
```

Success exits zero and emits schema `reversal.engine-state-41b2.result.v1`
with `status: "matched"`, input/replay digests, evidence kind, per-case step,
memory-event and call-boundary counts, null/non-null result classification,
and altered-result rejection results. It emits no captured addresses,
register values, raw memory, names, paths or RNG values.

An unsupported input or comparison failure exits one and emits
`status: "rejected"`, `stage` and `code`. Useful domain codes include
`REFRESH_UPDATE_REQUIRED`, `REFRESH_INITIALIZATION_REQUIRED`,
`CACHE_REFERENT_MISSING`, `FS_STATE_MISSING`, `RNG_STATE_OUTSIDE_DOMAIN` and
`MEMORY_CLOSURE_INCOMPLETE`. A stale date therefore remains an explicit
refresh dependency; the runner does not repair it.

The original replay is passed to Node in an automatically removed temporary
file. To retain it privately, add:

```text
--private-replay results/my-lookup-replay.json
```

The destination must not already exist. Paths inside this checkout are
restricted to ignored `results/`; an explicitly supplied path outside the
checkout is also accepted. Retained replay contains private memory. Keep it
outside Git.

The [TypeScript comparison module](../reconstruction/compare-state-41b2.ts)
exports `compareReplay41b2` for headless callers. It can also inspect a replay
created by the runner:

```text
node reconstruction/compare-state-41b2.ts results/my-lookup-replay.json
```

That command trusts the supplied replay JSON as its original evidence; it
does not regenerate instructions or independently verify the supplied
specimen identity. The Python wrapper is the trust boundary for fresh
original execution: it validates both executable hashes and the instruction
map, admits the supplied closure, regenerates the replay, and passes those
new results to TypeScript.

## Accepted inputs and unchanged domain

The direct input is the accepted R41-A
`reversal.runtime-capture-41.v1` schema, including a completed GDI lookup
interception, restoration/detach metadata and complete labelled memory
closure. The exact executable hashes and entry/caller addresses remain
mandatory. A generic capture hash is recorded without restricting which
capture can run.

For a metadata-reduced capture or a synthetic sanitized fixture, use:

```json
{
  "schema": "reversal.engine-state-41b2.input.v1",
  "evidence_kind": "sanitized-capture",
  "capture": {
    "schema": "reversal.runtime-capture-41.v1",
    "private": true
  }
}
```

The abbreviated `capture` above must contain the complete accepted capture
fields in a real input. Use `evidence_kind: "synthetic"` for authored fixture
state. Synthetic inputs report `declared_live_entry: false`. Sanitizing
may remove irrelevant metadata; it cannot redact required bytes, invent
referents or erase the actual evidence kind. Both forms retain private
memory when originating from the game. Input metadata and hashes provide
consistency checks, not independent authentication of how a file was made.
In particular, wrapper `evidence_kind` is supplied metadata. The runner
reports `provenance_authenticated: false` for every input; it cannot detect
a fabricated capture whose complete contents imitate an admitted capture.
It rejects unsupported labels and additional wrapper fields, including
claims of authentication. A direct capture schema declares a runtime entry
but does not authenticate that declaration.

Admission retains the R41 boundary: GDI `0062e6e0` with return address
`006cf8f7`, loaded base `00400000`, initialized refresh flags, a valid
staff-base/index relationship, nonnull attribute pointer and a status row
whose date matches the current date. Mapping `-1` returns null; an admitted
nonnegative mapping needs the corresponding captured 48-byte cache record.
Missing FS/RNG state, conflicting captured aliases, overflow, data aliasing
the active stack, code-page overlays and stale refresh rows are rejected.
The runner bounds input size and regions before emulation.

Comparison covers returned pointer/mapping/row, ordered nonstack reads and
writes, the actual refresh call and return, stack cleanup, restored FS head,
row/RNG digests and the caller-owned shared RNG object. It preserves the
existing FS-address normalization and no-exception domain. The path executes
no RNG call; the captured RNG cells remain unchanged.

Each successful comparison also changes the recorded return, mapping, RNG
result, call argument, memory-effect sequence and FS coverage in separate
copies, and requires each altered result to fail. Expected output is comparison
evidence, never an input used by the simulation.

## Verification

The [verification script](../scripts/verify_engine_state_41b2.py) checks:

- Two genuine R41-A lookup captures, and the first captured state with
  unrelated metadata removed, under separate input digests.
- Independently authored synthetic null and nonnull cached-record inputs,
  labelled synthetic and kept in temporary private files.
- Byte-identical normal/optimized Python runner JSON for every positive and
  negative capture-domain case.
- Resealed stale rows and uninitialized flags, incorrect lookup/RNG aliases,
  a missing cache referent, missing FS state, invalid hex, malformed registers,
  unsupported evidence kinds, an added wrapper trust claim and a missed breakpoint.
- Private-output location/overwrite rejection and standalone JSON rejection
  of an altered original return value.

The [receipt](../evidence/engine-state-41b2-validation.json) records counts,
digests and source hashes. Original code and captured-memory excerpt scans
cover public files and CLI stdout. Raw captures, private replay, fixture
envelopes and full traces are absent from Git.

```text
python -B scripts/verify_engine_state_41b2.py --pinned PINNED_EXE --gdi GDI_EXE --capture PRIVATE_CAPTURE_A --additional-capture PRIVATE_CAPTURE_B2 --node NODE24 --output evidence/engine-state-41b2-validation.json
python -O -B scripts/verify_engine_state_41b2.py --pinned PINNED_EXE --gdi GDI_EXE --capture PRIVATE_CAPTURE_A --additional-capture PRIVATE_CAPTURE_B2 --node NODE24 --output results/engine-state-41b2-optimized.json
npm run check
```

Both genuine captures replay 85 original instructions and match 19 memory
events and two refresh boundaries with a null result. Their input digests
differ, and each comparison independently preserves its own captured RNG
state. This does not claim that the two initial RNG states match. The second
capture's additional slot bytes are admitted for consistency with overlapping
reads; this runner does not establish slot-field semantics or lifetime.

R41-A collected both live entries. This offline unit establishes no live
return, RNG draw, completed effect, goal/non-goal result or resolver-entry
join. The next missing execution boundary is a paired same-thread lookup
entry and actual return at `006cf8f7`, including `ESP = entry ESP + 8`,
returned `EAX`, preserved nonvolatile registers and before/after RNG and row
state. Same-process reload/replay divergence remains unresolved; the
observed Restart Game route exited the old process and created a new one.
Runtime operation and any Windows prompt remain with R41-A. Shared queue,
frontier, registries, runner registration, canonical native database and
checkpoints are unchanged.

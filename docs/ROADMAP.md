# Research roadmap

## Completed baseline

Investigations 01–04 established a pinned specimen, verified it against an archived updater, built the Ghidra project, traced match progression, recovered commentary layouts and connected event IDs to configuration labels. Investigation 05 adds an executable-wide code atlas, a penalty-preparation reconstruction and explicit TypeScript/React boundaries. Investigation 06 verifies independent goalkeeper base-draw, shot-category and scoring-gate slices. Investigation 07 connects the penalty keeper base branch to its common adjustment stage under explicit 53/64-bit precision. Investigation 08 checks the action33 path from original entry to return, including tactical lookup and grid selection.

The TypeScript modules now cover the small-bound random helper/CRT generator, event-minute conversion, event-priority lookup, the post-goal stop predicate, penalty preparation and three shot-resolution boundaries. Their supported scope and limits are recorded with the oracles and [validation coverage registry](../evidence/code-atlas/validation-coverage.json).

## Map the whole program while reconstructing useful behavior

The [code atlas](../evidence/code-atlas/README.md) inventories all 9,241 currently inferred internal functions. The [workstream index](../evidence/code-atlas/WORKSTREAMS.md) groups direct source-path anchors for match simulation, data/storage, tactics/training, transfers/contracts/scouting, competitions, managers/news/finance and UI screens. These are research navigation groups, not completed modules.

For each workstream, recover state ownership and a behavioral contract, record dependencies, identify a bounded path, and compare a TypeScript implementation with original-instruction fixtures. Continue mapping unanchored functions through callers, callees, data references and controlled observations. Do not wait for every original symbol to be named before validating useful subsystems.

## Next: trace runtime state producers and connect the shared shot caller

1. Trace the sources of keeper ratings at slot`+168/+16a`, float`+d1`, counter`+f`, fallback rating`+3b` and match state`+8eaa`. The action33 routine now runs from entry to return with supplied tactical/grid/state inputs; their real match-state producers remain open.
2. Follow keeper output and quality through `00702050`. Account for intervening changes and every RNG consumer before following scoring/non-scoring branches to score/state writes and commentary.
3. Establish the x87 control word at match entry. Static CRT code requests 53-bit precision; both 53/64-bit modes are checked, but actual entry state has not been runtime-observed.
4. Preserve the original rounded distance lookup as data. Exact hypot matches only 24/108 entries; do not silently replace it. Public fixtures use a labelled synthetic grid; an additional local original-grid comparison passes.
5. Build a connected shot/penalty attempt and shootout only after state producers, caller preconditions and side effects are established. Continue bounded PRs, self-review and CI-gated merges; preserve and restore-test each native checkpoint.

Investigation 08 adds 9,056 original-entry public cases and a separately retained 9,056-case original-grid check. These cover action33, not all actions, a complete shot outcome or a full match. Earlier scoped oracles remain retained.

Additional leads are the event token formatter, the weather logic that selects the pitch-abandonment threshold, the large-bound x87 RNG path and RNG save/load restoration.

## Later: browser simulation

Use a TypeScript simulation core and a React UI, following [ARCHITECTURE.md](ARCHITECTURE.md). First introduce a stable headless contract and replayable event/snapshot stream; then add a small match log or penalty experiment UI. Rendering must not advance RNG or simulation state. Canvas can later provide a Sensible Soccer-style match presentation. No complete React app or playable match exists yet.

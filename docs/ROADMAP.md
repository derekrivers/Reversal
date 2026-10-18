# Research roadmap

## Completed baseline

Investigations 01–04 established a pinned specimen, verified it against an archived updater, built the Ghidra project, traced match progression, recovered commentary layouts and connected event IDs to configuration labels. Investigation 05 adds an executable-wide code atlas, a penalty-preparation reconstruction and explicit TypeScript/React boundaries. Investigation 06 verifies independent goalkeeper base-draw, shot-category and scoring-gate slices. Investigation 07 connects the penalty keeper base branch to its common adjustment stage under explicit 53/64-bit precision.

The TypeScript modules now cover the small-bound random helper/CRT generator, event-minute conversion, event-priority lookup, the post-goal stop predicate, penalty preparation and three shot-resolution boundaries. Their supported scope and limits are recorded with the oracles and [validation coverage registry](../evidence/code-atlas/validation-coverage.json).

## Map the whole program while reconstructing useful behavior

The [code atlas](../evidence/code-atlas/README.md) inventories all 9,241 currently inferred internal functions. The [workstream index](../evidence/code-atlas/WORKSTREAMS.md) groups direct source-path anchors for match simulation, data/storage, tactics/training, transfers/contracts/scouting, competitions, managers/news/finance and UI screens. These are research navigation groups, not completed modules.

For each workstream, recover state ownership and a behavioral contract, record dependencies, identify a bounded path, and compare a TypeScript implementation with original-instruction fixtures. Continue mapping unanchored functions through callers, callees, data references and controlled observations. Do not wait for every original symbol to be named before validating useful subsystems.

## Next: establish keeper entry state and connect the shared shot caller

1. Recover `00700420`'s validity/position prelude and the grid-derived factor supplied to the now-verified postlude. Trace the sources of slot`+d1/+f/+3b` and match`+8eaa` without assigning unsupported attribute names.
2. Establish the x87 control word at match entry. Static CRT helper`0094a698` requests 53-bit precision; the keeper reconstruction requires an explicit 53/64-bit choice and matches original instructions under both. No runtime entry trace exists yet.
3. Trace keeper output and final quality through `00702050`, including intervening modifications and every RNG consumer. Follow scoring and non-scoring branches to score/state writes and commentary; a failed ratio gate alone does not classify a save.
4. Build a connected shot/penalty oracle before a complete attempt and shootout. Entry preconditions must be established, not silently assumed.
5. Preserve the existing database, restore-test the new checkpoint, and commit findings/code/evidence together. Open and self-review bounded PRs; merge after checks pass under standing authorization, respecting repository protection rules.

Investigation 07's 8,192 fixtures verify the postlude and connected penalty response body, each at 53/64-bit precision. They do not include the original validity/grid prelude, complete shot caller, score writes or commentary. Earlier independent category/gate and preparation checks remain retained at their original scope.

Additional leads are the event token formatter, the weather logic that selects the pitch-abandonment threshold, the large-bound x87 RNG path and RNG save/load restoration.

## Later: browser simulation

Use a TypeScript simulation core and a React UI, following [ARCHITECTURE.md](ARCHITECTURE.md). First introduce a stable headless contract and replayable event/snapshot stream; then add a small match log or penalty experiment UI. Rendering must not advance RNG or simulation state. Canvas can later provide a Sensible Soccer-style match presentation. No complete React app or playable match exists yet.

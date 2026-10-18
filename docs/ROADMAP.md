# Research roadmap

## Completed baseline

Investigations 01–04 established a pinned specimen, verified it against an archived updater, built the Ghidra project, traced match progression, recovered commentary layouts and connected event IDs to configuration labels. Investigation 05 adds an executable-wide code atlas, a penalty-preparation reconstruction and explicit TypeScript/React boundaries. Investigation 06 verifies independent goalkeeper base-draw, shot-category and scoring-gate slices.

The TypeScript modules now cover the small-bound random helper/CRT generator, event-minute conversion, event-priority lookup, the post-goal stop predicate, penalty preparation and three shot-resolution boundaries. Their supported scope and limits are recorded with the oracles and [validation coverage registry](../evidence/code-atlas/validation-coverage.json).

## Map the whole program while reconstructing useful behavior

The [code atlas](../evidence/code-atlas/README.md) inventories all 9,241 currently inferred internal functions. The [workstream index](../evidence/code-atlas/WORKSTREAMS.md) groups direct source-path anchors for match simulation, data/storage, tactics/training, transfers/contracts/scouting, competitions, managers/news/finance and UI screens. These are research navigation groups, not completed modules.

For each workstream, recover state ownership and a behavioral contract, record dependencies, identify a bounded path, and compare a TypeScript implementation with original-instruction fixtures. Continue mapping unanchored functions through callers, callees, data references and controlled observations. Do not wait for every original symbol to be named before validating useful subsystems.

## Next: complete the goalkeeper response before joining penalty outcomes

1. Reconstruct `00700420`'s common postlude at `00700a4f..00700b87`. It adds further RNG draws and x87 floating-point scaling to the verified base draws. Preserve signed casts and original rounding; JavaScript double arithmetic must be checked against x87, especially constants 0.7, 0.3 and 4/7 represented as doubles.
2. Trace final quality and keeper terms into the eligible-category gate in `00702050`, including modifications between the verified boundaries. Record every RNG consumer in order.
3. Follow the scoring and non-scoring branches to score/state writes and presentation events. A failed gate is not a complete save classification.
4. Build an original-instruction oracle for a connected penalty path, then a complete attempt and shootout. Only join slices when their entry states and intervening effects are established.
5. Preserve the existing database, restore-test a fresh checkpoint, and commit matching findings, code and evidence. Open and self-review bounded PRs; merge after checks pass under the user's standing authorization. Respect repository protection rules.

Investigation 06 checks all 65,536 raw quality words with both variant bytes (131,072 classification cases), 4,096 keeper base cases and 4,056 ratio-gate cases independently. These do not establish a full outcome or scoring probability.

Additional leads are the event token formatter, the weather logic that selects the pitch-abandonment threshold, the large-bound x87 RNG path and RNG save/load restoration.

## Later: browser simulation

Use a TypeScript simulation core and a React UI, following [ARCHITECTURE.md](ARCHITECTURE.md). First introduce a stable headless contract and replayable event/snapshot stream; then add a small match log or penalty experiment UI. Rendering must not advance RNG or simulation state. Canvas can later provide a Sensible Soccer-style match presentation. No complete React app or playable match exists yet.

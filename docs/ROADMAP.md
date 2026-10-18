# Research roadmap

## Completed baseline

Investigations 01–04 established a pinned specimen, verified it against an archived updater, built the Ghidra project, traced match progression, recovered commentary layouts and connected event IDs to configuration labels. Investigation 05 adds an executable-wide code atlas, a penalty-preparation reconstruction and explicit TypeScript/React boundaries.

Four TypeScript modules now cover the small-bound random helper/CRT generator, event-minute conversion, event-priority lookup, the post-goal stop predicate and penalty preparation. Their supported scope and limits are recorded with the oracles and [validation coverage registry](../evidence/code-atlas/validation-coverage.json).

## Map the whole program while reconstructing useful behavior

The [code atlas](../evidence/code-atlas/README.md) inventories all 9,241 currently inferred internal functions. The [workstream index](../evidence/code-atlas/WORKSTREAMS.md) groups direct source-path anchors for match simulation, data/storage, tactics/training, transfers/contracts/scouting, competitions, managers/news/finance and UI screens. These are research navigation groups, not completed modules.

For each workstream, recover state ownership and a behavioral contract, record dependencies, identify a bounded path, and compare a TypeScript implementation with original-instruction fixtures. Continue mapping unanchored functions through callers, callees, data references and controlled observations. Do not wait for every original symbol to be named before validating useful subsystems.

## Next: penalty goal/save resolution

1. Start at `006be710`, phases 4/5/6, and trace the attempt path into the shared action routine.
2. Preparation is now checked in 3,584 controlled cases. Trace the quality argument into `00702050`, action kind `0x33`, to reach the keeper/goal decision.
3. Separate keeper inputs, random draws, score/state changes and presentation events. Record commentary's shared-RNG consumption explicitly.
4. Create controlled original-state fixtures and compare a narrow reconstruction with the original instructions.
5. Save new names/layouts into the existing database, restore-test a fresh checkpoint and update this repository's evidence and checkpoint metadata.

Additional leads are the event token formatter, the weather logic that selects the pitch-abandonment threshold, the large-bound x87 RNG path and RNG save/load restoration.

## Later: browser simulation

Use a TypeScript simulation core and a React UI, following [ARCHITECTURE.md](ARCHITECTURE.md). First introduce a stable headless contract and replayable event/snapshot stream; then add a small match log or penalty experiment UI. Rendering must not advance RNG or simulation state. Canvas can later provide a Sensible Soccer-style match presentation. No complete React app or playable match exists yet.

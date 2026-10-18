# Research roadmap

## Completed baseline

Investigations 01–04 established a pinned specimen, verified it against an archived updater, built the Ghidra project, traced match progression, recovered commentary layouts and connected event IDs to configuration labels.

Three TypeScript modules now cover the small-bound random helper/CRT generator, event-minute conversion, event-priority lookup and the post-goal stop predicate. Their supported scope and limits are recorded with the oracles.

## Next: one complete penalty attempt

1. Start at `006be710`, phases 4/5/6, and trace the attempt path into the shared action routine.
2. Separate attempt selection, player/keeper inputs, random draws, state changes and presentation events.
3. Recover a bounded decision path with all input widths and branches documented.
4. Create controlled original-state fixtures and compare a narrow reconstruction with the original instructions.
5. Save new names/layouts into the existing database, restore-test a fresh checkpoint and update this repository's evidence and checkpoint metadata.

Additional leads are the event token formatter, the weather logic that selects the pitch-abandonment threshold, the large-bound x87 RNG path and RNG save/load restoration.

## Later: browser simulation

Build a small browser-facing match log around verified event data, then widen the simulation one tested subsystem at a time. Rendering, text formatting and match simulation should have separate interfaces. A Sensible Soccer-style presentation remains a possible later direction; it is not evidence that the underlying simulation has been reconstructed.

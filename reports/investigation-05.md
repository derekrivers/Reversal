# Investigation 05 — whole-program map and penalty preparation

Input: CM 01/02 3.9.68, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`.

## What changed

The executable now has a [queryable code atlas](../evidence/code-atlas/README.md): 9,241 inferred internal functions, 143 external symbols, 396 source-path strings and 93,349 call instructions. Direct references connect 1,892 functions with original source-path anchors. There are 851 call instructions without a decoded static flow destination. This is a structural map, not complete original source recovery or proof that every behavior has been understood.

[Filename-based workstreams](../evidence/code-atlas/WORKSTREAMS.md) cover the wider application, including competitions, transfers, tactics, database code and UI screens. Most functions still need a behavioral contract. The scope registry distinguishes three checked whole functions from checked branches/calculation slices; it does not assign a misleading overall reconstruction percentage.

The new [penalty preparation module](../reconstruction/penalty-preparation.ts) agrees with original calculation slices across **3,584 controlled cases**, including final RNG state. It prepares the quality argument passed to the shared shot routine. The keeper/goal/save result is not yet reconstructed.

## Penalty preparation calculation

The checked slices are `006be9d7..006beacc`, `00700d19..00700d3c` and `006beaf0..006beb05`. They execute with the original small-bound RNG and x87-to-integer helper in Unicorn, using a synthetic table and context.

1. Draw using the signed byte at `player+0x35`.
2. Compute `baseErrorBudget = 2 * (200 - draw * (remaining+4))`.
3. If `remaining-1+ownScore < opponentScore`, add `random(trunc(baseErrorBudget*2.25))`.
4. Otherwise, if `opponentRemaining+opponentScore < ownScore+1`, add `random(trunc(baseErrorBudget*0.75))`.
5. The action-kind `0x33` branch selects event ID `0x1f7f` (config 63, `EVENT_TAKE_PENALTY`) and computes `signed16(150 + random(signed16(slot+0x180)*5))`.
6. Subtract a random draw bounded by the error budget to obtain the quality argument.

The multipliers change a random bound; they are not goal probabilities. `player+0x35` is community-corroborated as **One-on-Ones**. The community Penalties field is at `+0x38`; the checked budget slice does not read that offset. The meaning of the intermediate signed rating at roster `+0x180` remains unresolved.

## Validation scope

The fixture set covers all 256 raw attribute-byte patterns, both sides, zero/negative/positive inputs within the supported small-RNG domain, signed-16 quality conversion, pressure predicates, sequential random-state effects and table wrap. It includes 1,233 no-pressure cases, 1,180 must-score cases and 1,171 score-to-win cases. Some synthetic states are width/boundary tests rather than representative live-game states.

The harness sets the original sudden-death flag to 1 to suppress commentary calls. It joins three calculation slices with synthetic frames; it skips the original helper prelude and does not execute `00702050`'s complete shot resolution. Commentary can consume shared RNG when enabled, so this oracle does not reproduce the full live-game call stream.

The public implementation explicitly restricts remaining attempts to 0..5 and signed rating×5 to the previously recovered small-bound RNG domain. It rejects ratings that need the unrecovered large-bound branch.

## Native database checkpoint

The [new checkpoint](../checkpoints/2026-10-18-investigation-05/) preserves 22 working function names, 10 globals and 8 partial structures with 82 fields. A fresh extraction reopened read-only in Ghidra 12.1.4/JDK 21. All 32 code samples, 9 code comments and 10 canonical project-file hashes matched.

One important layout correction is roster-slot `+0x19e`: previously an unidentified activity word, it is dereferenced as the owning match-context pointer by possession/action routines. The new player-attribute type is a minimum observed/corroborated prefix; its 0x39-byte extent is not a recovered full allocation size.

The native archive stays outside the public repository and is identified by its checksum. Investigation 04 metadata and the earlier full private research archive remain historical checkpoints.

## Browser rebuild direction

[The port architecture](../docs/ARCHITECTURE.md) assigns simulation/RNG/event ordering to TypeScript and views/commands to React, with a worker boundary when a host is introduced. Preserve commentary variant draws inside the core event pipeline even when the UI hides events. React rendering must not alter the random stream.

The next behavioral target is the shared shot resolver's action-0x33 keeper/goal decision. The code atlas supports wider parallel workstreams later, but no complete match, React app or original-source recreation is claimed here.

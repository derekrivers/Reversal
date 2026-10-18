# Investigation 08 — penalty keeper response from function entry

Pinned specimen SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses below are virtual addresses. Names and layouts remain working research annotations.

The action `0x33` path of `00700420` is now checked from its original function entry through its return, including the tactical-position helper, base draws and common adjustment stage. **Other actions, actual match-state producers, the shared shot caller and complete penalty outcomes remain open.**

## Entry contract

Both output bytes are initialized to zero before checking eligibility. Variant byte 0 selects the signed16 rating at slot`+168`; every nonzero byte selects slot`+16a`.

The routine reads its grid factor using:

```text
index = abs(signed8(keeperY) - signed8(matchY)) * 9
      + abs(signed8(keeperX) - signed8(matchX))
factor = grid[index]
```

Keeper coordinates come from slot`+102/+103`; match coordinates come from match`+8ea7/+8ea8`. The checked reconstruction restricts x to 0..8 and y to 0..11, giving a 108-entry lookup window. This does not claim safe behavior for arbitrary raw coordinate bytes or invalid pointers. In particular, the native grid read occurs before the validity guards; a null context is not a supported input despite a later null test.

Eligibility requires signed8(slot`+2b`)<=1 and tactical position word 1. Raw activity bytes 128..255 are negative, so they pass the activity comparison; this is machine behavior, not a claim that every such state occurs in play.

`006c38c0` reads slot`+19` as a signed tactical-slot index. Indices 0..10 select a 16-bit word from the side table; all other bytes return AX 0. Match`+8ebc/+8ec0` hold the side 0/1 table pointers. The helper's upper EAX bits are not part of the contract. Its measured unsigned16 return width is now recorded in the native database.

Eligible action33 entries continue into the previously verified base+postlude calculation. The first output flag remains 0; the second reports the common postlude's fallback selection. Rejected entries return low-word 0, zero both flags and consume no RNG.

## Lookup provenance matters

The original 108-entry window at `00a15e44` is not identical to a freshly calculated Euclidean lookup: only 24 entries exactly match float32 hypot(dx,dy). The original window ranges from 0 to approximately 13.6. Its SHA-256 is retained in the oracle metadata.

The public oracle supplies an explicitly synthetic float32 hypot lookup and synthetic tactical tables. The TypeScript API accepts the lookup rather than silently substituting a formula for the original rounded values. An additional local run retains the original lookup window unchanged, using the same 9,056 cases, and also passes. That input/output oracle remains under ignored `results/`; only its validation receipt and digest are public. Both runs use the retained public synthetic RNG table and supplied runtime fields. Neither establishes actual full-match state or RNG seeding.

## Original-entry verification

| Observation | Coverage |
| --- | ---: |
| Public original-entry cases | 9,056 |
| Eligible / rejected | 2,787 / 6,269 |
| Activity bytes / tactical-slot bytes | All 256 of each, with independent sweeps |
| Sides / explicit variants | Both sides; variant 0,1,255 plus mixed samples |
| Grid indices | All 108 |
| Arithmetic precision | Explicit 53/64-bit x87 modes |
| Additional local original-grid cases | 9,056 |

The harness executes the original entry, original tactical lookup, original RNG and original `__ftol`; it does not patch instructions or join synthetic internal frames. It checks ret24 stack cleanup, preservation of EBX/EBP/ESI/EDI, restored control word, and unchanged 446-byte slot and 63,035-byte match context. The TypeScript check compares the signed16 response, both output flags, eligibility and final RNG state. Rejected entries are checked for unchanged RNG.

Public guards reject unsupported coordinates, raw values, tactical/grid shapes and bounded float inputs before consuming RNG. The public evidence check also prevents an original-grid oracle from being accidentally admitted as the public fixture.

## Database and continuation

The native project now records the tactical lookup, refines slot`+19` from a generic status label to its measured tactical-index role, adds coordinate/activity/table fields and saves a partial eleven-word tactical table type. It retains earlier names, annotations and checkpoint history. Fresh extraction and native read-only reopening verify the next checkpoint.

Next, trace where the ratings, counter, float adjustment and match state are produced, then follow the keeper response into `00702050`. Connect the actual quality modifications, category/gate decisions, score/state writes and presentation draws before claiming a complete penalty attempt. The static CRT precision request remains evidence for 53-bit mode; match-entry control state is still not runtime-confirmed.

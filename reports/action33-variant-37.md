# R37-B: connected variant draw and keeper-call preparation

The [TypeScript continuation](../reconstruction/action33-variant-37.ts) executes the actual `007023e3 -> 0090cfc0` call with bound 2 on R36-A's original-produced state, including the CRT wrap when reached, and continues to **before `00702416 -> 00700420`**. All 224 nonnull-keeper cases reach that boundary; the eight null-keeper cases retain their earlier stop before `00702332 -> 00944cff`. Neither pending call executes. No variant value, RNG state, keeper result or intermediate stack is supplied to cross the new continuation.

This is original-instruction execution on the existing synthetic entry schedule. It is not a live-game observation, complete keeper invocation, resolver return, penalty outcome or full machine-state join to R30-C.

## Provenance and scope

The pinned 7,192,576-byte PE32 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All instruction addresses are virtual addresses; range records separately retain file offsets. This unit starts from main `404185fb760788002d885eb3209c059bd9e6d87b`, containing the reviewed R36-A work. The R37-B assignment is recorded in the coordinator's R37 queue. The generator pins the R36-A generator, TypeScript module and oracle and the R30-C oracle; R36-A rechecks its own predecessor dependencies and private native manifests.

The [generator](../scripts/emulate_action33_variant_37.py) compares all operands in the added caller range `007023e3..00702416`, nonzero small-bound RNG range `0090cfcf..0090d02d` and CRT range `00946a04..00946a22` against the pinned PE and verified private native exports. The pre-keeper call and excluded large-bound branch are decoded and checked but not executed. The inherited zero-bound RNG entry and all earlier instructions remain admitted by the existing units. Coordinator task R37-B-INT registers this checker in the shared research runner. No native annotations, canonical database, frontier or registry are changed here.

The unchanged 232 cases run from resolver entry `00702050`. Before the new call, or at the null diagnostic boundary, the original complete represented state, prior instruction sequence, ordered memory events, completed calls and all 11 prior memory-region digests must equal the R36-A oracle. TypeScript independently executes that complete prefix and checks the same checkpoint. The public random table, float32 grid and match/lookup/stack regions remain synthetic.

## RNG ABI, ordering and caller effects

The actual RNG helper saves ECX and ESI, reads bound 2 from `[ESP+0c]`, and advances the shared cursor by four bytes. It stores the advanced cursor before testing the wrap path. The comparison uses the inclusive final table address: a cursor equal to the limit remains valid; a cursor above it wraps. **70 of the 224 variant draws wrap**, write the table start to the cursor, call `00946a04`, reload the cursor and write the new offset. The CRT call updates the seed with `seed * 214013 + 2531011 mod 2^32`, then returns the masked upper word. Both the transient past-end cursor and the subsequent reset are present in ordered writes and instruction-state comparisons.

After adding the table word to the offset with 32-bit wrapping, the original uses signed `IDIV` and returns the remainder in EAX and EDX for this positive bound. The retained schedule returns zero 143 times and one 81 times. ECX, EBX, EBP, ESI and EDI are preserved across the call. Its plain `RET` leaves ESP equal to the caller's pre-call value; the bound remains on the stack until the caller's `ADD ESP,4`. All CALL, PUSH, POP and RET stack effects are compared. The function does not touch x87 state. Arbitrary bounds and unsupported state are excluded by the TypeScript admission guards.

At `007023eb`, the caller writes AL as a byte at frame `+1c`. It then constructs the six outgoing dwords for the keeper helper, preserving high bytes and output-pointer aliasing. With `F` denoting ESP after the caller removes the RNG argument, the outgoing values are:

| Position | Original-produced dword |
| --- | --- |
| 1 | Action dword with its low byte replaced by shooter `+102` |
| 2 | `(F+20)` with its low byte replaced by shooter `+103` |
| 3 | Full dword read at `F+1c`, after only its low byte was overwritten with the variant |
| 4 | Original action dword from `F+698` |
| 5 | Pointer `F+20` |
| 6 | Pointer `F+14` |

ECX is set to the selector-produced keeper pointer at `00702414`. In the current synthetic schedule, the action is `33` and the high bytes surrounding the variant are zero. The reconstruction performs the original byte replacements and dword reads; it does not normalize raw arguments to those observed scalar values. The output pointers are addresses in the existing caller frame. They have not been written by the unexecuted keeper helper.

## Compared evidence and precise remaining gap

The [704,907-byte oracle](../evidence/action33-variant-37-oracle.bin), SHA-256 `e78aa4f325e9737245ea35b6078c113b9b60a599b2e0eace2c1738bd6160bf59`, contains **169,795 original instruction steps and 67,743 ordered memory events**. The new continuation contributes **10,024 instruction-state snapshots and 5,572 memory events**. There are 456 complete RNG calls across the prefixes: 232 earlier zero-bound calls and 224 variant draws, plus 70 nested CRT calls. Snapshots are hashed as canonical newline-delimited JSON in exact execution order; final states and call-boundary states are retained directly.

The [checker](../reconstruction/check-action33-variant-37.ts) compares every represented register, EFLAGS, x87 control/status/tag and active payload, shared RNG cells, complete instruction sequence, call/return state, ordered memory operand and all **15 final region digests**. Four new four-byte RNG-cell regions supplement the 11 existing regions, so RNG writes are now also represented as actual ordered memory events. The existing scalar `nextBounded` is independently compared with each derived variant result and final RNG state. As before, empty physical x87 payloads, x87 instruction/data pointers and hardware exceptions are outside the representation. Architecturally undefined integer flags follow the pinned Unicorn 2.1.4 observations, rather than a claim about every physical processor.

The 160 baseline variant projections match R30-C exactly in call site, bound, result and full before/after semantic RNG state. The complete current original/TypeScript state also matches at the pre-keeper boundary. **A full join to the R30-C TypeScript segment remains unavailable**: that segment does not represent the original keeper stack and operand-read order, scratch registers, full EAX return bits or x87 status/tag evolution. The first exact connected machine-state gap is now **`00702416 -> 00700420`**, with the selected receiver, six raw dwords, original-produced memory, RNG and x87 state retained. R30-C's independently validated semantic keeper behavior is a dependency for the next unit, not a returned value injected here.

The existing bit-04 lookup, contact branch, selector reserve routes and null diagnostic remain excluded as documented by their source units. A coherent synthetic state through this longer prefix does not establish original-game state initialization or live lifecycle reachability.

## Integrity, privacy and reproduction

The [verifier](../scripts/verify_action33_variant_37.py) regenerates byte-identical oracles in separate normal and optimized Python processes. Twenty-three negative checks reject a changed PE, independent native RNG argument-offset mutation, changed CRT export, changed synthetic table, corrupted preserved ESI, incorrect RET cleanup, altered RNG offset or CRT seed, altered actual return value or caller variant byte, unsupported bound, noncanonical/oversized public payloads, changed state digest and raw/hex/compressed private code fragments, including a byte-one offset and all three base64 alignments. The privacy gate scans every admitted 32-byte PE window in raw and hex form plus overlapping padding-free 30-byte base64 windows. Integrity gates use explicit exceptions under `python -O`. The Node checker additionally rejects inconsistent RNG memory/state cells and altered limits, and executes meaningful draw and outgoing-stack mutations which fail the same complete comparison.

```text
python scripts/verify_action33_variant_37.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --output results/variant37-normal.json
python -O scripts/verify_action33_variant_37.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --output results/variant37-optimized.json
node reconstruction/check-action33-variant-37.ts
npm run check
```

Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.19.0 were used. Normal and optimized receipts are byte-identical; the task checker and full repository check pass with the checker registered. Private PE bytes, native export bodies, original game data and raw runtime captures are absent from this unit. No installed game or save was launched, changed or captured by this work.

# R30-C: bounded TypeScript selector, variant and keeper composition

The [TypeScript composition](../reconstruction/action33-composition-30.ts) connects `007022fd..007024b4` for the 160 R30-A synthetic cases. It executes the accepted selector, variant RNG, keeper base and response helpers on one shared RNG state. It then derives the caller's marker bytes and the five outgoing argument dwords before the unexecuted `006cfe10` call.

This is a **semantic segment comparison from a supplied, original-produced checkpoint**. It is not a TypeScript implementation from resolver entry, a machine-state or stack emulator, a completed penalty attempt, or evidence of live-match reachability.

The pinned PE32 SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; addresses are virtual. The original comparison uses the R30-A evidence adopted in merged main `395823faae3c3e50427b2043749c3617bb93699f`. No native annotation or shared registry changes are proposed.

## Original producer and precise boundaries

The [oracle generator](../scripts/emulate_action33_composition_30.py) reruns the original instructions from `00702050`, using the unmodified R30-A schedule, code and synthetic memory. A read-only observer captures the checkpoint immediately before `007022fd`. Execution continues on that same machine to `007024b4`, and the complete R30-A record must equal its retained original-entry record. No instruction, register, memory value or return is changed between the checkpoint and the endpoint.

The checkpoint contains the original RNG state, semantic caller inputs, full match/tactical digests, and differences from the initial synthetic match. The only admitted earlier changes are bytes at match `+8d4c/+8d4d/+8d4e`, produced at `0070213d/0070215b`. The checker reconstructs the initial synthetic memory and applies these **supplied prior-producer bytes** before invoking the segment. They are not outputs calculated by the TypeScript segment.

The first missing TypeScript callee when starting from resolver entry is **`00702088 -> 006f09b0`**, the float32 grid helper. The later `0070210b -> 006d59b0` opponent scan and caller distance/conversion calculations also lack a composed TypeScript model here. R30-A executes those helpers under its guarded synthetic domain; this work does not substitute constants for them or claim their TypeScript recovery. `007022fd` is an interior boundary, not a callable original function.

The outgoing frontier remains **before `007024b4 -> 006cfe10`**. The model preserves `[shooter, 6d, 0, match & ffff0000, 0]`: the fourth dword retains the high word of ECX after `MOVSX CX,byte[frame+30]`. It is `04100000` in this schedule. No effect-helper return or shot result is supplied. A null keeper is rejected at the first diagnostic call site `00702332`, before variant RNG.

## Reused implementations and assumptions

The composition directly uses:

- `selectKeeperSlot29` from `keeper-selector-29.ts`, with the original mutable match memory.
- `nextBounded` and its CRT wrap from `bounded-random.ts` for the variant draw.
- `tacticalPositionWord` from `penalty-keeper-entry.ts` for the bounded two-side lookup.
- `penaltyKeeperBase` from `penalty-resolution.ts` and `adjustKeeperResponse` from `keeper-response.ts`, sharing the same state and synthetic random table. The postlude uses the existing finite x87 arithmetic at explicit precision 53 or 64.

Admission requires action `33`, mode 3, zero initial marker bytes and zero local byte `frame+30`; stable, nonwrapping mapped records; shooter and keeper context pointers equal to the supplied match; nominal keeper side 0 or 1; coordinates within x=0..8/y=0..11; finite bounded float32 grid and adjustment values; and the recovered small-bound RNG domain. The synthetic table has 51,000 words, with its original fixed limit represented by that length. Precision is round-to-nearest/even at 53 or 64 bits; exception, special-value and general x87 behavior are excluded. Unsupported-input rejection after selection is not transactional.

The tests use the same 80 cases per precision as R30-A. They cover cached/direct/invalidated/fallback selection, tactical and activity rejection, retained responses, weighted fallback and redraw. Reserve reassignment and a real roster/lookup lifecycle are not exercised by this composition corpus.

The scalar keeper modules validate and consume supplied fields rather than executing x86 loads. Consequently, **keeper operand-read order, original stack writes, scratch-register effects, full EAX return bits and x87 status/tag evolution are not model outputs or equivalence claims**. The caller uses the keeper's signed AX result, which is compared at that width. The model's call records retain semantic receiver and argument widths; incidental high bytes of byte arguments and stack output pointers are excluded.

## Compared observations

The [checker](../reconstruction/check-action33-composition-30.ts) compares against the [original-instruction projection](../evidence/action33-composition-30-oracle.bin):

| Comparison | Result |
| --- | --- |
| Same original-entry-produced checkpoint schedule | 160 cases |
| Exact ordered selector match/table reads and writes, including values | 11,456 events |
| All ordered match/tactical stores in this segment | 256 stores |
| Every variant and keeper RNG call: site, bound, value, full before/after state | 637 draws |
| RNG edge cases in the composition | 37 zero bounds, 50 negative bounds, 54 wraps |
| Projected selector, variant, keeper, tactical and RNG call order | All cases match |
| Keeper word, flags, caller markers and raw outgoing effect arguments | All cases match |
| Entire final 64 KiB match, 4 KiB tactical, random-table and synthetic-grid regions | All digests match |
| Final cursor, offset and CRT state | All cases match |

There are 64 rejected keeper cases, 65 retained responses, ten weighted fallbacks and 21 redraw fallbacks. Comparisons exclude the unimplemented earlier prefix and CPU stack. The RNG observations come from actual calls made by the imported helpers, not from recorded expected draws. A read-only table proxy observes each helper invocation (including zero bounds) and its state transitions. Unexposed base-call bounds are derived from the validated base expression; postlude bounds come from that helper's returned `drawBounds`. Values are derived from the observed table word and state using the validated remainder rule, and checked against exposed variant/base returns and branch decisions. These observations never choose the composition's response or mutate a second gameplay RNG state.

## Integrity, privacy and reproduction

The generator pins the R30-A oracle, emulator source and native site-evidence hashes. It revalidates all R30-A original/native operands using the existing pinned manifest, preflight and caller/runtime exports. The complete original-entry record comparison ties this projection to the same actual execution, including the original precision mode and shared RNG. No new PE instruction ranges are admitted.

The [verification script](../scripts/verify_action33_composition_30.py) regenerates byte-identical oracles in separate normal and optimized Python subprocesses. Explicit exception gates reject a changed PE, independent selector operand mutation, changed native export, JSON whitespace and an alternative gzip envelope. The fixed synthetic schedule, allowed producer-byte locations, operand regions and public schemas are checked. The script creates ignored `results/` before using temporary files. The Node checker pins and cross-checks the integrity receipt as well as the oracle and provenance inputs. Original executable/table/string bytes and private exports are not retained; full game regions are represented by digests, while recorded memory operands contain synthetic values only.

```text
python scripts/verify_action33_composition_30.py PRIVATE_EXE --fresh FRESH --r29 R29 --preflight PREFLIGHT --caller CALLER --runtime RUNTIME --output results/composition-normal.json
python -O scripts/verify_action33_composition_30.py PRIVATE_EXE --fresh FRESH --r29 R29 --preflight PREFLIGHT --caller CALLER --runtime RUNTIME --output results/composition-optimized.json
node reconstruction/check-action33-composition-30.ts
npm run check
```

`FRESH`, `R29`, `PREFLIGHT`, `CALLER` and `RUNTIME` are the same read-only private inputs documented by R30-A. Python 3.13, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.19.0 were used. Normal and optimized integrity receipts match. The shared research runner registers the bounded composition checker and passes under Node 24.

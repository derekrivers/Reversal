# R30-B: actual effect continuation reaches the null-player diagnostic boundary

All 160 R30-A cases execute the original call at `007024b4`, continue through both initial RNG groups in `006cfe10`, enter `0062ed70` with a null participant record pointer, and stop **before `0062ed99 -> 00944cff`**. Neither `0062ed70` nor `006cfe10` returns. `006d0980` is not reached.

This is useful original-execution evidence of the first unsupported dependency, not a successful participant-effect implementation. The retained R30-A state is insufficient for a normal effect path: shooter dword `+69` is zero, and the lookup-object global `00b63d28` remains zero in the mapped image. No player pointer, lookup object, return value, instruction or argument is repaired to force continuation. There is no new TypeScript model, effect-return equivalence or shot outcome claim.

The specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The branch starts at R30-A adoption commit `ee9420aa2e6fd50ff59a8b9b7de0fafca2ea7fbb`. Addresses are virtual; [site evidence](../evidence/action33-effect-30-sites.json) labels file offsets separately.

## Connection to the actual R30-A frame

The [continuation harness](../scripts/emulate_action33_effect_30.py) reruns the original prefix from `00702050` for every input in the retained R30-A schedule. Its complete per-case result must equal the retained R30-A record before continuing. The same Unicorn instance then executes `007024b4`; there is **no intervening memory, register, RNG, stack or x87 reset**. The initial synthetic setup is performed before original resolver entry, exactly as in R30-A.

The five outgoing dwords remain `[shooter, 0000006d, 00000000, 04100000, 00000000]`. The raw fourth dword is preserved. It is not read by the effect instructions reached before this diagnostic boundary and still has the same bits at the stop. The original CALL instruction pushes return address `007024b9`; the harness never injects it.

Before continuation, all eight integer registers, x87 control/status/tag, EFLAGS, RNG state, five RNG/lookup global cells, and full match/positions/stack/random-table/grid digests are recorded. The corresponding terminal snapshot is also retained. The R30-A prefix oracle SHA-256 is `08cd8c3725f98499b3fdaef8e42788c1f8ce80308616f881589042cc4d21ff4f`; its emulator source is separately pinned at `9486fdba017157b918081023641a2360a392839c2339c287e2a8fa97d28cee32`.

## Executed order and first unsupported call

| Site | Executed original behavior |
| --- | --- |
| `007024b4` | Call `006cfe10` with the preserved R30-A frame and ECX=match. |
| `006cfe10..006cfe2d` | Allocate 24 bytes, save EBX/EBP/ESI/EDI, save ECX in EDI, and initialize local selector bytes and float32 factors. These are stack writes. |
| `006cfe35`, `006cfe3b` | First group: `a=R(102)`, then `b=R(a)`. Store the result byte in the effect frame. |
| `006cfe50`, `006cfe5e`, `006cfe64` | If signed low byte of b is >50, draw `R(3)`; if nonzero, replace b with `R(R(76))`. The bounds/results are consumed in original call order. |
| `006cfe74`, `006cfe7a` | Second group: `a=R(102)`, then `b=R(a)`, even though participant2 is null. |
| `006cfe8c`, `006cfe9a`, `006cfea0` | The same optional three-call pattern for the second group. |
| `006cfeac..006cfec1` | Load nonnull participant1=shooter; load dword `[shooter+69]` into EAX, load global `[00b63d28]` into ECX, then push EAX. Both loaded values are zero in the retained state. |
| `006cfec2` | Enter original `0062ed70`, ECX=0 and one stack argument=0. |
| `0062ed70..0062ed83` | Allocate a 512-byte frame and save ESI/EDI. The argument is tested in EDI. `JNZ 0062edee` is **not taken**, selecting the null-input diagnostic path. |
| `0062ed85..0062ed94` | Prepare two stack buffers, two null arguments and literal source-pointer address `009e7f28`. The string contents are not read in the admitted segment. |
| `0062ed99` | Stop before the original call to `00944cff`. This is the first unsupported transitive call reached by every retained case. |

At the stop, ESP=`02007708`. The five diagnostic argument dwords, from top of stack, are `[009e7f28, 00000000, 00000000, 02007824, 02007724]`. ECX is now the second stack-buffer address; it is no longer the lookup receiver. ESI and EDI are zero within the suspended lookup helper. The two unreturned calls are explicitly retained as `007024b4 -> 006cfe10` and `006cfec2 -> 0062ed70`; terminal registers are not misreported as completed-callee ABI outputs.

The instruction at the stop and its target are independently matched against the PE/native listing. `00944cff` itself is not executed or modeled. The existing atlas inventories it as a 327-byte body with callees `00948851` and `009488e0`; that inventory does not admit its diagnostic buffer/string effects. The later diagnostic calls at `0062edb3`, `0062edc3` and `0062edd3`, global write at `0062eddb`, and null-path return are likewise unexecuted.

## RNG and memory evidence

The continuation adds **764 RNG calls** across the 160 cases. Exactly three have bound zero and leave RNG state unchanged; 761 advance it. Every case executes both mandatory two-call groups. The first optional `R(3)` is reached 28 times, with its two replacement draws reached 22 times each. The second optional `R(3)` is reached 24 times, with its replacement draws reached 14 times each. Per-case call counts are 4, 5, 7, 8 or 10. No CRT wrap occurs in this continuation, although the original CRT body remains admitted for the supported RNG boundary.

Every RNG call records site, bound, result and full initial/final cursor, offset and CRT state. The initial state equals the actual prefix's final state. The calls are not replayed from the independent R09/R10 ledger. The 764 calls are additional to R30-A's 797 calls; the connected two-stage corpus therefore contains 1,561 calls.

Only stack and RNG-state writes occur after `007024b4` and before the diagnostic call. The entire match, tactical tables, synthetic random table and synthetic grid are byte-identical before and after this segment. The lookup global and RNG limit remain unchanged. All original outgoing argument dwords remain intact. FPCW and the empty x87 tag word are preserved; no floating-point calculation in the effect body has yet been reached.

The [91,612-byte oracle](../evidence/action33-effect-30-oracle.bin) is gzip-encoded JSON stored with the repository's existing binary Git attributes. It retains full call-register/argument records, RNG records, all ordered nonstack memory events, full-region digests, and digests of the complete ordered memory/instruction traces. Its only retained memory values come from the existing synthetic match/table/RNG setup or the zero-mapped lookup cell. Source string bytes, original grid bytes, executable instructions and private exports are absent. Full traces can be regenerated with `--private-trace` only into ignored `results/`.

The continuation executes 27,390 instructions and 13,793 ordered memory events, reaching 101 distinct instruction starts and 115 consecutive instruction edges. These figures exclude the independently repeated prefix. All 160 records are explicitly marked `stopped_before_unsupported_diagnostic_call` and `effect_returned: false`.

## Initialization gap and the next dependency

The first missing participant input is loaded at `006cfeb8`: shooter `+69`, treated by R10 as the player/record pointer passed to `0062ed70`. R30-A creates a synthetic roster sufficient for its keeper-prefix tests and leaves this field zero. The null diagnostic is selected by this argument regardless of the lookup receiver. Filling only `00b63d28` would not change that branch.

The lookup global is a second missing input. It has no raw PE backing at `00b63d28`, and the original-image loader leaves the mapped storage zero. No game initializer or object constructor runs in this experiment. In the nonnull-input path, `0062ed70` reads the pointed record's index and global count, can call refresh helper `0062c680`, and only then resolves a cached record. Those storage, stamp, refresh and lifetime conditions must be established before admitting that path. The zero shooter `+6d` attribute pointer and later slot-float inputs also remain unprepared, but are not read before this first frontier.

There are two distinct follow-ups: admit `00944cff` and subsequent diagnostics to investigate the **actual null-input failure path**, or construct a new producer-backed synthetic domain with valid participant/lookup state **before resolver entry**, then rerun the entire connected path. Replacing the null lookup with return zero, inserting pointers after the prefix, or jumping to the low-float `006d0980` branch would not continue this oracle faithfully. The latter helper and its R25 reconstruction remain read-only context here.

## Integrity and reproduction

The [extractor](../scripts/extract_action33_effect_30.py) matches every operand in the complete 2,624-byte `006cfe10` body (887 instructions) and 187-byte `0062ed70` body (60 instructions) against the existing read-only exports-09 and exports-10. It records direct CFG edges, calls, return cleanup and store widths. The eight unexecuted indirect branch sites in the full effect body remain unresolved in that broader static context; they are not part of the executed admission. All 115 admitted continuation/RNG/CRT instruction starts and operands match, as does the unexecuted stop CALL. The PE is hash checked before extraction or execution.

Those older folders have no manifest, so their individual assembly and pseudocode files are pinned. The assembly hashes are `91c571aa3902a311fac6ea69f36836dde6cb2d2427c9a9d9ce687e82e3e91cf9` for `006cfe10` and `9b0bd12347e822108343cd47f26cfd81f47a577075c6463f853bde53cefd476e` for `0062ed70`; all four export digests appear in the site evidence. The original caller listing is pinned at `40afb06c0e55a22091d0aff2bcca1521feadc9fae0bb87f9416ab4a72472f8cf`. RNG/CRT use the fresh R30 runtime export manifest `4ef765c1d661f044d2c80eacdecaee7600e0d4eb8766901872c8444f6d71545c`. No shared native inputs, annotations or checkpoints were changed.

The [verification script](../scripts/verify_action33_effect_30.py) and [integrity receipt](../evidence/action33-effect-30-integrity.json) establish byte-identical regeneration under normal Python and `python -O`. Seven negative checks reject a changed PE, independently changed native branch operand, changed native export, injected player pointer, injected lookup object, normalized fourth argument, and execution of the diagnostic stop instruction. Integrity gates use explicit exceptions, not `assert`. The [Node checker](../scripts/check-action33-effect-30.mjs) verifies hashes, schemas, prefix-state continuity, nested draw order, pending-call status, argument widths and the retained memory boundaries. It also pins the integrity receipt SHA-256, validates its exact keys, status and seven negative-check names, and cross-checks its specimen/sites/oracle hashes and case/frontier totals. It checks evidence, not a TypeScript effect implementation.

```text
python scripts/verify_action33_effect_30.py PRIVATE_EXE --exports09 EXPORTS_09 --exports10 EXPORTS_10 --runtime EXPORTS_30_RUNTIME --output results/effect-normal.json
python -O scripts/verify_action33_effect_30.py PRIVATE_EXE --exports09 EXPORTS_09 --exports10 EXPORTS_10 --runtime EXPORTS_30_RUNTIME --output results/effect-optimized.json
node scripts/check-action33-effect-30.mjs
npm run check
```

All checks passed using Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.22.0. The normal/optimized receipts match. The existing research suite also passes, including its registered R30-A checker. The coordinator can register the new R30-B checker on adoption; this branch does not edit the shared runner, queue, atlas or checkpoint files. A successful effect return, TypeScript composition and live-game participant validity remain open.

### Review regression checks

Independent review found that the native-export mutation check assumed ignored `results/` already existed, and that the Node checker did not read the retained integrity receipt. The verifier now creates that directory before allocating its temporary export folder. The receipt remains byte-identical, SHA-256 `41f0a30117a36b5879c3a23523364e10b539b34007026b43adcc0ec577480401`.

The [review regression script](../scripts/test_action33_effect_30_review.py) archives the staged Git tree into two separate temporary checkouts and explicitly verifies that neither contains `results/` before running normal Python or `python -O`. Both regenerate the retained receipt exactly and pass the Node checker. In a copied receipt, changing `status` to `failed` and independently replacing `negative_checks` with an empty object both fail specifically at the receipt SHA-256 gate. After restoring the receipt, the complete Node 24 research runner passes in the archive. No private input is copied into the archive or retained evidence.

Stage the intended task files before running this check; its ignored output records the exact staged tree and command results:

```text
python scripts/test_action33_effect_30_review.py PRIVATE_EXE --exports09 EXPORTS_09 --exports10 EXPORTS_10 --runtime EXPORTS_30_RUNTIME --node NODE_24_EXE --output results/action33-effect-30-review.json
```

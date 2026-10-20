# R39-A: connected effect call reaches the null participant diagnostic

The continuous [TypeScript model](../reconstruction/action33-effect-39.ts) now executes the actual `007024b4 -> 006cfe10` effect call on all **224 R38-A nonnull cases**, including both initial RNG groups and the nested `006cfec2 -> 0062ed70` lookup call. All 224 stop **before `0062ed99 -> 00944cff`**. The effect and lookup calls remain pending. The eight null-keeper cases retain their earlier stop before `00702332 -> 00944cff`.

This advances original-instruction-validated TypeScript from resolver entry `00702050` to the first unsupported transitive call in the existing synthetic domain. It establishes no effect, lookup or resolver return, goal/save outcome, live reachability, saved-game initialization or valid participant lifecycle. R30-B's 160-case original-only continuation remains a separate domain.

## Provenance and unchanged entry state

The specimen is the 7,192,576-byte PE32 image with SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses are virtual; the oracle's range receipts record file offsets separately. The baseline is merged R38-A at `c90f826c5ce3df6fbf1944296208c8f2e6e8476d`.

The [generator](../scripts/emulate_action33_effect_39.py) pins R38-A's generator, TypeScript model and oracle, plus the R30-B extractor and oracle. It reruns the unchanged 232-case schedule from resolver entry in one Unicorn instance per corpus, reseeding each case only at its original entry. Before executing `007024b4`, it requires equality with the retained R38-A complete represented state, all prior instruction addresses and memory events, every completed call and all 21 prior region digests. It also regenerates R38-A's complete per-instruction keeper/caller state digest. The TypeScript checker independently performs the same comparisons.

No argument, participant pointer, lookup object, effect return, RNG state, stack frame or intermediate checkpoint is inserted at the continuation boundary. The five original-produced argument dwords stay `[shooter, 0000006d, 00000000, 04100000, 00000000]`. The full fourth dword is preserved throughout the suspended effect call. The actual CALL instructions push their own return addresses.

The admission remains the predecessor's finite synthetic match/table/grid/stack schedule, action `33`, nearest/even 53- or 64-bit x87 precision, and signed-small-bound RNG. Reserve selection, contact/bit-04 routes, nonnull participant storage, diagnostic execution, other effects and original runtime producers remain outside the admission.

## Executed effect and lookup behavior

The 72 newly admitted instruction starts comprise `007024b4..007024b9`, `006cfe10..006cfec7` and `0062ed70..0062ed99`. The unexecuted stop CALL is independently checked. Every new instruction is compared operand by operand with pinned private `exports-09/006cfe10.asm`, `exports-10/0062ed70.asm` and the caller listing. R30-B's extractor also rechecks its full static effect/lookup bodies and runtime instruction comparisons; those wider static bodies are not executable admission here.

The effect allocates 24 bytes, saves EBX/EBP/ESI/EDI, captures ECX in EDI, initializes two selector bytes to `ff`, and stores two float32 bit patterns for 4.0. These stores are represented as dword writes; no x87 effect calculation has yet executed.

Each of the two initial groups draws `a=R(102)` followed by `b=R(a)`. If the signed low byte of `b` exceeds 50, the group draws `R(3)` and, if nonzero, replaces `b` with `R(R(76))`. Both groups execute even though the second participant argument is null. The reconstruction preserves byte-width comparisons, original stack cleanup, saved register bits, flags, nested draw order and the shared caller RNG cells.

At `006cfeb8`, the original code reads shooter dword `+69`, which is zero in every admitted case. At `006cfebb`, it reads `00b63d28`, which remains zero in the image's mapped storage and has no raw PE backing. No game initializer has run for either input. The actual lookup call therefore enters with ECX=0 and argument=0.

`0062ed70` allocates its 512-byte frame and saves ESI/EDI. Its test of the participant argument selects the null diagnostic branch; `0062ed83` is not taken. The reached instructions prepare two stack buffers and push the source-pointer address and four remaining arguments. At the stop, ESP is `02007708` and the five diagnostic dwords are `[009e7f28, 00000000, 00000000, 02007824, 02007724]`. The source string's bytes are not read.

Both `007024b4 -> 006cfe10` and `006cfec2 -> 0062ed70` remain in the pending call list with `after: null`. Terminal registers are the suspended lookup state, not callee return values. `00944cff`, later diagnostics, cache/refresh behavior, the remainder of the effect and `006d0980` are unexecuted.

## Original-to-TypeScript comparison

The [1,716,300-byte oracle](../evidence/action33-effect-39-oracle.bin), SHA-256 `fc0771a515e0e142b3b1d1d5ffd62bebf6710aa93b258e6fa66a4cab78e8958d`, retains **263,330 total original instruction steps** and **116,866 ordered memory events**. The new continuation adds:

| Measurement | Count |
| --- | ---: |
| Instruction-state snapshots | 39,146 |
| Ordered memory events | 19,661 |
| Writes | 10,009 |
| Completed RNG calls | 1,096 |
| Zero-bound calls | 3 |
| CRT wraps | 0 |
| Effect returns | 0 |
| Lookup returns | 0 |

The first optional `R(3)` executes 44 times, with its replacement pair executing 26 times. The second executes 52 times, with its replacement pair executing 26 times. Per-case effect RNG counts are 4, 5, 7, 8 or 10. There are 2,343 completed RNG calls over the entire connected corpus. Its 70 CRT wraps all occur before the new effect continuation.

The [checker](../reconstruction/check-action33-effect-39.ts) compares every represented integer register, EFLAGS, x87 control/status/tag and active payload, all instruction addresses, the digest of every new instruction's complete state, ordered memory operands, call arguments and complete before/after states, pending calls, ordered RNG and **22 final region digests**. The additional region is the four-byte lookup global; the entire 64 KiB stack remains covered. Each RNG call is also compared independently with the existing scalar `nextBounded` model.

Only stack and RNG-state writes occur in the new continuation. All match, tactical, grid, table, scalar and dispatch data remain equal to the preceding R38 checkpoint. The lookup global stays zero, the five effect arguments stay intact, and x87 control/status/tags remain unchanged. Empty physical x87 payloads, FIP/FDP, exceptions and hardware-specific undefined flag behavior remain outside the existing representation; the oracle targets Unicorn 2.1.4.

R30-B had already observed this same diagnostic frontier on its own 160-case original-only schedule, with 764 additional RNG calls. This unit runs the 224 current original-produced R38 cases and implements their full represented machine continuation in TypeScript. It does not reuse R30-B draws or return values, expand R30-B's domain, or establish a full machine-state join to the separate R30-C semantic implementation.

## First remaining gap

The first missing normal-path input is the participant pointer read from shooter `+69`. The uninitialized lookup global is a second missing input. Supplying only a lookup receiver would not change the null participant branch. A normal effect path requires producer-backed participant and lookup state before resolver entry, including the record index, cached rows, stamp/refresh conditions and their lifetime. R39-B owns that provenance investigation.

For this unchanged corpus, the first unsupported execution is `0062ed99 -> 00944cff`. Continuing the actual null-input path would require admitting that diagnostic helper and subsequent behavior. Neither replacing the lookup with zero nor installing a nonnull pointer after resolver entry would be a faithful continuation.

## Integrity, privacy and reproduction

The [verifier](../scripts/verify_action33_effect_39.py) and [receipt](../evidence/action33-effect-39-integrity.json) require byte-identical original-instruction regeneration in normal and optimized Python processes. Seventy-seven negative probes reject changed PE/native operands/export files/synthetic table, changed R38 checkpoint state, injected participant/lookup pointers, normalization of the fourth argument, altered draw state or selector byte, damaged lookup stack, changed terminal flags, execution of the diagnostic stop, fabricated effect return, removed pending calls and damaged public payloads. The reused R38 snapshot and bounded decompression implementation is independently source-pinned by the verifier.

Privacy checks scan every overlapping original-code/grid window of **12–32 bytes** in raw and case-insensitive hex, and every padding-free source window of **9, 12, ..., 30 bytes** in base64. The nine-byte base64 samples cover the aligned interior of a 12-byte excerpt embedded at any of the three encoding offsets. Both task files and decompressed oracle JSON are scanned. Regression probes cover 12-, 13-, 14-, 21-, 29-, 33-, 48-, 64- and 96-byte excerpts at every base64 group alignment, including later offsets in the effect body. The public evidence contains synthetic operands, scalar addresses/constants and digests; no original executable/code bytes, original grid/table contents, private exports or runtime captures are retained.

The TypeScript checker also rejects four machine-effect mutations and four unsupported input mutations. The task checker and full repository check pass under Node 24.19.0. Normal and optimized verification receipts are byte-identical under Python 3.13.7, Capstone 5.0.7 and Unicorn 2.1.4. The task checker is invoked separately because shared runner registration belongs to the coordinator.

```text
python scripts/verify_action33_effect_39.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --exports09 EXPORTS_09 --exports10 EXPORTS_10 --output results/effect39-normal.json
python -O scripts/verify_action33_effect_39.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --exports09 EXPORTS_09 --exports10 EXPORTS_10 --output results/effect39-optimized.json
node reconstruction/check-action33-effect-39.ts
npm run check
```

Only seven R39-A files are changed. Shared runner, queue, frontier, registries, native database, installed game, save and live process are outside this unit.

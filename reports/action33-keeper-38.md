# R38-A: connected original-entry keeper call and caller continuation

The [TypeScript continuation](../reconstruction/action33-keeper-38.ts) executes the actual `00702416 -> 00700420` keeper call on the state produced by R37-B, including the original six raw argument dwords, output-pointer aliases, keeper receiver, x87 state and shared RNG. All **224 nonnull cases return from the keeper** and continue to **before `007024b4 -> 006cfe10`**. The eight null-keeper cases retain their stop before `00702332 -> 00944cff`. Neither pending boundary call executes.

The model runs from resolver entry `00702050`; it does not insert a keeper response, restore an intermediate checkpoint or borrow R30-C's supplied segment inputs. This is original-instruction validation on the existing synthetic schedule. It does not establish resolver return, goal/save outcome, live-game reachability or original-game state initialization.

## Provenance and admission

The pinned PE32 specimen is 7,192,576 bytes with SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All code addresses are virtual addresses; the range receipts separately record file offsets. This worktree is based on the reviewed R37-B continuation, with the R38-A assignment recorded in the coordinator's queue.

The [oracle generator](../scripts/emulate_action33_keeper_38.py) pins R37-B's generator, TypeScript model and oracle, plus the R30-C oracle. Every original execution begins with the unchanged 232-case schedule. Before the keeper call, the complete represented state, prior instruction trace, memory events, completed calls and all 15 prior region digests must match R37-B exactly. The TypeScript checker independently executes the same prefix and checks that boundary.

The new 201 admitted instruction starts comprise keeper ranges `00700420..007004f1` and `00700a4f..00700b9f`, tactical lookup `006c38c0..006c38ea`, and caller ranges `00702416..00702463` and `00702498..007024b4`. They are compared operand by operand with the pinned native exports in `exports-30-action33-prefix`, `exports-29` and `exports-09`. The pre-effect CALL is checked but not executed. Small-bound RNG, CRT and `__ftol` instructions were already admitted by predecessor units; their machine effects are now reconstructed for the keeper's inputs too. Six immutable binary64 scalar constants are checked against the PE and included as separate memory regions.

The admission remains action `33`, the unchanged finite synthetic grid/table/match/stack schedule, explicit nearest/even 53- or 64-bit x87 precision, and the recovered signed-small-bound RNG path. R36's reserve routes, the earlier bit-04/contact branches, null diagnostics, other keeper actions, large RNG bounds, exceptional floating-point inputs and original runtime producers remain outside this unit.

## Keeper ABI and effects

The original call pushes its return address and allocates the keeper frame on the existing stack. The prelude saves EBX, EBP, ESI and EDI, captures both output pointers, then initializes both output bytes before checking eligibility. It reads the low variant byte to select keeper word `+168` or `+16a`. The selected word overwrites only two bytes of a stack dword whose pointer value was already captured. The distance spill similarly reuses the outgoing variant argument's stack location. The reconstruction preserves these aliases and byte/word widths.

The grid is read and spilled before activity or tactical-position rejection. The actual `006c38c0` call retains its low-word return semantics, signed index and side loads, original table access order and `RET 4` stack cleanup. A rejected keeper follows `00700b92`, clears AX with the original 16-bit XOR, restores the saved registers and returns with `RET 24`.

Eligible cases execute both base RNG calls, the finite x87 postlude, each actual `__ftol` conversion and any fallback draws. The machine model represents the original temporary stores, full EDX:EAX conversion return, saved/restored control word, active physical x87 payloads, TOP, tags and signed zero. Integer flags include the actual `ADD ESP,-0xc` in `__ftol`. The signed-small-bound RNG model consumes original-produced bounds, preserves the zero-bound early return and negative-bound remainder adjustment, and shares the caller's real modeled cells and table. The scalar `nextBounded` is separately compared against every observed RNG call.

The 224 keeper calls comprise 72 rejections, 91 retained responses, 16 weighted fallbacks and 45 redraw fallbacks. They make **791 keeper RNG calls**: 594 positive, 96 negative and 101 zero bounds, plus **488 `__ftol` calls**. The 70 CRT wraps in the complete corpus occur in the preceding variant draw; no keeper draw wraps in this fixed schedule. The reused CRT body remains validated by those same original-entry executions. All 224 keeper returns preserve EBX, EBP, ESI and EDI, restore the incoming control word, leave an empty x87 stack, and advance the caller's pre-call ESP by 24. Full EAX is compared even though all upper words happen to be zero in this corpus.

After return, the caller saves full EAX, tests the actual fallback output byte, and applies its signed AX thresholds of 375 and 260. The action33 path bypasses `006c87e0`, zeroes EDI, and constructs the five effect-call dwords. The fourth retains ECX's high word after a 16-bit `MOVSX CX,byte[...]`; it is `04100000` in the corpus. No effect return is supplied.

## Comparison and the R30-C boundary

The [1,491,007-byte oracle](../evidence/action33-keeper-38-oracle.bin), SHA-256 `d5e9ed42bae44b49a0c21dc21b6e7e045f7eb724b2b2a3f9770eddecf703a53d`, contains **224,184 original instruction steps** and **97,205 ordered memory events**. The new continuation contributes **54,389 instruction-state snapshots**, 29,462 memory events and 11,062 writes. There are 1,247 complete RNG calls across the entire prefix and continuation, including the earlier 232 zero-bound calls and 224 variant calls. The added continuation visits 247 distinct instruction starts, including previously admitted runtime bodies.

The [checker](../reconstruction/check-action33-keeper-38.ts) compares every represented register, EFLAGS, x87 control/status/tag and active payload, complete call-before/after states, every instruction address, each ordered memory operand, and all **21 final region digests**, including the full 64 KiB synthetic stack. Each new instruction's complete state contributes to a canonical ordered JSON digest. Empty physical x87 payloads, FIP/FDP, exceptions and hardware-dependent undefined flag behavior remain outside this representation; the comparison targets Unicorn 2.1.4.

For the 160 baseline cases, independently derived keeper response words, output flags, caller markers, paths, outgoing dwords, all variant/keeper RNG draws and four complete game-data region digests agree with R30-C. This closes the connected original-entry TypeScript gap across the keeper and the remainder of R30-C's interval in this new machine model.

It is **not a full machine-state join to the existing R30-C semantic implementation**: that implementation has no CPU stack, scratch-register, full EAX or x87 status/tag representation to compare or accept. Its supplied checkpoint and semantic projections remain separate evidence. The full machine equality established here is between the new continuous TypeScript execution and the corresponding original instructions. The first remaining connected machine-state gap is **`007024b4 -> 006cfe10`**. R30-B's original-only effect continuation and its missing participant/lookup state are downstream context; this unit supplies neither those pointers nor a return value.

## Integrity, privacy and reproduction

The [verifier](../scripts/verify_action33_keeper_38.py) and [integrity receipt](../evidence/action33-keeper-38-integrity.json) require byte-identical regeneration in separate normal and optimized Python processes. Forty-four negative probes reject changed PE/native operands/export files/synthetic table, damaged preserved registers or stack cleanup, changed upper EAX bits or x87 status, altered RNG state/output pointer/caller marker, another action route, malformed or oversized public payloads, changed state digest, and raw/hex/base64/compressed private fragments. Integrity checks use explicit exceptions under `python -O`.

The privacy gate scans overlapping windows across admitted original code and the original grid: every 32-byte window (or the whole range when 12–31 bytes long), plus every 30-byte window, shortened to a multiple of three in smaller ranges. It checks raw, case-insensitive hex and base64 encodings in task files and expanded oracle JSON. The 30-byte encodings contain no padding and therefore also match inside longer encoded excerpts. Original table values are excluded by the pinned synthetic-table replacement and its digest. The public oracle contains synthetic operands and compact scalar/digest provenance; private PE/native bodies, original grid/table data and raw runtime captures are not committed.

Independent review found that the original scanner's padded 32-byte base64 samples missed longer encoded excerpts. The corrected scanner adds overlapping padding-free samples. Twenty-four regression probes insert 33-, 48-, 64- and 96-byte excerpts from keeper VA `00700a4f` and grid VA `00a15e84` into compressed JSON, testing each of the three base64 group alignments. All are rejected under normal and optimized Python. The Node checker requires each named regression result as well as the new receipt digest; gameplay code and oracle are unchanged by this repair.

The Node checker also executes five deliberate machine-effect mutations and rejects altered action/precision admission. It pins the oracle and integrity receipt independently. The task checker and full repository check pass under Node 24.22.0; normal and optimized receipts are byte-identical under Python 3.13.7, Capstone 5.0.7 and Unicorn 2.1.4.

```text
python scripts/verify_action33_keeper_38.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --output results/keeper38-normal.json
python -O scripts/verify_action33_keeper_38.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --output results/keeper38-optimized.json
node reconstruction/check-action33-keeper-38.ts
npm run check
```

Only R38-A files are changed. The coordinator can register the checker after review. No shared runner, queue, frontier, registry, native database, installed game, save or live process was changed or accessed by this unit.

# R35-A: original zero-bound RNG and selector-call boundary

The [TypeScript continuation](../reconstruction/action33-rng-35.ts) executes the real action 33 prefix from `00702050`, calls the zero-bound path of `0090cfc0` at `00702241`, and continues to **before `0070230c -> 006ce110`**. The preceding R34-A helper result, stack, RNG state and mutable synthetic regions flow directly into this continuation. No intermediate RNG result or `007022fd` checkpoint is supplied to the TypeScript execution.

This establishes a longer original-instruction comparison on synthetic state. It does not establish a live match, resolver return, shot outcome, or a full machine-state join to the separately scoped R30-C composition.

## Evidence and dependency

The pinned PE32 x86 SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All code addresses are virtual; the retained range metadata separately labels file offsets. The [generator](../scripts/emulate_action33_rng_35.py) checks the original PE, inherited caller/helper exports and fresh RNG runtime exports before executing the instructions. The additional read-only `exports-30-action33-runtime` manifest SHA-256 is `4ef765c1d661f044d2c80eacdecaee7600e0d4eb8766901872c8444f6d71545c`; the `0090cfc0.asm` digest is `0dcc691c2e21d447bdd4adbad330f3ccc037901fe34d0aa665395ecbe409092d`.

This unit depends on the reviewed R34-A task files at commit `f2a0728`, now merged in PR #126. Its generator and reconstruction hashes, along with the R34-A/R30-A/R30-C oracle hashes, are pinned in the new evidence. Those seven dependency files were copied locally after Git-object verification for this investigation; they are not part of the R35-A commit. No canonical native database or annotation was changed.

The [299,063-byte oracle](../evidence/action33-rng-35-oracle.bin), SHA-256 `edb057f22e3b5eec75ca0583a03f0b1c291e2ec96403cbf7efb61bf8d31f3a32`, retains **232 original-entry cases, 101,443 instruction steps, 45,139 ordered data/stack events and 232 actual RNG calls**. These use the unchanged 232 R34-A clear-path cases: 160 baseline cases, 44 additional opponent/comparison cases and 28 distance cases. Their inputs remain synthetic, including the public RNG table and float32 grid. The separate bit-04 path and directed-rounding conversion probes are outside this continuation.

Each case records its state, region digests, trace, memory events and completed calls immediately before `00702241`. Those records must match its R34-A oracle exactly. The [Node checker](../reconstruction/check-action33-rng-35.ts) separately derives the same checkpoint by executing the TypeScript prefix from resolver entry and compares it to R34-A. It then compares every one of the **5,104 new instruction snapshots** (22 per case), the complete instruction sequence, ordered memory values and widths, call/return snapshots, and final state. The represented state includes all eight integer registers, EFLAGS, x87 control/status/tag and active payloads, plus the cursor, offset, limit and CRT seed cells. Digests cover all nine admitted regions: match, tactical positions, stack, RNG table, grid and four scalar constants. The four RNG cells are compared as exact dwords in every snapshot.

Physical empty x87 payloads, instruction/data pointer registers and hardware exception behavior remain outside the representation. EFLAGS observations match pinned Unicorn 2.1.4, including its treatment of architecturally undefined flags such as AF after logical operations; this is not a general hardware-status claim.

## Exact zero-bound call and caller effects

The existing `nextBounded` scalar implementation already returns zero without advancing state for bound zero. This unit adds the original machine-state ABI and caller effects that scalar behavior does not represent.

`0090cfc0` pushes ECX and ESI, loads the actual bound dword from its stack, and tests it. Bound zero takes the short path: XOR EAX,EAX; restore ESI and ECX; plain RET at `0090cfce`. There is no callee argument cleanup, random-table read, RNG-cell read/write or CRT call on this path. EAX becomes zero; EBX, ECX, EDX, ESI, EDI and EBP are unchanged across the call. The return ESP equals the caller's pre-call ESP, leaving the argument present for the caller to remove. The original CALL and two callee pushes still make real stack writes, and the bound, saved registers and return address are read in original order.

The caller writes EAX as a **dword** at `[ESP+80]`, which at this point is frame `+7c`: this extends beyond the adjustment helper's earlier output-word write. It subtracts zero from EDI, reloads the match pointer, adds four to ESP, and writes the unchanged quality dword back to the incoming argument. At `0070225f`, it compares the shooter against `match+f5aa`; that field is zero in the retained schedule, so `JNZ` at `00702265` reaches `007022fd`. The contact-candidate branch beginning at `0070226b` does not execute.

The five instructions beginning at `007022fd` load the shooter's side into DL, reload ECX=match, test DL, set AL to the opposing selector and push EAX. Only AL is replaced: the actual pushed selector argument is `04100001` for side zero and `04100000` for side one. The high bytes come from the preceding match-pointer value in EAX. The first unsupported machine-state call is now **`0070230c -> 006ce110`**, before the CALL instruction executes. Its argument dword, receiver, registers and x87 state are retained. No selector return is injected.

## R30-C projection and remaining join

For the 160 unchanged baseline cases, the original-produced `007022fd` input projection matches R30-C exactly: match/shooter pointers, action, mode, marker bytes, zero local byte, precision, complete semantic RNG state, and entire match/tactical-region digests. The TypeScript-derived projection independently matches the same records. At pre-`0070230c`, all eight registers, FPCW and the raw selector argument also match R30-A's original call snapshot.

This is an **input projection match**, with no patching of the TypeScript-produced memory. R30-C's semantic segment excludes original stack writes, several scratch-register and full-return effects, keeper operand-read order, and x87 status/tag evolution. Its retained `007022fd` projection does not contain the full CPU/stack checkpoint needed for the stricter join. Accordingly the R30-C full machine-state join remains open. The next work is admitting `006ce110`'s machine ABI and effects on this actual incoming frame, followed by the variant and keeper call boundaries; its existing semantic selector implementation is a useful dependency, not a replacement for those observations.

Unsupported nonzero bounds stop at `0090cfcf`; the caller's matching-contact branch stops at `0070226b`. The prior bit-04 boundary remains `0071614b -> 005b58e0`. None is promoted to completed behavior by this evidence.

## Integrity and checks

The [verifier](../scripts/verify_action33_rng_35.py) regenerates byte-identical oracles in normal and optimized Python subprocesses. Fourteen negative checks reject changed PE bytes, an independent RNG stack-operand mutation, a changed native RNG file, a changed synthetic table, a nonzero actual bound, the unsupported contact branch, a changed actual RNG cell, noncanonical or oversized public payloads, a changed retained instruction snapshot, and raw/hex/compressed private code fragments. Integrity checks use explicit exceptions and stay active under `python -O`. The Node checker adds unsupported bound/contact rejections and pins the oracle and integrity receipt hashes.

```text
python scripts/verify_action33_rng_35.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --output results/rng35-normal.json
python -O scripts/verify_action33_rng_35.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --output results/rng35-optimized.json
node reconstruction/check-action33-rng-35.ts
npm run check
```

Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.19.0 were used. The normal and optimized verification receipts are byte-identical. The task checker and full repository check pass. The shared runner, registry, queue and frontier are coordinator-owned and unchanged here; register the new checker during integration. Original PE bytes, native export bodies and full private memory images remain outside Git.

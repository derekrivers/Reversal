# R30-A: original action33 entry to the pre-effect boundary

The pinned original instructions execute from `00702050`, with action `0x33` and mode 3, to **before** the call instruction at `007024b4`. The 160 retained synthetic cases execute the real early helpers, keeper selector, variant draw and keeper entry. They use no patched instructions, replacement callees, injected return values or resumed mid-function frames. `006cfe10` does not execute.

This is a connected **original-execution prefix oracle**, with a static dependency map. There is no new TypeScript implementation or TypeScript equivalence claim. No complete shot, goal/save outcome, resolver return, live-match reachability or real match state is established. In particular, the evidence must not be entered as a completed TypeScript scope in the validation registry.

The specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The branch begins at main `6ecf14fdde9e7727aa607cb07dcecd5c36e39c40`. All code addresses below are virtual; [site evidence](../evidence/action33-prefix-30-sites.json) labels file offsets separately. The 1,124-byte caller prefix has SHA-256 `ea2f7f04449d66f00a25e1d66ddeb2a19818770dbd1519264f2fc281925446ed`.

## Earlier calls that must precede the R09 ledger

The R09 ledger starts at `00702241`. Original entry first reaches two calls that must be admitted before that ledger can be used in a connected run:

| Caller site | Original callee and actual admission |
| --- | --- |
| `00702088` | `006f09b0`, ECX=shooter, arguments `(4, side==0 ? 11 : 0)`. This is the R12 call-free float32 grid lookup, returning in x87 ST0 and using `RET 8`. The caller stores its result at frame `+80`. |
| `0070210b` | `006d59b0`, ECX=match, one argument=shooter, `RET 4`. This 93-byte helper calls `00714d30` at `006d59bc`, then may call `007160f0` at `006d59f0`. It returns a count byte in AL, saved by the caller at frame `+25`. |

`00714d30` is four bytes: it reads the shooter's side byte `+27` into AL and returns. `006d59b0` converts zero side to array selector 1 and any nonzero side to selector 0. It scans 20 slots, stride `1be`, from `match+4796` or `match+6a6e`. For every nonnegative signed `slot+19`, it calls `007160f0` and increments BL if EAX equals the shooter pointer. The helper has no direct game-state store or RNG call; it does have normal stack writes, and its general transitive effects depend on `007160f0`.

The admitted `007160f0` path saves four registers, calls `005b57c0` at `0071611c`, tests AL bit `04` at `00716121`, and takes `JE 00716194` at `00716123`. It restores the saved registers and returns EAX=0 at `0071619a`. The 15-byte getter takes the low signed byte of its stack argument as an index and reads AL from `[ECX+5b4+index]`, then `RET 4`. Here ECX is `match+91e2+18e3*signed8(slot+27)`. The synthetic tactical flags at these addresses are zero. The other bytes of the pushed argument are incidental and are retained in the call records.

This is a real guarded execution with an active opposing keeper in its normal roster array. It does not avoid the dependency by putting every opposing slot into an inactive state. Each case calls `007160f0` once. With the guard satisfied, the scan returns count 0, makes no game-state write and consumes no RNG.

**First unsupported early branch:** if the getter returns bit `04` set, execution falls through to `00716125`. The next new callee is `005b58e0` at `0071614b`; later branches involve tactical lookups and additional runtime state. The negative run sets this bit on the actual opposing slot and fails exactly at `00716125`. No success record is emitted for that run. This boundary limits the admitted domain; it did not prevent the 160 guarded cases from reaching the requested endpoint.

## Ordered original calls, state and RNG

Let `S` be resolver entry ESP and `F=S-694` the frame after its `684` allocation and four saved-register pushes. Entry ECX is the shooter. The six stack arguments are action, quality, event code, mode, 0 and 0. They appear at `F+698/+69c/+6a0/+6a4/+6a8/+6ac` after the prologue. The event code is `1f7f` in this schedule and is not dispatched before the endpoint.

| Order | Site | Actual effect in the admitted cases |
| --- | --- | --- |
| 1 | `00702088` | Original grid helper described above. No RNG. |
| 2 | `0070210b` | Original opponent scan, side getter and flag getter. No RNG or game-state writes in the guarded path. |
| 3 | `0070213d`, `0070215b` | Write shooter side byte to `match+8d4e`, then write `trunc(signed16(match+8ed0)/11)` as a word to `match+8d4c`. These writes precede the adjustment helper and keeper selection. |
| 4 | `00702193` | Original `00945640` converts the distance calculation; the caller derives the existing quantized byte at `F+1b`. Its x87 control word is restored. |
| 5 | `007021e5` | A second original grid-helper call, with the same coordinate arguments in the stable synthetic state. |
| 6 | `00702222` | Original `00713e90` entry and action33 early return: AL=2, output word at `F+7c`=0, `RET 1c`. No transitive callee is taken. The caller still performs an additive-zero **word write** to shooter `+39` at `00702237`. |
| 7 | `00702241` | Original `R(0)`: return 0, no RNG-state advance. Quality at `S+8` is written back unchanged at `00702258`. |
| 8 | `0070230c` | Original `006ce110` with ECX=match and opposing selector in the low argument byte. Both side caches are processed. The fixture covers retained cache, direct selection, invalidated cache and active fallback. The returned pointer is nonnull and remains in EBX and `F+48`. |
| 9 | `007023e3` | Original `R(2)` after the action33 switch resolves byte-table index 4 to `007023e1`. AL is stored as variant at `F+1c`. This draw shares the same RNG state with the later keeper draws. |
| 10 | `00702416` | Original `00700420`, ECX=selected keeper, six arguments: shooter x/y low bytes, variant low byte, action33, pointer `F+20`, pointer `F+14`. It executes the original tactical-word, RNG, CRT-wrap and `__ftol` instructions when reached. Rejected keepers consume no further draws; eligible keepers consume four draws for a retained response or seven for a fallback response. |
| 11 | `0070241f..0070243a` | Save full EAX at `F+38`. If fallback flag `F+14` is zero, signed AX>375 sets byte `F+1a`, else signed AX>260 sets `F+19`. The first keeper output `F+20` remains zero. |
| 12 | `00702498..007024ad` | Action33 bypasses `006c87e0`, clears EDI and builds the real `006cfe10` argument frame. Stop before `007024b4`. |

The oracle has 64 rejected-keeper cases, 65 retained-response cases and 31 fallback cases. Ten fallback cases take the weighted redraw at `00700b1e`; 21 take the redraw at `00700b45`. The marker bytes include both >260 and >375 branches. There are 797 RNG calls in total: 160 zero-bound caller calls, 160 variant calls and 477 keeper calls. The 54 original CRT calls occur on table wrap. Zero bounds remain calls but do not advance the cursor.

Every RNG record includes the call site, signed bound, result and complete cursor/offset/CRT state before and after. The call trace captures entry argument dwords, all eight integer registers before and after each nested call, stack cleanup and x87 control-word restoration. It checks EBX/EBP/ESI/EDI preservation for each actual callee. The outer resolver has not returned, so no outer `RET 18` behavior is claimed here.

## Exact stop boundary

Before the unexecuted call at `007024b4`, ECX=match, ESI=shooter, EBX=selected keeper, EDI=0, EBP=0 and ESP=`F-14`. The five outgoing argument **dwords**, in callee argument order, are:

`[shooter, 0000006d, 00000000, 04100000, 00000000]`

The fourth dword is not a clean 32-bit zero. At `0070249a`, `MOVSX CX,byte[F+30]` writes only CX, leaving ECX's upper word from the match pointer. The zero local byte therefore becomes a zero **low word** with upper bits retained, and `PUSH ECX` at `007024a2` pushes `04100000` in this memory layout. `007024a3` then reloads ECX=match. The earlier shorthand `006cfe10(shooter,6d,null,0,0)` hides this register-width detail. A future consumer must check which width the callee actually reads before normalizing the argument.

All 160 cases finish with the requested FPCW (`027f` or `037f`) and an empty x87 tag word. The next boundary requiring new execution admission is `006cfe10` itself, which R09/R10 show begins with nested RNG groups. The present prefix supplies its actual input state; it does not supply an effect-helper model or permit concatenating independent category/gate fixtures.

## Synthetic state and evidence limits

The [emulator](../scripts/emulate_action33_prefix_30.py) gives the complete deterministic input schedule. Match memory is 64 KiB at `04100000`; tactical word tables are 4 KiB at `04300000`; the stack is 64 KiB at `02000000`, entry ESP=`02008000`. Each region starts at zero except the explicit schedule. The shooter is roster row 3 of its side, and each side's keeper is row 0. Both have the match context pointer; all other rows have signed index -1. The shooter's active index is 3 and the keepers' is 0. Reserve reassignment is not exercised in this prefix fixture.

Both sides, both explicit x87 precision settings, coordinate values within x=0..8/y=0..11, sampled signed clock words, quality dwords, ratings, fallback ratings, counters and match bytes are included. These are sampled cases, not an exhaustive input-domain proof. The two precision groups do not establish live-match precision or exhaustive cross-precision equality. Match `+f5aa` is zero, so the earlier contact/assist branch is bypassed at `00702265` before its candidate is dereferenced. Null keeper/error paths are excluded. The fixture has stable mapped memory with the intended in-match slot aliases and no concurrent mutation.

The random table is the existing public synthetic 51,000-word fixture, SHA-256 `befdec88f802582bba7450e418aaa39837036c8d038810158cfc7a998be1b3db`. The grid is explicitly synthetic float32 `hypot(x,y)`, SHA-256 `188bb55f439634304279bb566d74ad4adae19b4b405d524c830a5b540b085a9f`. No original grid run has been made for this prefix. Twelve immutable PE constant/dispatch windows are read-only and identified by digests, without publishing their bytes. Every executed memory read/write must fall within a declared synthetic region, RNG state cell or one of those immutable windows; unsupported access fails. Original code is never modified.

The [119,336-byte compressed oracle](../evidence/action33-prefix-30-oracle.bin) is gzip-encoded JSON; its `.bin` suffix uses the repository's existing binary Git attributes. It retains the synthetic inputs, full call/return register snapshots, ordered RNG records, ordered match writes and final match/tables/stack digests. It retains instruction and complete ordered memory-trace digests, plus coverage addresses. Full ordered traces are reproducible with `--private-trace` and are restricted to ignored `results/`; no original executable, bulk assembly or game data is committed. A future reconstruction can compare complete event sequences by regenerating those private traces, or compare their exact digests. This report does not claim that comparison already exists.

## Native integrity, checks and reproduction

The coordinator supplied fresh read-only Ghidra 12.1.4 `-noanalysis` exports from a separately restored checkpoint-28 copy. Their manifests have SHA-256 `5089d7a53a599ffaeada705cc7fb02ae62ab76070e3c886ac57cd99080019a4f` (early/keeper dependencies) and `4ef765c1d661f044d2c80eacdecaee7600e0d4eb8766901872c8444f6d71545c` (RNG/CRT/ftol). The existing exports-29 manifest/preflight and R09 caller export are also pinned in the [extractor](../scripts/extract_action33_prefix_30.py). No native database or annotation was changed.

All 808 instruction starts and operands in the admitted ranges agree with native exports, with one explicit decoder-boundary normalization: Ghidra's `FSTCW` at `00945646` is Capstone/Unicorn's `WAIT` at `00945646` followed by `FNSTCW word[EBP-2]` at `00945647`. The exact native operand is checked before expansion. Full operand comparisons are also made for nine local dependency bodies. Their direct branches/calls/returns are recorded; unexecuted keeper switches remain unresolved in that full-body context and do not become a full keeper contract. The caller's action33 indirect switch is resolved from the pinned PE and verified independently.

The 160 executions cover 662 instruction starts and 713 consecutive instruction edges, totaling 158,784 steps and 66,601 ordered memory events. These are the reached subset of the admitted ranges. [Integrity checks](../evidence/action33-prefix-30-integrity.json) regenerate identical retained static/oracle bytes under normal Python and `python -O`; they reject a changed PE, changed synthetic RNG table, changed native file, independently altered native operand and the unsupported tactical-bit path. Every gate uses an explicit exception, not `assert`.

Run the following with the named private paths substituted. `FRESH` and `RUNTIME` mean the two new export folders; `R29`, `PREFLIGHT` and `CALLER` mean exports-29, preflight-29.json and exports-09/00702050.asm:

```text
python scripts/verify_action33_prefix_30.py PRIVATE_EXE --fresh FRESH --r29 R29 --preflight PREFLIGHT --caller CALLER --runtime RUNTIME --output results/action33-normal.json
python -O scripts/verify_action33_prefix_30.py PRIVATE_EXE --fresh FRESH --r29 R29 --preflight PREFLIGHT --caller CALLER --runtime RUNTIME --output results/action33-optimized.json
node scripts/check-action33-prefix-30.mjs
npm run check
```

The [Node checker](../scripts/check-action33-prefix-30.mjs) validates retained hashes, the gzip envelope, exact public schemas, call order, RNG continuity and the observed boundary/ABI invariants. It is an evidence check, not a gameplay implementation. It passed on Node 24.22.0; the existing `npm run check` also passed. Python checks ran on Python 3.13.7 with Capstone 5.0.7 and Unicorn 2.1.4. The normal and optimized integrity receipts are byte-identical. The coordinator should register the new checker in the shared check runner when adopting this branch; shared queue, atlas, checkpoint and runner files were not edited here.

Next work can either broaden the early `007160f0` flag-set path starting at `00716125`, or admit `006cfe10` using this prefix's actual frame and ordered RNG state. A bounded TypeScript prefix implementation still needs its own ordered read/write, ABI, full admitted-memory and original-instruction comparison before being called equivalent.

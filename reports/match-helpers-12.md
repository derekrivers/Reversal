# Investigation 12: three match helper contracts

`006f09b0` loads one float32 grid element into x87 ST0; `006cb960` computes a signed-byte rectangle predicate in AL; `006bce20` filters a candidate and returns a normalized 32-bit 0/1. The first two have no calls or game-state writes. The third calls unresolved `006f4600` before its final match-byte test, so its transitive effects are open. These contracts remove three immediate unknowns in R11's `007103e0` map; they do not establish a connected action33 outcome.

This is static original-instruction analysis, with no new execution oracle or reconstruction. Specimen SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline: `a5972e1659afa4b2937490cdc57ebd8f4a5887d3`. All instruction addresses are virtual addresses; [compact evidence](../evidence/match-helpers-12-sites.json) labels raw file offsets separately. Names and field meanings remain provisional. The coordinator's checkpoint-11 exports were read-only inputs; no native database was changed.

The extractor independently decodes all 222 owned bytes with Capstone 5.0.7: 20/28/31 instructions respectively. Every instruction address and direct-call site/target agrees with the Ghidra assembly exports. All 56/11/8 incoming direct-call references in the supplied exports are verified against original instruction targets. These are exported reference counts, not a claim about indirect callers. Digests of the three ranges and nine export files identify the inputs without retaining bytes, pseudocode, original grid contents or private paths.

## ABI and state boundaries

Here `S` is entry ESP, before any saved-register push. Argument slots are four bytes wide, but the coordinate and side arguments are read only through their low byte. Calling-convention descriptions below state observed machine contracts rather than original source declarations.

| Entry | Inputs and normal result | Cleanup and register effects |
| --- | --- | --- |
| `006f09b0` | ECX=slot; x byte at `[S+4]`, y byte at `[S+8]`; result is one float32 memory load extended into x87 ST0 | `006f09ea: RET 8`; saves/restores ESI; changes EAX/ECX/EDX and flags. Normal FLD adds one x87 stack entry. |
| `006cb960` | Side byte at `[S+4]`, x byte at `[S+8]`, y byte at `[S+c]`; AL=0/1 | Returns `006cb982/006cb99b/006cb9a0`, all `RET c`. Only AL and flags change; EAX upper 24 bits survive. ECX is unused. |
| `006bce20` | ECX=match; candidate dword at `[S+4]`, x byte at `[S+8]`, y byte at `[S+c]`; EAX=0/1 on normal return | Returns `006bce76/006bce7c`, both `RET c`; saves/restores ESI. ECX becomes candidate before the call, AL/DL are scratch. Further preservation/clobber effects depend on unresolved `006f4600`. |

All three have no explicit memory stores. Saved-register pushes, calls and returns do affect the stack. `006f09b0` reads slot bytes `+102/+103` and one float32 grid element; `006cb960` reads only stack arguments. `006bce20` reads the candidate/match fields listed below, and its callee may read/write more state or consume RNG. There are no direct RNG calls in these owned bodies. No claim of purity is made for the candidate filter.

## `006f09b0`: exact grid index

Define `s8(v)` as signed interpretation of the low byte and `a(u,v)=s8(abs(s8(u)-s8(v)))`. The x86 absolute value is calculated in signed32 first, then narrowed to a byte and sign extended. With current coordinates `cx=byte(slot+102)` and `cy=byte(slot+103)`, the loaded address is:

`00a15e44 + 4 * (9*a(cy,y) + a(cx,x))`

The y loads are at `006f09b0/006f09b7`, the first narrowing at `006f09c4`, x loads at `006f09ca/006f09d1`, second narrowing at `006f09dd`, and float32 FLD at `006f09e2`. The first x stack access appears as `[ESP+8]` in the listing because ESI has already been pushed; it is `[S+4]`. No distance arithmetic or rounding occurs after the lookup load.

The narrowing matters: an absolute delta of 128 becomes -128, and 255 becomes -1. This is not unrestricted `abs(dx)+9*abs(dy)`. There is no index, coordinate, null-pointer or x87-stack guard. Admission must ensure readable slot/grid addresses and a successful FLD. The formula does not establish Euclidean distance or the whole grid's contents.

In `007103e0`, the nonzero-side route pushes y=0 then x=4 at `0071055a/0071055c`, sets ECX=current slot, calls at `00710560`, and stores the ST0 result to float32 at `00710565`. The side-zero route instead inlines the same indexing with target `(4,11)` at `00710528..00710551` (FLD is `00710551`; range ends before `00710558`). Both reach the existing `R(12)` and ordered comparison described in [R11](shot-helper-11.md). This lookup contributes no additional direct draw.

## `006cb960`: signed rectangle predicate

The result is AL=1 exactly when signed x is in 2..6 inclusive and signed y is in 10..11 for side byte exactly 1, or 0..1 for every other side byte. Otherwise AL=0. `006cb964` compares side to 1; `006cb96a` selects the other-side path. The x/y bounds use signed `JL/JG`, including `TEST AL,AL; JL` at `006cb991/006cb993`. In particular side=2 or ff does not reject automatically; it selects y=0..1. Negative x/y bytes fail the appropriate lower bound.

Success uses `MOV AL,1` at `006cb980` or `006cb999`; failure uses `XOR AL,AL` at `006cb99e`. None normalizes EAX as a dword. The decompiler's one-byte result is consistent here, but a boolean source type or full-width return is not established.

The two `007103e0` calls, `007104b9` and `007109bb`, supply low-byte arguments `(slot_side==0 ? 1 : 0, match+8ea7, match+8ea8)`. The side is set by `SETE AL`; coordinates are loaded into CL/DL before their full registers are pushed, so upper argument bits are incidental. Although ECX is set to match, this callee never reads it. Both callers test AL only. At the first site AL=0 proceeds toward `R(20)`; AL=1 proceeds there only when match byte `+8ea9==ff`. At the second site AL=0 or `+8ea9==ff` selects `00714d40`, otherwise `00713fc0(1)`, subject to the earlier R11 gates. This helper itself is independent of match state and x87/RNG state.

## `006bce20`: ordered candidate filter

The following tests short-circuit in instruction order:

1. A null candidate returns EAX=0 (`006bce27/006bce29`).
2. If candidate bytes `+102/+103` both equal the supplied x/y low bytes, return 0 (`006bce2b..006bce45`). A difference in either coordinate continues. Coordinate equality is byte equality; it has no signed comparison.
3. If signed byte `candidate+2b >= 2`, return 0 (`006bce47/006bce4b`). Negative byte values pass this test.
4. If candidate equals either dword pointer `match+f582` or `match+f57a`, return 0 (`006bce4d..006bce5b`). These pointer loads precede the call and are not repeated afterward.
5. Call `006f4600` at `006bce5d` with ECX=candidate and no newly pushed explicit stack arguments. If its AL is zero, return 0 (`006bce62/006bce64`). Its full body, transitive state effects and register contract remain unassigned.
6. Read byte `match+8eb2` **after** that call (`006bce66`); nonzero returns 0. Zero returns EAX=1 (`006bce70`). The false epilogue clears the full EAX (`006bce79`).

The match context is not read for null candidates, same-coordinate candidates, or candidates rejected by `+2b`. Reaching pointer tests requires readable match memory; nonnull candidates need readable fields through the tests actually reached. No null or lifetime guard protects those reads. The post-call byte cannot be replaced with a pre-call snapshot without establishing callee effects/aliasing. No score or slot writes occur directly here.

All five R11 candidate loops pass ECX=`*(slot+19e)`, candidate=`*(slot+1ae+4*signed8(index))`, x=`slot+102`, y=`slot+103`. Calls are at `007105fd/00710705/00710799/00710858/00710912`. Their register arrangements differ but establish the same pointer/low-byte contract; the extractor checks all five setups. Each caller tests AL and skips its direct `R(900)`/candidate dispatch when zero. A nonzero result is only eligibility for the following RNG gate, not a proven event outcome or a fixed total draw count: `006f4600` remains transitive.

## Reproduction and limits

Run `python scripts/extract_match_helpers_12.py PRIVATE_EXE --exports PRIVATE_EXPORTS_12 --output evidence/match-helpers-12-sites.json` with Capstone 5.0.7. The script rejects a different specimen/decoder, verifies contiguous PE-backed decoding, export agreement, all incoming direct-call targets, selected operand widths/signed branches, all normal return cleanup sites, absence of explicit memory stores, and the eight owned caller relationships. It reads pseudocode only to corroborate the checkpoint's old generic function names; behavioral statements come from instructions.

Deterministic regeneration, wrong-hash rejection, JSON parsing, staged privacy inspection, `git diff --check` and `npm run check` under Node 24.19.0 passed. The retained numerical suite checks earlier primitives; it is not a new oracle for these helpers. The [annotation proposal](../evidence/match-helpers-12-annotations.json) is for coordinator review and native preflight only. Remaining work includes admitted grid bounds/data, `006f4600` effects, the tactical helper and large R11 callees, x87 state and live caller reachability. No runtime producer, connected shot outcome, complete score formula or full-match equivalence is established.

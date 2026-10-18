# Investigation 14: match slot coordinate/action dispatch

`00713fc0` selects coordinate/action calls through early match-state gates, two alternative candidate regions, tactical destination adjustments, a partner branch and fallback candidate tests. Its direct writes are word `slot+198`, wrapping word `slot+35`, and one diagnostic global. The callees can change considerably more state. This closes the local body of one R11 dispatch dependency; it does not close a shot outcome.

This is a static original-instruction contract, with no behavior port or execution oracle. Specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; baseline is `3d81fa3c056c7d28c3c2a6d99e93d96464f43834`. All addresses are virtual unless explicitly called file offsets. The read-only checkpoint-13 export manifest SHA-256 is `233ec2078dc3eacf0d1b83a3d093028caf57c634329bacce4af4ea2efb5c7f86`. Names/field meanings remain research labels. Canonical native state and shared registries were not changed.

The [sites](../evidence/match-dispatch-14-sites.json) identify all 3,226 bytes at `00713fc0..00714c5a` exclusive, raw file offset `313fc0`, 997 instructions, 66 direct calls, 161 branches, 11 direct RNG sites, 24 direct non-frame stores and 16 returns. Capstone 5.0.7 agrees with every exported instruction address and direct-call target. It also verifies both supplied incoming call sites in the original PE. Bulk assembly/decompilation and original bytes stay private.

## ABI and notation

ECX is the slot pointer `p`; `m=dword(p+19e)`. The prologue reserves `224h` bytes and saves EBX/ESI/EDI. Every exit restores them and uses `RET 4`; EBP is untouched directly. The single four-byte entry stack slot is **unused locally**. R11 pushes 1 at `007109cd` and calls at `007109d1`; the other supplied caller also pushes 1 at `006ba4df`. The extractor propagates inferred callee cleanup through every CFG edge, verifies consistent joins and entry ESP at every return, and verifies all explicit ESP-based accesses are below entry ESP. Do not copy the decompiler's one-register `fastcall` prototype and lose this cleanup requirement.

No consistent return value is established; R11 ignores it and exits. EAX/ECX/EDX/flags and x87 state are scratch subject to the actual callees. General-register preservation across unassigned callees assumes their normal ABI. No null, valid-side, coordinate, profile-pointer or alias precondition is established by the whole body.

Below, offsets/masks are hexadecimal; numeric bounds, coordinates and arithmetic constants are decimal unless suffixed `h`. `s8`/`s16` mean signed extension; `R(n)` is `0090cfc0`, with ordinary signed integer comparisons as specified. A call to `R(0)` need not advance the exposed RNG state. Local coordinate slots `X/Y` are dwords whose low bytes are repeatedly changed; their upper bytes can retain prior contents. Do not normalize the pushed dwords to clean integers without admitting the callee's actual consumption.

The entry byte lookup uses the already mapped R13 leaf `005b57c0`, with base `m+91e2h+18e3h*s8(p+27)` and low-byte index `p+19`. It snapshots bit2 of the returned byte at `00713ffb` for the later partner gate. The separate immediate dependency `005b5270..005b5286` sign extends the stack index byte, loads EAX from `base+188bh+8*index`, EDX from the following dword, and returns with `RET4`. It has no stores/RNG. Thus its three call sites test **EAX mask200000h (bit21)**, **EDX mask4h (bit2)**, and **EAX mask800000h (bit23)**, respectively; the middle test at `007143fa` is not EAX bit2.

## Early exits and candidate regions

1. Write word `p+198=ffffh` (`0071400a`). If `m+8ea9==ffh` and `m+8eae!=ffh`, call `006c2a40(m; p,&x,&y)`, write action word `68h`, then call R13's `006f46b0(p; x,y)` and return. R13 supplies the normal membership/coordinate mutation contract and its unresolved diagnostics; the producer remains unassigned. If both sentinel bytes differ from `ffh`, skip the following early gates.
2. When either sentinel byte is `ffh`, if `dword(m+f57a)==p`, snapshot signed byte `p+107`, draw `R(20)` at `00714075`, and test whether the wrapping 32-bit sum is **nonzero**. It is not a positive comparison. Nonzero calls `006f09f0(p; m+8ea7,m+8ea8,100h,0,0)`, then writes `p+198=100h` **after** the call, and returns. Otherwise, a null `m+f57a`, AL!=0 from `006cfda0(m;p)`, and freshly read byte `m+1c5==0` select the same exit without another direct draw.
3. At `00714100`, the special region is `(side==1 && s8(y)<3) || (side==0 && s8(y)>8)`, where side/x/y are slot `+27/+102/+103`. In that region x in signed `[2,6]` enters the first threshold block directly. Outside that x range, load the float32 grid at index `9*s8(low8(abs(s8(y)-s8(m+8ea8)))) + s8(low8(abs(s8(x)-s8(m+8ea7))))`. Only an **ordered grid value >2.0** enters that first threshold block (`00714176..00714181`). Less, equal or unordered selects the other region; signed low-byte narrowing of the absolute differences must be retained.
4. The other region (`0071424e`) first calls the two-dword flag getter. If EAX mask200000h (bit21) is set, draw `a=R(s8(byte(dword(p+6d)+1a)))` at `0071428b`, then `b=R(5)` at `00714294`. Signed `a>=b` permits `006bce80(m;p,&x,&y,12)`. AL!=0 writes action `6ah`, calls `006f09f0(p;x,y,-1,0,0)` and returns, with **no direct +7 word increment** on this route. Failure/bypass reaches the second threshold block.
5. Each alternative threshold block (`00714187` or `007142e8`) snapshots byte `p+107` before the tactical-word lookup `006c38c0(m;p)`; a null m supplies zero in these guarded lookups. It then computes x87 `(2.5 - s16(p+35)*0.0002) * (s8(p+101)*snapshot_s8(p+107))`, stores it as float32, and draws `R(20)` if tactical mask40h is set, otherwise `R(50)` (`007141de` or `0071433f`). The comparison is draw versus the stored threshold. `TEST AH,1` at `007141f4/00714355` passes **less or unordered**, not equal. AL!=0 from a subsequent `006bce80(...,4)` then adds 7 modulo 65536 to `p+35`, writes action `6ah`, dispatches those outputs and returns. Failed/bypassed candidate routes converge at `007143a7`. The direct expressions use bounded integer inputs and finite pinned constants; unordered here describes the instruction branch, not a demonstrated runtime case.

## Destination preparation and tactical overrides

`006c2be0(m;p,&X,&Y,1)` supplies destination dwords at `007143ba`. `00715f50(p;X)` returns AL, which replaces only X's low byte at `007143cb`. The second flag-getter call gates further coordinate overrides on **EDX&4**. If clear, go directly to `00714643`.

For a stable side and stable read-only tactical results, the four duplicated override regions reduce to the table below. The site inventory retains all comparisons and repeated helper calls; the reduction assumes those reads stay stable. In each region `mx/my` are signed match coordinate bytes. For side0 the reference strip is `my in [10,11]`; for nonzero side it is `[0,1]`.

| Entry route | First eligible tactical combination | Destination rewrite |
| --- | --- | --- |
| side0 | mask80h and any mask78h | X=0,Y=11 only if `mx<6 && (mx<2 || my outside strip)` |
| side0, first combination failed | mask800h and any mask78h | X=8,Y=11 only if `mx<2` |
| nonzero side | mask80h and any mask78h | X=8,Y=0 only if `mx<2` |
| nonzero side, first combination failed | mask800h and any mask78h | X=0,Y=0 only if `mx<6 && (mx<2 || my outside strip)` |

The first eligible combination exits this region even when it does not rewrite. The X=8 blocks contain redundant later comparisons: after taking the `mx>=2` path, they test `mx<2` again; that path does not write. Arbitrary side values are not normalized to 0/1 throughout the function, and every comparison remains signed.

At `00714643`, unguarded tactical calls construct a byte bound B: mask200h clear ->16; otherwise mask8h set ->18; otherwise mask4h set ->20; otherwise ->0. These are repeated calls, not one cached word.

Next test dword `m+9766h+18e3h*s8(side)` mask1000h. Set with byte `m+6+s8(side)` nonzero selects `R(B)`; set with zero skips that draw. If mask1000h is clear, the third flag-getter call selects `R(B)` only when **EAX mask800000h (bit23)** is set. Snapshot `s8(p+107)` before that draw; snapshot>draw jumps to centralization.

On bypass/failure, the regional gate at `007146e2` requires `(side0 && y<mY && y>7) || (side1 && y>mY && y<4)`, plus `p+109!=0`. Call `006cb700(m;y,side,1)`, sign extend AL to `q`, then draw `R(3)` at `00714736`. `q<draw+1` selects centralization. Centralization (`00714743`) sets low Y=11 for side0, otherwise0, and low X=`trunc_toward_zero((s8(X)+4)/2)`. The CDQ/SUB/SAR sequence is significant for negative X.

Then, if `p+107!=0`, call `006c4180(m;side,Y)`; negative signed AL leaves Y unchanged, otherwise side0 subtracts AL and any nonzero side adds it modulo256 (`0071477d..007147ba`). A final tactical lookup at `007147c5` saves the word used by later fallback gates.

## Partner, diagnostics and fallback

Read `partner=dword(p+1aa)`. Null goes to fallback. Partner byte `+19` equal to `fbh` or `ffh` selects diagnostics: `00944cff`, `0090d130`, `00944c9f`, `005e8290`, then dword `00b67a34=0`, then fallback if those callees return (`007148c5..00714928`). The line token is `5226h`; source anchor is `match_pl.cpp`. This error route continues locally; it is not a proven terminating assertion.

A different partner byte writes word `p+198=105h`, copies partner coordinate low bytes, and tests `p+10a`. Zero continues to fallback, so this action word is not necessarily final. Nonzero calls `006cb930(m;side==0,partnerY)`. A nonzero AL or the saved entry byte-lookup bit2 skips the following draw. Otherwise snapshot the partner pointer in EDI and draw `R(21)` at `00714849`, compare its integer result with float32 `partner+ad`. `TEST AH,41` skips nudge on **less, equal or unordered**; only ordered greater nudges. Nudge decrements Y for side0 when Y>0, increments for side1 when Y<11, increments signed X<=2, decrements signed X>=6, and leaves X=3..5 unchanged. The redundant x<8 / x>0 tests remain in the evidence. Call `006f09f0(p;partnerX,partnerY,-1,0,0)` and return. No direct coordinate state store occurs here.

Fallback calls `006c4130(m;p)` at `0071492f`. Negative AL skips two draws. Otherwise snapshot byte `p+107`, draw `a=R(5*s8(AL))`, then `b=R(3)`; signed `a+snapshot>b` writes action `6bh`, calls `006f5b80(p;0)` and returns. A zero first bound is possible at this boundary; it must remain a call in the ordering account.

If current coordinate low bytes equal X/Y, use these ordered exits:

1. Saved tactical word==1 and `p+10a!=0`: action `76h`, dispatch current coordinates.
2. Otherwise `p+10a!=0`, or AL!=0 from `006cd5f0(m;p)`: action `76h`, current coordinates.
3. Otherwise `p+107!=0` permits `006bce80(...,4)`; AL!=0 increments word+35 by7, action `6ah`, helper coordinates.
4. Otherwise `p+101!=0`, saved tactical mask6h clear, and `p+107!=0` permit a **second** `006bce80(...,4)` call. AL!=0 increments word+35 by7, action `69h`, helper coordinates. The first call's failure must not be replaced with a cached result.
5. Otherwise action `76h`, current coordinates. All these dispatch through `006f09f0(...,-1,0,0)` and return.

For differing coordinate bytes, load float32 `p+e1`, add float32 constant10.0 using x87, call `00945640`, then use its EAX as `R`'s bound at `00714b30`. Snapshot `s8(p+109)` is compared with that result. Signed snapshot<=draw dispatches action `68h`, X/Y directly. Otherwise try the same two ordered mode4 candidate gates above (actions `6ah`, then `69h`, each with word+35 increment7). Both fail ->action `68h`, X/Y. Conversion exceptional behavior, helper effects and live float domain remain dependencies; no replacement JS conversion is supplied.

## Calls, writes and ordered RNG limits

The [findings](../evidence/match-dispatch-14-findings.json) group all 22 direct targets by observed register/stack arguments and consumed return widths. `006f09f0` is called 14 times in the static body with ECX=p and five four-byte stack slots. At 13 sites the third slot is -1; the early shared site uses `100h`. In ordinary paths the caller writes the selected action word **before** dispatch, except the early `100h` route, which writes it after return. The dispatcher is an unresolved stateful boundary, not a pure notification. R13's relocation routine is called only once, with ECX=p and two output dwords.

The exhaustive direct state-store inventory is in sites: 17 word writes to `p+198`, six word additions at `p+35`, and the single diagnostic global dword write. There is no direct match-coordinate, score or exposed RNG-state write in this body. Callees may alter aliases, slot/match state, coordinates, actions, buffers and RNG. These writes are not atomic with their surrounding calls.

Direct RNG order is `R20? -> [threshold20/50 | profileBound?, R5?, threshold20/50?] -> RB? -> regionalR3? -> [partnerR21? then return | fallbackR(5*q)?, R3?, differing-coordinateR(converted)?]`. Every question mark is branch dependent. The local CFG is acyclic even though layout has backward jumps. Its structural upper bound is **nine direct RNG calls**, ignoring correlated predicates; this is not a proved reachable total and excludes all transitive helper draws. Actual RNG advances can be fewer than calls, including B=0 and q=0. There is no fixed connected draw count.

Unassigned helper bodies, normal-return assumptions, live coordinate/side/profile/partner invariants, x87 control and conversion domains, and caller reachability remain open. `007109f0` and `00714d40` remain unowned. No connected action33 outcome, complete match, gameplay/UI build or numerical equivalence is claimed. The optional name proposal describes the dispatch boundary only.

## Reproduction and checks

Run `python scripts/extract_match_dispatch_14.py PRIVATE_EXE --exports PRIVATE_EXPORTS_14 --preflight PRIVATE_PREFLIGHT_14 --output evidence/match-dispatch-14-sites.json` with Capstone 5.0.7. It rejects wrong specimen/manifest/preflight hashes, independently decodes the contiguous owned body, checks the native instruction/direct-call inventory and incoming call targets, selected exact operands, every direct state store/width, all branch targets, all return cleanups, local CFG acyclicity, stack joins and selected caller/flag-leaf windows. It reads four pinned numeric constants through PE section mapping. Hashes identify the source without redistributing it.

Deterministic regeneration, wrong-specimen rejection, JSON parsing, public-content review, `git diff --check`, and `npm run check` with Node24 passed. The retained numerical checks validate earlier primitives; they are not execution evidence for this function. The owned body supports `contract-supported` at the stated static scope, with transitive and runtime limits retained.

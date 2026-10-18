# Investigation 18: active-slot, heading, scalar-cost and action helpers

R18-A maps four direct dependencies of R17's `006f09f0`: installing active-slot state, deriving a perturbed heading, subtracting a scalar cost and selecting an action/commentary route. These are complete **local static contracts**. Callee effects, live inputs, connected gameplay and execution equivalence remain unproved. Previously reviewed `006f09b0` is context only and is not counted again.

The pinned PE SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; repository baseline is `267756e`, checkpoint 17. All addresses and offsets below are hexadecimal unless a number is explicitly decimal. Virtual addresses are distinguished from raw file offsets. Working names and field meanings are research labels.

| Entry | Bytes / instructions | Branches / calls / RNG sites / non-frame stores | Raw file offset |
| --- | ---: | ---: | --- |
| `006f0630` | 819 / 191 | 35 / 2 / 0 / 38 | `2f0630` |
| `006f4920` | 264 / 78 | 12 / 4 / 4 / 7 | `2f4920` |
| `006f56c0` | 282 / 70 | 13 / 0 / 0 / 5 | `2f56c0` |
| `0070d430` | 504 / 167 | 12 / 20 / 11 / 3 | `30d430` |

[Generated sites](../evidence/match-helpers-18-sites.json) retain body/export digests, every branch successor, call, explicit non-frame write, RNG argument origin, return, normal stack join and switch case. Capstone 5.0.7 decodes every full body directly from the PE, then compares every address, mnemonic and operand with the pinned Ghidra 12.1.4/JDK21 read-only export. All four bodies are contiguous; all local branch targets lie within them, and all instructions are structurally reachable. No native body correction is needed. Ten known incoming calls from R17 are independently decoded; this is not a whole-executable caller census.

Notation: `p` is entry ECX, `m=dword(p+19e)`, `side=s8(p+27)`, `x=s8(p+102)`, `y=s8(p+103)`, `R` is `0090cfc0`, and `F` is x87 conversion helper `00945640`. Integer operations narrow/wrap at their encoded widths. A later use of a field means a fresh load unless a snapshot is stated. Descriptions using m do not assert that its address remains stable under aliases or calls.

## `006f0630`: install active-slot state

Entry ECX=p; no stack arguments; plain RET at `006f0962`. EBX/ESI are saved, EBP/EDI untouched. The decompiler's fastcall label does not establish an EDX argument: no incoming EDX value is consumed. EAX/AL is residual rather than a normalized result. A null initial m returns immediately; p itself has no null guard.

1. Read `old=dword(m+f582)`. If nonnull, repeatedly load `dword(old+19e)` and clear its dword4786, set byte8eae=ff, clear dwordf582 and byte1a7, in that order. Then clear old's words29 and19c. This uses old's match pointer, which need not equal p's. Self-selection is allowed mechanically; there is no alias exclusion.
2. Repeatedly reload m and clear bytes1a4,1a7,1cd, then dword4786. Read `q=dword(m+f576)`. If q is nonnull and byte q+27 equals byte p+27, increment byte q+2, then call `006c38c0(m;p)`. Test **AX==1**, not a Boolean or full EAX. Re-read m.f576 for the subsequent word+35 addition: decimal108 if AX==1; otherwise96 when `(side==1 && y>=6)||(side==0 && y<6)`; otherwise150 when `(side==1 && y<3)||(side==0 && y>8)`; otherwise120. Coordinate comparisons are signed bytes. A callee or alias can change the pointer between the initial increment and later addition.
3. On that q route, add decimal240 to dword m+4782; take a fresh m and q snapshot, then write p to m+f5aa and that q to m+f5a6. Regardless of q route, clear dwords m+f576,f57a,477e in order, with m reloaded between them. Call `006c38c0(m;p)` again; the first query is conditional and the second is unconditional after the initial m guard.
4. If the second AX==1, require signed x in decimal2..6 and y in10..11 for side==1, or y in0..1 for **every side other than1**. If byte `m+1a5+side==0`, store word p+19a as decimal180 for any nonzero side, otherwise0; then set byte m+8ea9=ff. NEG AL/SBB/AND implements that selection. There is no guard restricting side to0/1.
5. Under the same half-field predicate used for the decimal96 addition, clear byte m+8eb1. Write byte `m+1a5+side=1`, then byte `m+1a5+(side==0)=0`. These indexed writes can overlap or address other fields for out-of-domain sides. Copy p.x/y to m bytes8ea7/8ea8, p.side to8eae, p to dwordf582, p word19a to m word8ed8, and clear byte8eaa, in that order. Each assignment reloads m.
6. If byte m+8eab differs from freshly loaded p.side, clear dword m+4782. Then snapshot p.side/m and store side to m+8eab. Unless its byte is ff, increment byte `m+8d46+side`; if signed byte `m+8d46+(side==0)>0`, subtract decimal10 modulo256. Finally clear p words29 and19c.

There are no direct RNG calls. The one or two tactical queries are still transitive state/RNG/failure boundaries. The initial m check does not validate subsequent reloads, old/q, their match pointers, side indexes or same-object aliases. No coordinates or action word198 are directly changed.

## `006f4920`: heading from supplied coordinates and perturbation

Entry ECX=p; four four-byte stack slots hold low bytes `(x0,y0,x1,y1)` at entry ESP+4/+8/+c/+10. Both returns use RET10. EBX/ESI and conditionally EDI are saved; EBP is untouched. There is no normalized result. The body writes only word p+19a, through seven possible store/add sites; it does not commit coordinates.

Compute `dx=s8(low8(x1-x0))`, `dy=s8(low8(y1-y0))`, preserving byte subtraction before sign extension. Nonzero displacement loads word `b67c30+2*(24*dx+dy)` into p+19a. The table's initialization/content and valid index domain remain unreviewed; this is not an atan2 reconstruction. Coincident coordinates instead select heading0 for `(x1,y1)==(4,11)`, decimal180 for `(4,0)`, otherwise low16(R(360)).

Next snapshot bytes p+10c and p+105 **before** the always-executed R(120). If their signed product is strictly less than full EAX, draw R(30), then another R(30), and add the low16 of first-minus-second to p+19a. Equality skips these draws. Afterward load `profile=dword(p+6d)` and add low16 of `2*(s8(profile+3b)-s8(profile+30))`. MOVSX targets DX/AX; the later dword SUB/SHL consumes residual high bits, but the stored DX depends only on this low-word expression.

Finally interpret p+19a as signed16. If negative, add decimal360 once and return. Otherwise, if greater than359, subtract360 once. This is **one correction**, not a modulo guarantee for arbitrary initial table entries, profiles or RNG behavior. The direct draw order is optional R(360), mandatory R(120), then either zero or two R(30) draws. Acyclic CFG maximum is4 direct draws; callees' internal effects are excluded. Pointer validity, table indexing and aliases with p/profile are unchecked.

## `006f56c0`: subtract cost from float32 p+4d

Entry ECX=p; float32 amount at ESP+4 and low signed16 mode at ESP+8; RET8 at `006f57a2/006f57d7`. No nonvolatile integer register is changed, no calls/RNG occur, and EAX is not a defined result. All five direct write sites target the four-byte p+4d scalar; no upper clamp is present.

For mode==-1, freshly compare float32 p+4d against float32 thresholds decimal9500,8750,7750 in descending order. Select multiplier12 if ordered greater than9500,10 if ordered greater than8750,8 if ordered greater than7750, otherwise6. Each AH mask41 test sends **less/equal/unordered** to the next test. Compute `p+4d - amount*multiplier*C`, where C is the exact float32 constant at96d780, decimal0.09090909361839294. Products remain x87 values under the current control word; C is not replaced with exact division by11. Store with FSTP float32, reload the rounded float32, and compare it against0.

For other modes, signed-extend mode and subtract13h; an unsigned range guard admits13h..2eh. The byte selector at6f57e8 and three-target table at6f57dc select these double-precision coefficients:

| Mode | Coefficient address / approximate decimal value |
| --- | --- |
| `13`,`21` | `96d770` / 0.3818181818181818 |
| `15`,`24`,`2e` | `96d778` / 0.5454545454545454 |
| Every other signed16 mode except `-1` | `96d768` / 0.16363636363636364 |

Compute `Q=200.0-float32(p+d5)*8.5` using float64 constants at96a648/96a790, then subtract `Q*coefficient` from float32 p+4d. The amount argument is unused on these paths. FST float32 writes the result **without popping it**; FCOMP compares the retained x87 value against0, rather than reloading its rounded store. That differs from the sentinel path. All paths use AH mask1 after the comparison: less **or unordered** causes an explicit dword zero write, while ordered greater/equal retains the prior store. Thus NaNs are not described correctly by a simple ordinary-language `max(0,value)` port. Float precision, rounding modes, traps, overflow/underflow and actual input ranges are unmeasured. The extractor records widths, values and digests of all14 constants without exporting original tables.

## `0070d430`: threshold gate and conditional action calls

Entry ECX=p; signed16 threshold at entry ESP+4; RET4 at four exits. It saves ESI, transiently EDI for the first two draws, and conditionally EBX. EBP is untouched. All normal returns explicitly assign full EAX:1 for the fallback event route,0 for either intercepted action route. Three direct non-frame stores change byte p+2b (two alternatives) and word p+35 (one route). Callees can do more.

If threshold>decimal1000, immediately take the fallback route. Otherwise sign-extend byte `dword(p+6d)+21`, overwrite the argument's **full dword stack slot** with it, FILD that dword, add float32 p+a5, call F, and draw R(F-result), then R(20). No float32 store separates the addition and conversion. If first>=second under a signed dword comparison, fallback; otherwise snapshot byte p+106 and draw R(8), then compare the signed snapshot to EAX.

The fallback emits commentary token1fe2 through `006d6f70` with receiver `dword(m+8f7a)` and arguments `(token,m,low8(p+2e),low8(p+27),-1,-1,0)`, then returns1. The pushed p+2e/p+27 registers have partially assigned byte values; their upper bits are not normalized. Full-dword semantics for those arguments are not asserted here.

If snapshot>R(8), emit token1fe3, draw R(2), reload p+2b and add AL modulo256, then draw R(10). Nonzero R(10) selects `(flag,last)=(1,0)`. Zero draws R(200), selecting `(0,p)` when zero, `(0,0)` otherwise. Call `006cd770(m; low8(p.x),low8(p.y),3,low8(p.side),flag,1,last)` and return0. Coordinates/side are read after these draws. Dword pushes have the same partial-register upper-bit limitation.

Otherwise emit token216f, draw R(3), update byte p+2b the same way, then draw R(10) and conditionally R(200), selecting the same flag/last pairs. Call `006cd770` with kind1 instead of3. Then subtract decimal250 from word p+35, read `a=s8(dword(p+69)+5a)`, and draw R(30*a+20), with the original MOVSX/LEA chain forming a→3a→15a→30a+20. If zero, draw R(3), negate **AL only**, and call `007172d0(p; pushed EAX)`. Only the low byte is known to be the negated draw; the full dword is not a sign-extended negative integer. If the returned AL is nonzero, call `006eecb0(p;0)`. Return0.

No local loop exists. The event1fe3 path has at most6 direct draws; event216f has at most8, including conditional200 and the last3. Paths skipping interception have0 or2. The11 direct sites are not eleven calls per invocation. Commentary precedes the branch-specific draws, the p+2b update precedes R(10), and kind1 action delegation precedes the p+35 decrement and profile draw. Transitive RNG/failures in commentary, action, conversion and refresh helpers remain excluded; dynamic bounds are not locally checked for positivity.

## Reproduction and scope

Run `scripts/extract_match_helpers_18.py PRIVATE_EXE --exports PRIVATE_EXPORTS_18 --preflight PRIVATE_PREFLIGHT_18 --output evidence/match-helpers-18-sites.json` with Capstone5.0.7. It rejects specimen/manifest/preflight mismatches, checks every manifest file, independently decodes all506 instructions/1869 bytes, verifies every exported instruction, all72 branches/26 calls, the mode switch, all53 direct non-frame stores,15 RNG argument origins, normal stack joins, nine return sites and ten supplied R17 callers. Acyclic CFG maxima0/4/0/8 ignore correlated conditions and exclude every transitive call.

The [validation receipt](../evidence/match-helpers-18-validation.json) records deterministic regeneration, wrong-specimen rejection and Node24 research checks. Those numerical checks exercise earlier retained primitives, not these four bodies. The [findings](../evidence/match-helpers-18-findings.json) and [name-only proposals](../evidence/match-helpers-18-annotations.json) are compact authored metadata. No native database, shared ledger, source export, original table, executable, game/UI code or execution oracle is changed or added. Canonical annotation integration belongs to the coordinator after independent review.

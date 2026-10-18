# Investigation 15: other-slot coordinate/action dispatch

`00714d40` selects early coordinate/action exits, an optional partner dispatch, a destination, and final actions/commentary through match, tactical and signed-byte gates. It can consume direct RNG, clear the partner pointer, and change action/accumulator state. This closes the local body of the remaining smaller R11 dispatch dependency. `007109f0` and the transitive effects of this function's callees remain open.

This is a **static original-instruction contract**, without a behavior port or execution oracle. Specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; baseline is `a4fa4bc7745ad3fbc67759325c45a9058ceaecc0`, checkpoint 14. Addresses are virtual unless explicitly labelled file offsets. Names and field meanings are provisional. Canonical Ghidra and shared coverage/checkpoint files were read only.

The [sites](../evidence/match-dependency-15-sites.json) identify all 4,583 bytes at `00714d40..00715f27` exclusive, raw file offset `314d40`, 1,388 instructions, 75 direct calls, 209 branches, 13 direct RNG sites, 27 non-frame stores and 20 plain returns. Capstone 5.0.7 independently decodes the PE and agrees with **every instruction address, mnemonic and operand** in the native export after syntax normalization: case/whitespace, equivalent condition mnemonics, numeric formatting, float/double memory-width spelling, scale1, and implicit `FCOMP ST(1)`. The ten supplied incoming direct calls also target this entry in the original PE; that list is not proved exhaustive. Native manifest/preflight and per-file hashes are retained; bulk listings and original bytes remain private.

## ABI, values and preconditions

Entry ECX is slot `p`; `m=dword(p+19e)`. There are no explicit stack arguments or local reads of entry stack slots. The prologue saves original EBP, sets EBP to that frame position, aligns ESP down to 8, reserves `238h` bytes, and saves EBX, frame EBP, ESI and EDI (`00714d40..00714d51`). EBP is subsequently used as ordinary scratch. Each normal epilogue pops EDI/ESI/frame EBP/EBX, restores ESP from frame EBP, pops original EBP, and uses plain `RET`. The extractor verifies stack joins and epilogues for both four-byte-aligned entry ESP residues modulo8. These checks assume the inferred normal callee cleanup and nonreturn of diagnostic call `00945934`. No consistent meaningful return value is established; R11 ignores it.

Offsets/masks are hexadecimal; other arithmetic constants are decimal unless suffixed `h`. `s8`/`s16` denote sign extension; `R(n)` is `0090cfc0`. `T` is the saved low word from the first `006c38c0` lookup. `A=(AX,AY)` is the match-coordinate byte snapshot at `00714e1e..00714e2e`; `D=(DX,DY)` is the later destination. These names denote local values, not CPU registers. Coordinate locals are dwords whose **low bytes alone** are initialized/replaced on many routes; upper bytes of pushed arguments may remain unspecified. No clean integer normalization is justified at those call boundaries.

The function dereferences m before any null guard. The guarded tactical calls later do not make null m a valid entry input. Slot/profile/partner pointers, side values, coordinate/grid domains, aliasing and normal callee return are caller preconditions. Repeated helper calls and later memory reads are distinct observations; do not cache them without proving purity and stability. Grid index construction throughout is `9*s8(low8(abs(s8(y1)-s8(y2)))) + s8(low8(abs(s8(x1)-s8(x2))))`; it is not an unbounded Euclidean calculation.

## Early gates and mirrored exits

1. If `m+8eae==ffh`, test `m+f57a==p`. If equal, snapshot s8 `p+107`, draw `R(20)` at `00714d7b`, and test the wrapping 32-bit sum with that snapshot for **nonzero**. Nonzero dispatches current match coordinates with third argument `100h`; write word `p+198=100h` **after** `006f09f0` returns. A zero sum continues. Independently, null `m+f57a`, nonzero AL from `006cfda0(m;p)`, and freshly read `m+1c5==0` choose that same exit. These exits precede the `ffffh` action reset.
2. At `00714dda`, the mapped byte getter `005b57c0` uses base `m+91e2+18e3*s8(p+27)` and low index byte `p+19`. Save its bit2. Write word `p+198=ffffh`; snapshot A; call `006c38c0(m;p)` and save T. If `m+8ea9==ffh && m+8eae!=ffh`, obtain output dwords through `006c2a40(m;p,&x,&y)`, write action `68h`, call mapped R13 relocation `006f46b0(p;x,y)` and return (`00714e43..00714e86`).
3. Otherwise snapshot s8 bytes `p+10a`, `p+105`, `p+106` before **one** side-selected `R(25)` (`00714eb3` side0; `00715043` any nonzero side). Require their signed product>draw, nonnull `m+f582`, and T!=1. For side0 also require current signed y<AY and y<6; for nonzero side require y>AY and y>5. Failure converges at `007151b4`.

For the remaining mirrored tests, side0 uses `L=s8(m+8eb0)`, `Q=m+f59a`, default qY=9 if Q is null, and destination Y=L+2. Nonzero side uses `L=s8(m+8eaf)`, `Q=m+f596`, default qY=-1, and destination Y=L-2. Side0 requires qY<=L; nonzero side requires qY>=L. First, team dword `m+9766+18e3*s8(side)` mask400h and signed delta in (-2,2) dispatch action `7ah` to current x and the selected low-byte Y. Delta is y-L for side0, L-y for nonzero side (`00714f44..00714f85`, `007150d4..00715115`).

If that dispatch fails, snapshot signed `p+106` and `p+10b`, draw `R(100)` at `00714fa4` or `00715134`, and require their product>draw. Require delta==1 and freshly read qY+1<=L for side0, qY-1>=L for nonzero side, with the same null defaults. Success dispatches the same `7ah` exit. Each of four `7ah` writes precedes `006f09f0(p;x,Y,-1,0,0)`; otherwise continue. Coordinates and boundary pointers are re-read after RNG where the instructions do so.

## Opposing/sentinel gate and partner

At `007151b4` initialize two temporary current-coordinate low bytes and set scratch EBP=`100h`. T==1 skips to partner testing. Otherwise require either sentinel `m+8eae==ffh`, or nonnull owner `m+f582` of different raw side and nonnegative signed AL from `006c4180(m;side==0,ownerY)`. Also require null `m+f57a` or its side different from p. AL!=0 from `006cfda0(m;p)` chooses the shared match-coordinate `100h` exit.

AL==0 enters repeated null-guarded tactical lookups (`00715279..0071531a`). First require any mask200h/100h/400h, then any mask8h/10h/20h, in that order of separate calls. Snapshot signed `p+10d` and store grid distance float32. Convert float32 `p+dd` through `00945640`, draw `a=R(converted)` at `00715378`; convert x87 `storedDistance*8.0f`, draw `b=R(converted)` at `00715394`. Signed `a+snapshot>b` dispatches current match coordinates, third argument100h, then writes word+198=100h after return (`007153bb..007153ce`). Failure continues to partner.

At `007153cf`, null partner `dword(p+1aa)` skips partner dispatch. Otherwise partner consideration is permitted if team mask400h is clear, owner is null, or one of these signed coordinate conditions holds:

| Side gate | Additional condition |
| --- | --- |
| side==0 and current y<6 | y>AY-1 **or** partnerY>=s8(m+8eaf) |
| side==1 and current y>5 | y<AY+1 **or** partnerY<=s8(m+8eb0) |

When team mask400h is set and owner nonnull, other side/region combinations skip partner. An eligible partner index s8 `partner+19` equal -5, -3, -2 or -1 clears **dword `p+1aa=0`** at `00715583` and continues; -4 is accepted by the actual comparisons. This differs from R14's diagnostic partner handling.

For a valid eligible partner, nonzero `p+105` and `m+f57a==partner` write action105h and dispatch the original snapshot A with third argument -1. Otherwise write action105h and replace A's low bytes with partner coordinates. Call `006cb930(m;side==0,partnerY)`. Only zero AL plus clear saved entry getter bit2 draws `R(21)` at `00715502`; only **ordered draw>float32(partner+ad)** nudges the local coordinates. Side0 decrements positive signed Y; side1 increments signed Y<11; other side values leave Y unchanged. Signed X<=2 increments; X>=6 decrements; X3..5 remains. Redundant x<8 and x>0 comparisons are present. Dispatch A with third argument -1 and return. This is a local-coordinate adjustment, with no direct slot coordinate store.

## Destination selection and direct RNG order

Unaccepted/null/cleared partner paths reach `0071558d`. Sentinel `m+8eae==ffh` or saved T bit0 set chooses `006c2be0(m;p,&DX,&DY,1)`, then `00715f50(p;DX)` replaces only DX's low byte. A local selected-match-coordinate flag F remains zero.

Otherwise convert x87 `float32(p+e1)+0.5` through `00945640`, draw `R(converted)` at `007155bd`. Result0 selects threshold0.0 and skips the next two draws. Nonzero result starts a float64 local threshold1.5, snapshots signed `p+10d`, and draws `R(10)` at `007155ec`. Snapshot>draw replaces threshold with the encoded double1.995. For zero `p+106`, then zero `p+10a`, multiply by pinned double1.33 with a float64 store after each. Snapshot float32 `p+1a2`, draw `R(150)` at `0071564a`, and compare integer draw+30 with the snapshot. **Less or unordered** multiplies the loaded threshold by1.33 once more, without another local float64 store.

Compare float32 grid distance from current position to A with this x87 threshold at `007156ac`. **Ordered distance>=threshold** chooses the candidate producer/adjuster above. **Less or unordered** proceeds to flag tests:

- `005b5270` EAX bit15 set, or a separate call's EAX bit13 set with team mask100h, or team mask4000h, selects D=A and F=1.
- Otherwise repeated guarded tactical lookups with mask2h or4h set choose the producer/adjuster.
- Otherwise draw `a=R(s8(m+8d46+(side==0)))` at `007157c2`, then `b=R(25)` at `007157cb`. Signed a>b and AL==0 from `006cd5f0(m;p)` select D=A,F=1. Failure chooses producer/adjuster. The two-dword getter's tested bits are in **EAX**, not EDX; its read-only leaf contract was established in R14.

The direct draw ordering is `entryR20? -> sideR25 -> sideR100? -> tacticalPair? -> [partnerR21? and return | destinationConverted?, R10?, R150?, teamBound?, R25?]`, with earlier exits shortening it; sideR25 is itself bypassed by the entry/relocation exits. The full local CFG is acyclic, including backwards layout jumps. Its structural upper bound is **ten direct RNG calls**, ignoring correlated predicates and excluding transitive draws. This is not a demonstrated reachable count. Bounds can be zero, and `R(0)` need not advance exposed RNG state. Float-to-integer exceptional inputs and x87 control remain unresolved; the conversion helper is not replaced by a language cast.

## Final exits when saved T==1

Destination selection above still happens before this test (`00715873`). Compare snapshot A with current slot coordinate bytes.

If equal, return with existing action when `m+8eae!=ffh`, signed `m+8ea9>=5`, or `m+1c5!=0`. Otherwise call `006f4920(p;currentX,currentY,4, side==0 ? 11 : 0)`, enqueue commentary `1f46h` through `006d6f70` with ECX=`dword(m+8f7a)` and stack `(event,m,p+2e,p+27,-1,-1,0)`, call `006f0630(p)`, add4 modulo65536 to word `p+35`, write word `p+198=103h`, return (`00715a26..00715a7f`). State is re-read for commentary after the first call.

For differing bytes, require nonzero AL from `006cfda0(m;p)` and grid distance **<=1.5 or unordered** to enter the next gates. Failure writes action71h and dispatches D with third argument-1.

1. `006cb960(m;side,AX,AY)` AL!=0 plus `(sentinel==ffh || (p+106==0 && p+10a==0))`: write103h, dispatch A with third argument100h, return.
2. Otherwise non-ff sentinel writes71h and dispatches D/-1. For ff sentinel call `006c3950(m;side==0,AX,AY,1)`. Ordered result>2.5 enters bounds checks directly; <=2.5 or unordered with either `p+106` or `p+10a` nonzero writes71h and dispatches D/-1. With both bytes zero, continue to bounds as well.
3. Bounds require signed AX in0..8 and AY in0..11. Failure returns with the preceding action unchanged. Success writes103h, dispatches A/100h, returns (`00715b84..00715bcb`).

## Final exits when saved T!=1

With non-ff sentinel and current signed x in2..6, test the end strip: side1 y10..11, any non1 side y0..1. In that strip call `006cb960(m;side,AX,AY)`. AL!=0 selects `006ce110(m;side)`; if nonnull result has signed byte+2b>1, call `006f09f0(p;4, side==0 ? 0 : 11,-1,0,0)`, then write action78h **after** return. Null result selects diagnostics described below. Failed strip/region/byte tests converge at `007158ba`.

Call `006c4130(m;p)`; nonnegative signed AL and nonzero `p+107` call `006f5b80(p;0)`, then write6bh after return. Otherwise call `006cfda0(m;p)` again. AL==0 goes to the final destination/occupancy block. Nonzero AL uses the following gate at `00715c1c..00715ca0`:

- ff sentinel and `(side1 && current y>=6) || (side0 && current y<6)` enter the A dispatch block directly.
- Non-ff sentinel and nonzero `p+10d` enter it directly.
- On the remaining routes require nonzero `p+10d`, call `006cc4e0(m;AX,AY,DX,DY)`, and enter it only for result<2.0 **or unordered**. The instruction sequence rechecks +10d and the side/half predicates; the first two reductions assume stable reads between instructions.

The A dispatch block requires signed AX0..8 and AY0..11. Invalid bounds write action `F ? 100h : 68h` then dispatch D/100h. Valid differing A/current bytes write100h and dispatch A/100h. Valid equal bytes with non-ff sentinel, signed `m+8ea9>=5`, or nonzero `m+1c5` write104h and return. Otherwise add4 to word+35, write100h, call `006f4920(p;currentX,currentY,4,side==0 ? 11 : 0)`, select commentary, enqueue and call `006f0630(p)` before returning (`00715d19..00715dcf`).

Commentary is2113h when freshly read `m+1cd!=0` and either side0 with y>=10,x3..5 or side1 with y<=1,x3..5. Otherwise it is1f46h. The helper uses ECX=`dword(m+8f7a)` and seven stack slots as above. These are event identifiers, without a recovered natural-language/event-lifecycle claim.

The final destination/occupancy block (`00715e0c`) tests the same current x/end-strip rectangle, using side1 y10..11 and any non1 side y0..1. Compute cell offset `90*(12*s8(currentX)+s8(currentY))`. If byte `m+21b6+cell+(side==0)` is nonzero, byte `m+21b6+cell+s8(side)` equals1, and `p+10a!=0`, write104h and return. Otherwise compare D with current coordinate bytes: equal writes `F ? 100h : 76h` and returns; different writes `F ? 100h : 68h` and dispatches D/100h. The side-index expressions are distinct for arbitrary side values. There are no direct score or coordinate state writes in this body.

## Stores, dependency effects and diagnostic exit

The exhaustive 27-site inventory is retained in sites: **23 action-word writes** at `p+198`, two wrapping word+35 additions of4, one dword partner clear, and one diagnostic global dword clear. No direct exposed RNG-state store is present; the RNG helper owns its changes. Most action writes precede dispatch, but action100h at `00715268/007153c0`, action6bh at `007158e5`, and action78h at `007159c3` follow the associated call. The equal T==1 commentary path writes its accumulator/action after all three calls; the T!=1 path writes them before its calls. Callee aliases and effects can therefore matter even when the final direct word value matches.

The [findings](../evidence/match-dependency-15-findings.json) group all 30 direct targets by observed ABI and consumed return width. The fourteen `006f09f0` sites use ECX=p and five dword stack slots `(x,y,third,0,0)`: third is100h or-1 as described. R13 relocation and prior getter/rectangle contracts remain bounded dependencies. Candidate producers, tactical/region predicates, coordinate adjustment, mode/action helpers, commentary, x87 conversion and the termination chain are not assigned full bodies here. They can mutate state, consume RNG, alter coordinate/pointer relationships, or fail to return; local call counts do not bound those effects.

If `006ce110` returns null, the diagnostic route calls `00944cff`, `0090d130` with token5418h, `00944c9f`, and `005e8290`; writes dword `00b67a34=0`; calls `005cc7d0`, `005a8f60`, then `00945934(-1)` at `0071599a`. Source anchor is `match_pl.cpp`. The native export marks the final call nonreturning. The stack/CFG checks model it as terminal; if it returned, the next original instruction would dereference EAX and the pushed argument would remain, so that case is not an admitted normal path. Earlier diagnostic helpers are assumed to return for that path description; no complete error-handling contract is claimed.

## Reproduction and verification

Run `scripts/extract_match_dependency_15.py PRIVATE_EXE --exports PRIVATE_EXPORTS_15 --preflight PRIVATE_PREFLIGHT_15 --output evidence/match-dependency-15-sites.json` with Python/Capstone5.0.7. The extractor rejects wrong specimen/manifest/preflight hashes, checks all native file sizes/digests, decodes the complete range, compares every instruction, verifies incoming targets, the exhaustive direct store inventory/widths/sources, direct RNG sites, branch targets, returns, acyclicity and stack joins in both alignment cases. It reads seven pinned constants through PE section mapping. It publishes addresses, selected store operands, constants and digests only.

Deterministic regeneration, wrong-specimen rejection, JSON parsing, public-content/privacy review, `git diff --check`, and the retained research check under Node24 passed. These checks validate the static addition and earlier primitives; they do not execute this function. No connected action33 outcome, live reachability, numerical equivalence, complete match or game/UI implementation is claimed. The optional exact-old-value name proposal describes this local dispatch scope only.

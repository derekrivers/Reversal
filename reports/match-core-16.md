# Investigation 16: slot action selection and dispatch

`007109f0` consumes a match control byte, prepares candidate coordinates and local scores, and dispatches candidate, movement, mode or shot-resolution helpers. It can mutate both the input slot and another slot, emit commentary, and consume many direct RNG calls. This maps the complete local body of the remaining large R11 dependency. Its helper bodies, exception unwinding and connected shot outcome remain open.

This is a **static original-instruction contract**, without a behavior port or execution oracle. Specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; baseline is `15eb7357500cf2dfd1838487e2a28e05d4965410`, checkpoint 15. Addresses are virtual unless labelled file offsets. Names and field meanings remain provisional. Canonical native state and shared registries were read only.

The [sites](../evidence/match-core-16-sites.json) identify `007109f0..00713d5a` exclusive: 13,162 bytes, raw file offset `3109f0`, **3,824 instructions, 211 direct calls to 46 targets, 732 branch instructions, 59 direct RNG sites and 33 non-frame store sites**. Capstone 5.0.7 independently decodes the pinned PE and matches every native instruction address, mnemonic and operand after equivalent syntax normalization, including default x87 operands. Both indirect jump tables lie just outside the function body; the extractor reads and hashes them separately. Bulk listings, pseudocode, original bytes and private paths are excluded from Git.

## ABI, return and caller relationship

Entry ECX is slot `p`; `m=dword(p+19e)`. There is one four-byte stack argument `q`. The function compares **low8(q)** with 4 and later forwards the **whole dword q** to two `006f09f0` sites. Its prologue pushes three SEH values, reserves `29ch` bytes and saves EBX/EBP/ESI/EDI. At the ordinary body frame, ESP is entry ESP minus `2b8h`. EBP is scratch, not a frame pointer. The sole `RET 4` at `00713bf6` follows register restoration, restoration of the previous FS:[0] chain link, and an `ADD ESP,2a8h`.

There are two normal result paths: `00713bdc` sets **AL=1** for final choice 3 with low8(q)==4; `00713cd9` sets **AL=0** for the common cleanup path. Both first call `0068d040` on the local object at body ESP+78, then enter the same epilogue. The high 24 EAX bits are not normalized. Returning 1 does not imply an absence of earlier stores, RNG or helper effects. R11 calls with q=0 at `00710654`, ignores the result, re-reads the match pointer and clears byte `m+1a7`; this original caller window is independently checked. Its subsequent state-dependent retry remains outside this body's bound.

All instruction-level stack joins, the loop join and entry ESP at return agree under an explicit table of inferred normal callee cleanup. Explicit entry-stack reads are solely the byte/dword views of the one argument at entry ESP+4. The stack consistency check does not prove all callee prototypes. In particular, two dwords are staged before `006bba80` and remain for `00702050`; no stack cleanup is inferred for `006bba80`, and whether it also reads those staged values remains unresolved. Do not adopt the decompiler's apparent arguments without checking this arrangement.

The function dereferences the slot and match context before null guards. Its later guarded tactical lookups do not admit null m as a safe input. Keeper/profile/candidate pointers, signed coordinate and side domains, grid indices, occupancy capacity, aliasing and normal callee behavior are caller preconditions. The SEH handler at `0095d46b`, the local object's allocation/destruction and external unwind paths are boundaries, not recovered exception guarantees.

## Initial distance and match-byte switch

Offsets and masks below are hexadecimal; ordinary arithmetic constants are decimal. `s8`/`s16` mean sign extension; `R` means `0090cfc0`; `F` means the original x87 conversion helper `00945640`, not a host-language cast. Integer arithmetic retains encoded wrapping and division semantics. Coordinate dwords often have only their low bytes initialized or replaced; their upper bytes must not be silently normalized.

Snapshot float32 distance `d` to `(4,11)` for side0, or call the earlier mapped `006f09b0(p;4,0)` for every nonzero side. Direct grid indexing is `9*s8(low8(abs(s8(y)-endY))) + s8(low8(abs(s8(x)-4)))`. Construct the local object with `0068d020`, then read signed byte `m+8eb2`. The guarded switch at `00710aaf`, table `00713d5c`, has these cases:

| Byte | Local behavior and continuation |
| --- | --- |
| 2 | Clear byte, call `006c6a30` with selector36h. Null result chooses fallback x=`R(4)` when match x is zero, otherwise `8-R(4)`; y is wrapped low8(match y + (side==1 ? -1 : 1)), then signed-clamped to0..11. Write action36h before `006fa250`. |
| 3 | Clear byte, candidate selector34h. Null result chooses x=`5-R(3)`; y=0 for side1,11 for side0; other side values do not initialize that y byte here. Write34h before `006fa250`. |
| 4 | Clear byte, selector5ah. Null candidate or signed output score<2000 replaces x with `7-R(7)` and y with `R(3)+6` for side0 or `5-R(3)` otherwise; force candidate0. Write5ah before `006fa250`. |
| 5 | Clear byte; prepare action33h through `00700bd0`, sign-extend AX quality, then `R(100)`. Zero selects resolver mode5, nonzero mode1. Stage two zero dwords and call shared `00702050`; no direct action-word write on this route. |
| 6 | Clear byte. Signed x2..6 and d<3.1 **or unordered** allow `R(F(float32(p+a1)+20))`, after snapshotting s8(p+109). Only ordered `trunc_signed32(wrapping_sum(draw,snapshot)/3)>d` selects byte `m+8eb1=6`, action35h preparation and `R(100)` selecting mode6/1, then resolver. Otherwise use the same selector37h fallback as case7. The unordered qualification belongs to the d comparison, within the x gate. |
| 7 | Clear byte, selector37h. Null candidate or score<2000 forces candidate0,x=4 and low-byte y=`m+8eaf-2` for side0, `m+8eb0+2` otherwise. Write37h before `006fa250`. |
| 8 | Clear byte and enter the default calculation path. |
| Other | Enter the default path without that clear. |

All five `006fa250` switch exits join common AL0 cleanup. The case5/6 resolver paths do likewise. None of these local dispatches certifies the helper's transitive writes or RNG.

## Default calculation regions and direct field preparation

For low8(q)==4, select destination low bytes `(4, side==0 ? 11 : 0)` directly. Otherwise call `006c2be0(m;p,&X,&Y,1)` and replace only X's low byte with AL from `00715f50`. A region-dependent distance to that destination is saved separately. Then obtain region/flag results through `006cb700`, `006cb780`, `006c3950`, `006c3a00`, the keeper pointer through `006ce110`, and five output bytes through `006ce310`. The `006c3950` x87 result is stored float32 as `t` at body ESP+60.

The word `p+29` has four assignment sites before the common wrapping add70 at `00711342`:

- q low byte4 assigns350 at `00711339`.
- Match byte `8ea9==ffh` assigns200 at `007111f3`.
- Otherwise `006bcbd0(p,&scalar,&local array/object)` returns signed AL count. Count0 clamps t to3.5 only for ordered t>3.5, then writes low16 of `F(t*60+57)` at `00711150`.
- Nonzero count clamps the returned signed16 scalar below at0, forms its wrapping squared product with the signed count, and converts x87 `-0.75*product` to v. For v<-500, draw `R(trunc_signed32((v+500)/3))`, subtract500, and clamp below at-2000; the other route clamps above at32000. Write low16 of `F(v*0.75)` at `007111e9`.

The add70 occurs after further helper calls on ordinary routes, so combining it with the assignments assumes those calls cannot alias this field. The mode4 direct assignment and immediate add give420 locally; this still does not make the routine a pure query.

Four signed32 scratch values at body ESP+10/+14/+30/+44 feed the eventual action choice. They are research labels `S10/S14/S30/S44`, without recovered natural-language meanings. The complete CFG and RNG bounds are retained; these arithmetic regions are not presented as a validated replacement formula:

| Region | Data and branch effects |
| --- | --- |
| `00711349..00711a87` | Opposite-side team mask400h and `R(5)` can alter initial S14/S44. Distance/match-state branches prepare S10, optionally call `00700bd0`, draw converted bounds and save a blended quality. Team state5 adjusts S10/S30 using the two output bytes; tactical and profile gate `R(...)<1` decrements byte `p+100`. Distance/occupancy routes alter S14. Three further draws20/profile/10 can reach `0070ec80(p;1)`, followed by action10h and cleanup. |
| `00711a87..00712292` | Distance, repeated tactical words, keeper position/flags and converted RNG adjust S10/S14/S44. A region/predicate/score route calls `006fa490(...,1)` and exits. Another uses `R(F(3000-t*1000))` then `R(S30+2000)`; signed first>second with match state!=ffh and q!=4 calls `006fa490(...,0)` and exits. Additional `006f9f90`/`006bd5b0`/region results affect scratch scores. |
| `00712292..0071294b` | `006bce80` receives p, two byte-output addresses and mode2/3 from the earlier byte flag. Its signed AL and output coordinates affect S14/S44/S10; mode4 can clamp a candidate x. Repeated tactical masks38h/880h/40h, conversions and branch-dependent draws adjust S10. `R(F(p+e1))`, optional `R(4)` and later converted draws choose alternate score adjustments. |
| `0071294b..007130a9` | For q!=4, getter EAX bits25/27/29 and **EDX bit2** select tactical/region changes and draws. `00713e90` receives selector16h and a two-byte output buffer; its AL can permit `R(300*s8(p+2d))`. Distance, region, signed-byte fourth powers and x87 helper results adjust scores before either the occupancy loop or its bypass. |
| `007130a9..00713333` | Build an integer baseline from signed `p+19c`, `p+29`, float32 `p+4d` and an x87 helper result. Candidate action/output and getter **EDX bit2**, then tactical masks880h, alter the baseline or S14. Optional `R(S10)` and `R(current baseline)` precede signed clamping in a side-selected half. Subtract the baseline from S14. `006cb910`, the candidate/action output and a fallback `R(10)` choose the tournament or a mode-helper exit. |

Repeated lookups and field reads remain separate observations. Their apparent reduction to one cached tactical word, side, profile pointer or coordinate snapshot requires purity/stability evidence. The six two-dword getter calls test EAX flags at some sites and EDX bit2 at others (`00712b40`, `00713160`, `00713326`); combining the two return registers would change the contract.

## Candidate loop and RNG bounds

The sole cyclic SCC consists of blocks `0071304a`, `0071305f`, `00713092`. The scan is entered only after the draw at `00712fee`, bound `F(30*s8(p+106))`, exceeds the following `R(200)`, and earlier distance/region branches permit it. Define cell base `c=m+215e+90*(12*s8(p+102)+s8(p+103))` and opposite index `o=(side==0)`.

Initialize BL=0; enter only for signed byte `c+58+o>0`. Read pointer `dword(c+4*(11*o+s8(BL)))`. Its byte+24 nonzero draws at `00713088` with bound `F(100*s8(p+17)+float32(p+95)*125)`, adding EAX to the scratch S14 accumulator. Increment BL once and compare it **signed** with the freshly read count byte, recalculating o from the current side. There is no local array-capacity check or per-candidate null guard. Re-reading the side/count is observable behavior.

The raw graph permits arbitrarily many trips around an RNG-bearing cycle. Its induction restricts admitted normal execution: BL starts0, increments once per iteration, and cannot remain less than any signed byte after reaching127. Thus it executes at most127 iterations, with at most127 direct calls at that site, assuming normal register preservation across the called conversion/RNG helpers. This bound does not require a fixed count byte. A typical team-sized capacity or maximum11 has not been established here.

Collapsing this SCC with weight127 and taking the longest remaining CFG route gives **167 direct RNG calls**. It is a conservative structural bound ignoring correlated predicates, not a demonstrated feasible total. There are59 instruction sites, not59 calls per invocation. The direct order is the branch-specific prefix, optional candidate scan, optional baseline draws, the four tournament draws, then the selected dispatch suffix. The [sites](../evidence/match-core-16-sites.json) provide all59 bound expressions, argument-push origins, branch successors and block edges needed to reproduce that order. Earlier exits shorten it; alternative switch/side sites are mutually exclusive.

Some bounds are signed, negative, zero, narrowed from AX/AL or wrapping sums. `R(0)` can return without advancing exposed state. Every transitive callee, including conversion and object helpers until admitted separately, remains a boundary for complete effects; the167 figure excludes transitive RNG and any R11 caller retry.

## Tournament, final choices and secondary mutations

At `00713333`, draw four times in order with freshly recomputed bound `50*(20-s8(p+106))`: add to S30, S14, S44 and S10 respectively (`0071334a/3370/3396/33b8`). S14 already includes the baseline subtraction. Start choice3; strictly greater S14 can replace it with4 under match-state/endpoint guards; then strictly greater S44 can replace it with2 under further state/`006bd5b0`/action gates. S30 can select choice1 when a candidate exists. Without one, a conditional draw10 or2 can reselect2/4, or dispatch `006fa490` directly. Signed ties retain the earlier choice at each comparison.

The remaining region/mode/`006f9f90`/RNG gates can override choices before the second switch. Existing action3bh forces choice3. Low8(q)==4 also forces3 when choice1/2 or when the candidate result byte is zero. Selector values outside1..4 branch to diagnostics. The table at `00713d78` routes:

| Choice | Resulting local boundary |
| --- | --- |
| 1 | Nonnull candidate writes action6ch then calls `006fa250(action,candidate,flags,X,Y)`. Null candidate writes9 and calls `006fa490` with second slot0. Common AL0 cleanup. |
| 2 | Call `0070ec80(p;0)`, **then** write action10h. An earlier pre-tournament route shares the call with argument1. Common AL0 cleanup. |
| 3 | q low byte4 destroys the local object and returns AL1. Otherwise optional commentary1f44h and wrapping word `p+35 +=25`, quality preparation through `00700bd0`, optional signed division-by2 blending with saved quality, then `006bba80` and the shared six-slot `00702050` boundary. Common AL0 cleanup. |
| 4 | Optional coordinate override sends x to0/8 and y to the selected end; x==4 can draw `R(2)`. `006f9f90` failure with no candidate or q4 can call `006f4920`, dispatch current coordinates/action0fh through `006f09f0`, then write0fh. Otherwise usable candidate, q4 or nonzero p+109 permits clamped destination dispatch described below. With none, draw `R(10)` and optionally call `006cb9b0`; choose action9/mode fallback or choice2's action10h route. |

The destination route signed-clamps the low-byte candidate x0..8 and y0..11, computes side/x-dependent intermediate arguments for `006f4920`, then optionally enqueues commentary1f44h and adds25 to word `p+35`. Existing action11h or12h dispatches action12h. Other actions dispatch11h, first optionally changing a second slot:

Require the earlier byte flag nonzero, `p==dword(m+f5aa)`, nonnull `other=dword(m+f5a6)`, signed word `p+29>-100`, and other action neither34h nor37h (`00713aed..00713b67`). Increment byte `other+3` modulo256 at `00713b2d`; re-read the pointer and add low16 of `trunc_signed32(s16(p+29)/3)+275` to word `other+35` at `00713b53`; re-read m and add275 modulo2^32 to dword `m+4782` at `00713b5d`. These are direct accumulators with unresolved game meanings. Do not label the dword as a goal or financial amount.

The three `006f09f0` calls use `(x,y,action,local flag dword,q)` and write action0fh/11h/12h **after** return (`00713961/00713b87/00713bb5`). The five early candidate writes and final action6ch precede `006fa250`. Both word+35 additions follow commentary; the other-slot mutations precede the action11h dispatch. These orders matter if a callee aliases, throws or fails to return.

## Float branches, direct stores and limits

There are28 local x87 comparisons. The extractor records each memory operand, FNSTSW/TEST/branch site and exact branch relation of ST0 to that operand. Assuming a completed, nontrapping comparison:

| Test | Nonzero | Zero |
| --- | --- | --- |
| AH&1 | less **or unordered** | ordered greater/equal |
| AH&41h | less/equal **or unordered** | ordered greater |
| AH&40h | equal **or unordered** | ordered unequal |

For example, `00710e35` admits less or unordered to the state6 draw, while `00710e83` rejects less/equal/unordered for its strict converted threshold. `00711126` clamps only ordered t>3.5. `0071184a` permits equal or unordered to the occupancy test; this is not a plain host equality. Runtime x87 control, traps, exceptional conversion inputs and feasible NaN routes remain unmeasured. The51 direct conversion calls and four x87-helper calls must not be replaced with host arithmetic from these static findings.

The exhaustive33-site non-frame inventory consists of two FS:[0] writes, seven match-byte8eb2 clears, one match-byte8eb1=6, eleven slot action-word writes, four word+29 assignments and its add70, one byte+100 decrement, two own word+35 additions, the three second-slot/match accumulator stores, and one diagnostic global clear. There is no direct coordinate store or identified score-byte store. Stack-local output pointers and arbitrary aliases can still allow transitive writes to any of these fields.

The invalid-choice diagnostic route calls `00944cff`, `0090d130` with token50bbh, `00944c9f` and `005e8290`, clears dword `00b67a34`, calls `005cc7d0` and `005a8f60`, then calls `00945934(-1)` at `00713d55`. The native export marks it nonreturning; CFG/stack checks admit that terminal behavior. The SEH and diagnostic helper bodies are unresolved. The source anchor is `match_pl.cpp`, not proof of a complete match model.

The [findings](../evidence/match-core-16-findings.json) describe all46 direct targets, consumed return widths, direct-store categories and an optional exact-old-name proposal. Candidate producers, mode/action dispatch, keeper/region logic, scratch object lifecycle, quality/resolver transitive paths and exceptions need further body admission. This function's static mapping does not establish a connected action33 result, live match reachability, full RNG stream, numerical equivalence, complete match or game/UI implementation.

## Reproduction and checks

Run `scripts/extract_match_core_16.py PRIVATE_EXE --exports PRIVATE_EXPORTS_16 --preflight PRIVATE_PREFLIGHT_16 --output evidence/match-core-16-sites.json` using Python/Capstone5.0.7. It rejects wrong specimen/manifest/preflight hashes, verifies all export file sizes/digests, compares every body instruction, reads both switch tables, verifies every branch destination, the33-site direct non-frame store inventory, all59 RNG argument-push origins, selected induction/ABI instructions, the R11 caller window, every normal stack join and return, the sole cyclic SCC and the167 conservative bound. It reads52 numerical constants through PE mapping. Output contains compact metadata and selected operands, never original code bytes or bulk listings.

Deterministic regeneration, wrong-specimen rejection, JSON/call-inventory consistency, public-content review, `git diff --check` and the retained research check under Node24 are the verification scope. Earlier numerical checks do not execute this function. Normal callee cleanup and diagnostic nonreturn remain explicit assumptions. No native annotation was applied by this worktree.

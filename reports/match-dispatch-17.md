# Investigation 17: candidate dispatch and slot movement/contact bodies

The three R16 callees prepare or execute coordinate/action dispatch, update match and slot state, and can call further candidate/contact helpers. This report closes their **local static instruction contracts**. It supplies no behavior port, execution oracle, connected shot outcome, live match trace or game/UI implementation. Helper effects and abnormal returns remain boundaries.

Specimen SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline: `edc2a3c`, checkpoint 16. All addresses are virtual unless labelled raw file offsets. Names and field meanings remain research labels. The [sites](../evidence/match-dispatch-17-sites.json) and [findings](../evidence/match-dispatch-17-findings.json) separate original instructions, inferred normal stack cleanup and transitive uncertainty.

| Entry | Native body bytes | Admitted bytes / instructions | Calls / branches / RNG sites / non-frame stores |
| --- | ---: | ---: | --- |
| `006fa250` | 576 | 576 / 176 | 10 / 15 / 2 / 13 |
| `006fa490` | 2,222 | 2,222 / 678 | 44 / 109 / 37 / 9 |
| `006f09f0` | 14,526 | **14,547 / 4,489** | 203 / 846 / 59 / 93 |

Capstone 5.0.7 independently decodes and matches every exported native instruction's address, mnemonic and operands after syntax normalization. Function ranges map to raw file offsets `2fa250`, `2fa490`, `2f09f0`. All direct calls, branches, seven jump tables, explicit stores, RNG argument-push origins, normal stack joins and returns are checked. The extractor also independently verifies all 17 R16 incoming call instructions for these entries; this is not a whole-executable incoming-call census.

## Native body omission in `006f09f0`

The supplied native body has ranges `006f09f0..006f1639` and `006f164e..006f42c3` exclusive, totalling14,526 bytes. After subtracting2 from the signed result and guarding the adjusted index unsigned<=3, the switch at `006f1632` reads four targets from `006f4354`: input2→`006f1647`/token1ff9h, 3→`006f1640`/1ff7h, 4→`006f164e`/1ff8h, 5→`006f1639`/1ff6h. The destinations for inputs2,3,5 are absent from that native body and its export. The pinned PE contains six instructions in the omitted21 bytes; three assignments select event tokens `1ff6h/1ff7h/1ff9h` and each jumps to `006f1670`. Input4 selects `1ff8h` in the exported case. Treating the omitted cases as default would change behavior.

The extractor admits this bounded PE-only closure, asserts its six exact decoded instructions, hashes the21 bytes and all table data, and then checks the complete969-block CFG. Public evidence retains sites, targets and digests; the bounded disassembly/table bytes are private. This is a native function-membership defect, not an executable patch. Canonical Ghidra and the structural atlas were not edited. Counts above distinguish native metadata from the reachable native code admitted here.

## Shared notation and ABI limits

`p` is entry ECX; `m=dword(p+19e)`; `side=s8(p+27)`; coordinates are signed low bytes. Offsets/masks/tokens are hexadecimal; other numbers are decimal. `R` is `0090cfc0`, `F` is original x87 conversion helper `00945640`. Integer arithmetic wraps at encoded width. `G(dx,dy)` denotes the original grid table, indexed by `9*s8(low8(abs(dy)))+s8(low8(abs(dx)))`. The table is not replaced with Euclidean distance.

All three save and restore EBX/EBP/ESI/EDI. Normal callee cleanup is an explicit inferred table, verified at every local instruction join; this does not recover all helper prototypes. None normalizes a meaningful Boolean/integer result on every return. Do not promote residual EAX/AL to a success result. There are no local SEH frames or allocator calls. Null p/m, invalid profile/candidate pointers, side/index domains, occupancy capacities, aliasing, x87 exceptions and nonreturning callees are not locally made safe. Later null checks do not validate earlier dereferences.

## `006fa250`: supplied candidate/action dispatch

There are five four-byte stack slots `(action,candidate,flag,X,Y)`, `RET14h` at `006fa3d8/006fa48d`. The body uses byte views of action/flag and dword views of all slots; Y is also reused as float32 scratch and later as a byte snapshot. This does not make the incoming Y a float. Its caller-selected coordinate values may have unspecified high bytes.

1. Increment byte `p+2b` modulo256 **before** calling `006fad40(p; p.x,p.y,action,&flag,candidate,X,Y)`. The pointer is to the caller stack slot holding flag. Delegation can therefore replace flag's low byte; the later gate reads it after return. If AL==0, return with that increment already performed.
2. Unless low8(action)==36h, call `006cfd70(m;side,p.y,Y,0)`. A null result skips the candidate route. For a nonnull returned slot `o`, call `006f09b0(o;4,o.side==0?11:0)` twice, independently re-reading side. Save the first result float32 in the reused Y slot; convert `2*second_result*saved_first_result` through F, then draw R at `006fa2f8`. The decompiler omits this product. There is no proof that the two helper calls observe identical input state.
3. Nonzero draw emits commentary1f78h, then increments byte `m+f5ca+36h*side`, increments `o+13`, decrements `p+1`, copies o.x/y to match bytes8ea7/8ea8, sets8eb2=7, sets8eae=(p.side==0), clears dword f582 and returns. Match/side pointers are freshly read between stores. Zero draw calls `006bb9a0(m;-1,o,0,0,8,o.x,o.y,-1,-1)` before the next gate.
4. Require freshly read byte `m+8eb2==0` and the delegated flag byte nonzero. Write candidate to dword `m+f57a`, then p.side to byte8eab. If side!=-1, increment byte `m+8d46+side`; if signed byte `m+8d46+(side==0)>0`, subtract10 modulo256. For nonnull candidate with byte+2b==0, snapshot signed bytes+105/+107, draw R(80), and call `007103e0(candidate)` iff their signed product is strictly greater than EAX. This call can recurse through the mapped R11/R16 dispatch chain; its transitive RNG/state effects are excluded here.

No direct action-word or coordinate write to p occurs in this wrapper. R16 writes action before its six calls; the other-slot/match changes above are additional effects. Two direct RNG sites give a structural maximum of2 per local invocation, excluding helpers and recursion.

## `006fa490`: generated coordinate/action dispatch

Two four-byte slots `(mode,adjust)` are read only as low bytes. Stack reservation is14h; body ESP is entry ESP-24h; both normal returns use RET8. Let h=s16(p+19a). The initial flags are local classification bytes, with no claimed tactical interpretation:

- Start A=B=C=D=E=0. If h<50 or h>310: side!=1 sets B=1; side==1 and h>310 sets E=1; side==1 and h<=310 sets C=1. Independently, 40<h<140 sets C=1.
- For130<h<230: side!=0 sets A=D=1; side==0 and h<=180 sets C=1; side==0 and h>180 sets E=1. Finally220<h<320 sets E=1.

The flags correspond respectively to BL, body bytes14h/13h/15h/12h. Their overlaps are intentional. Preserve the branch ordering, including side values outside0/1.

First compute distance to `(4,side==0?11:0)` through a direct grid load for side0 or `006f09b0` otherwise. The x87 comparison with5 admits **less or unordered**. Together with x outside2..6 and mode!=4, it selects action5eh, x=`3+low8(R(3))`, and y=`11-low8(R(2))` for side0 or `low8(R(2))` otherwise. The Y draw precedes X.

Otherwise let H be `(side==1 && y>=6)||(side==0 && y<6)`. Read match-coordinate bytes as bases X0=m+8ea7,Y0=m+8ea8. All resulting coordinate assignments narrow modulo256:

| Route | Action | Y when A / B / neither | X when E / C / neither |
| --- | --- | --- | --- |
| H,mode4 | 5bh | Y0-R(2)-2 / Y0+R(2)+2 / Y0-R(2)+R(2) | X0-R(2)-2 / X0+R(2)+2 / X0-R(2)+R(2) |
| !H,mode4 | 5ch | same with shift1 | same with shift1 |
| H,mode!=4 | 3eh if m+8ea9==ffh, otherwise9 | Y0-R(5)-4 / Y0+R(5)+4 / Y0-R(3)+R(3) | X0-R(5)-3 / X0+R(5)+3 / X0-R(3)+R(3) |
| !H,mode!=4 | 5dh | Y0-R(4)-2 / Y0+R(4)+2 / Y0-R(3)+R(3) | X0-R(4)-2 / X0+R(4)+2 / X0-R(3)+R(3) |

Y draws precede X draws. For the ordinary mode!=4 routes, then bias Y by+2 for side0 with B==0, or-2 for nonzero side with D==0. The special5eh route omits this bias. Mode ffh skips midpoint adjustment. With adjust==0, an optional R(3)==0 when p+10b==0, or side0 y<2, or side1 y>9 also skips it; this optional draw occurs **before** the latter position checks. Otherwise choose midpoint Xanchor1 when E,7 when C, or1/7 from R(2); choose Yanchor starting10 and decrementing for side0, or1 and incrementing otherwise, until signed distance from p.y<=5 (<=3 for mode4). Replace each coordinate with the signed sum of generated coordinate and anchor divided by2 with truncation toward zero. The two anchor loops contain no RNG.

Increment p+2b; set local flag1; call `006fad40` with generated action, candidate0 and local coordinates. AL0 returns. The nonzero route uses `006cfd70` and a candidate branch equivalent to the previous function's event/store sequence. Here both distance loads are direct G table reads and F receives `2*g*g` without the previous wrapper's intermediate float32 store. Nonzero R emits1f78h and the eight state stores; zero R calls `006bb9a0`. If still m+8eb2==0 and either match coordinate is signed outside x0..8/y0..11, call `006cd490(m;side)`.

There are no direct action-word/coordinate stores to p and no post-dispatch candidate pointer/counter update corresponding to `006fa250`'s step4. The37 alternative RNG sites have a conservative local structural maximum7. The one x87 comparison and both loops are retained in the CFG; runtime float control remains open.

## `006f09f0`: entry scans and active-slot score

Five four-byte slots `(X,Y,action,flag,mode)` are admitted. X/Y/action have dword views; Y also byte, action also word; flag/mode are used only as bytes. Stack reservation25ch plus four saved registers gives body ESP=entry ESP-26ch. Six normal RET14h sites restore entry ESP. There is no normalized return contract.

Snapshot p.x/y, then increment p+2b. If target low bytes equal current coordinates and low16(action) is neither0fh nor100h, scan the p+1ae pointer array with signed-byte index starting0 while index<s8(p+101). Each candidate passes through `006bce20(m;candidate,p.x,p.y)`; only nonzero AL draws R(900), after snapshotting signed p+107/+104. Call `00714d40(candidate)` when their product<=draw+50. Count and pointer reads repeat each iteration; return after the scan. Nonpositive initial count returns directly.

Otherwise, when p!=dword(m+f582), call `006cfe10(m;p,action,0,-1,1)`, then re-read m and that pointer. If still unequal, `006fa140(p;X,Y)` AL0 and bytes p+10c/+10a/+105 all zero, call `006f4920` with current and target coordinates, perform a second separately emitted candidate scan of the same form, write action word p+198=6fh, then return. This return does not reach occupancy updates below.

Build provisional destination by moving each signed coordinate one byte step toward target. For p!=m.f582, snapshot s8(p+104), draw R(1000), and take another step on both axes only if its square>draw. The pointer is tested again: a non-active slot now goes directly to movement at `006f3a67`, bypassing the score/contact region.

For p==m.f582, convert float32(p+4d), narrow result signed16, compute wrapping square `(10000-value)^2`, divide signed by50000 and draw R at006f0cf8. Save low16 of its result as a signed subtraction in the next bound. If flag!=0, add low16(F(float32(p+99)+20)) to word p+19c, then signed-clamp to[-200,200]. Choose signed16 field138 for action0fh,13e for12h,13c otherwise; draw R(field - signed16(previous draw)+s16(p+19c)). Adjust the result according to signed match byte+1:1/2 subtract1+R(3),8 subtract2+R(5),20h subtract3+R(8). Next subtract R(50*s8(m+8ea9)^3), then add R(trunc(s16(p+29)/10)-30), in that order.

Call `006c87e0` with p, side, action and five output addresses plus0. Keep its returned pointer o and local outputs; if o!=0, call `006cfe10(m;p,action,o,s16(s8(output28)),0)`. A separate commentary selector region `006f0e7a..006f124f` uses current action0fh..12h, tactical word1, optional R(20), regional coordinates and optional R(2) to emit215ah..2162h. Its parameter is1 if `5*trunc_s32(s8(low8(F(9*g+2.5)))/5)<1`, otherwise low8 of that multiple-of5, freshly recomputed with a second grid lookup/conversion. This region neither commits coordinates nor changes direct state fields. It can precede every later contact route.

## Contact outputs and early state exits (`006f124f..006f283a`)

The working score is accumulated in32 bits but subsequent contest comparisons use its **signed low16**, v. The output threshold at body+38 is also compared as signed16. A nonnull o can emit1f4dh unless its tactical word is1. If threshold<v and R(5)!=0, clear output-result byte24 and bypass contact calculation. Otherwise `006cfc60(m;o,p,output28,-1,&output44,&output40,&output30)` supplies result AL; match byte8ebb and o's rectangle permit additional predicate/word+31/ R(3) commentary2168h. A nonzero result draws R(30); zero with output48==0 calls `006bb9a0` and rejoins.

For a retained nonzero result, `006cfcd0` receives o,p and local result/output pointers. The first action-byte switch selects1fe9h..1ff4h commentary. The second switch selects event1ff6h..1ff9h for result2..5, otherwise draws R(7) to compare with s8(output40)-2. Result7 sets m+8eb2=7. Otherwise the current p rectangle selects state5 or6; state5 additionally sets dword m+478a=p, subtracts500 from o+35, optionally calls `007172d0`/`006eecb0` through R(profile+5a+6),R(8), and emits1f7ah.

The selected nonnegative signed16 event enters `006f17cc..006f1ac7`: a `007c1e30`/F result, optional object/date gates and draws5,5,3500,3 can enqueue a25-byte local record through `0068d0d0`; output action2ch/2fh and flag30 can emit21d9h/21dah and set o+16=1; R(4)==0 permits further R(output40),R(20) and optional20f5h/2109h commentary. Emit the selected event; result3/4/5/6 can call `006cda20(m;o,0)`. No original record bytes are published.

The following region resolves a restart candidate through `006ceb90`, emits state/position commentary, tests `006cb650`, and can draw2/9/3/2 for20ddh/20dfh/20e0h/20d9h. Calls `006bb8d0` then `00716e10` occur only on the admitted predicate route. Its common early exit copies p.x/y to match8ea7/8ea8, writes p.side to8eae, clears f582, subtracts25 from o+35 and returns at006f1e30. It does not commit the provisional step.

Other nonnull-o paths write o+198=s16(s8(output28)), increment byte o+4, and subtract59 from o+35 if successive tactical lookups match30h and880h, otherwise70. This precedes the later contest branch. p+1d!=0 immediately selects the reset route at006f39af. For mode!=4 and v<1, R(F(p.e5*5+75))==0 also resets when o==0 or threshold<v.

When o!=0 and threshold>=v, the loss route `006f1f0d..006f283a` tests action predicate/output30/optional R(s16(o+31)), a rectangle and R(2). Its action switch emits event pairs through the same1fe9h..1ff4h family and R(50) followups, or action-specific1f62h/2150h/1f61h/1f64h. For output action1, `0070d430(p;output38 - full32 score)` returning zero exits immediately. Otherwise call `006f0630(o)` and subtract20/100/250 from p+35 by region; the250 route can draw profile-dependent bound then3 and refresh helper calls.

Assign o+19c=low16(output38-full32 score-200), then signed-clamp[-200,200]. The subsequent threshold is400 for action13h,250 for21h/2dh,100 otherwise. Depending on that threshold and match8ea9, call `006cd770` then either assign o+2b from three ordered draws10,10,`3-(first<o.10d)-(second<o.10c)`, or call `00716c90`; the alternative routes through `006f4920` and result-ratio commentary with optional o+fd=1. Increment o+5. Credit to o+35 starts120 when the three-draw route retained a zero match state,200 otherwise, doubled unless successive tactical queries find bit4 or2. Outside the admitted endpoint regions (side0 y<3 or y>8; side1 y<3 or y>8), use low16(F(signed16(credit)*0.85)); add the resulting word. A flag/grid/`006cd5f0` gate can add300 to o+35 and increment o+6 with further RNG/refresh calls. Finally add output37 to byte p+2b. A late R(7) can emit1f41h. This route returns at006f2837 without occupancy commit.

The optional refresh gate at `006f27b8` draws `R(30*s8(o+17)+50)`, then R(5) only when the first result is zero. The original MOVSX/LEA chain forms x→3x→15x→30x+50; the extractor asserts that sequence explicitly.

## Winning/absent contact and action commentary (`006f283a..006f39af`)

For o==0 or threshold<v, an exterior-rectangle R(s16(p+31))<-10 updates float32 p+1a2 by multiplier float32(1.05), a profile-derived lower selection and cap100, emitting211dh. Preserve x87 ordered/unordered branch relations from the sites; this is not a host min/max specification for NaNs.

Write match8eab=p.side; update side byte8d46 (+1 when side!=-1, opposite positive byte-10), then add5 to the freshly read side-indexed byte unconditionally. Form `w=v-s16(low16(max(250,s16(output38)+50))) + p.e5*p.95`. The comparison loads0 above w and compares **0 to w**: retain w only for ordered w<=0, otherwise select0. Add low16(F(selected value)) to p+19c and clamp[-200,200]; an empty opposite occupancy count in p's current cell adds50 with a second clamp. The nested signed16 narrowing and comparison direction are observable.

| Contact/action | Ordered direct accumulator effects before commentary |
| --- | --- |
| o==0 | p+35 +=9; match4782 and4786 +=36 |
| o!=0,action0fh | o+2b +=output2f; p+35 +=75; p+11++; match4782/4786 +=300 |
| o!=0,other action | o+2b +=max(2,s8(output2f)); tactical word1 sets match1a4=1 and adds200 to4782/4786, otherwise adds400; p+35 +=100; p+11++; optional draws20*(p+17+1),5 and refresh |

Clear match8ea9=0. Actions0fh/11h/12h then select commentary, regional crossings, tactical word1, repeated `006cb910`/`006cb930`, optional region score from `006c3950`, and candidate-at-current-coordinate tests. The12h and11h blocks contain separate, ordered F(p.95),R(...),R(30) pairs. Mode4 and position gates can clear the local flag argument, affecting later commentary conditions. The original pointer/side/coordinate reads and repeated lookups must remain separate until stability is proved. The CFG records every branch and call site across these long commentary regions, including joins between them.

An action other than0fh/11h/12h calls the diagnostic formatter/source loader/token formatter/error display, clears global dword00b67a34, and rejoins movement; there is **no local exit-process call** on this diagnostic path. A source diagnostic identifies `MATCH_PLAYER::move_to`; it supports the working label without recovering original declarations.

The reset route clears match4786,f582,1a7 and p words29/19c, sets8eae=ffh, draws R(2), subtracts150 from p+35, assigns p+2b=low8(draw+1), emits1f42h and may draw profile-dependent bound then3 and refresh. It then enters movement with a local reset flag. These effects occur before coordinates commit.

## Occupancy, movement cost and final state (`006f3a67..006f42c3`)

If provisional coordinates differ from p.x/y, compute source/destination cells `m+215e+90*(12*x+y)`. A negative signed p+28 means absent from a source list: copy the destination's side count into p+28, increment that byte, and write p into `cell+4*(11*side+s8(p+28))`. Otherwise replace its source entry with the last source-side pointer, decrement source count, update the replacement slot's byte+28 if nonnull, then append p to the destination list. There is no local capacity/index check. Store p.x and p.y afterward. This is swap-delete/append, not stable ordering, and helpers can already have changed coordinates/aliases before this point.

For side0 update m+f596 when new y exceeds its pointed y (default-1); for side1 update m+f59a when y is smaller (default9). Other side values update neither. Perform the third candidate scan, the same signed-index/R(900)/dispatch pattern as the entry scans, now at committed coordinates.

If s8(p+19)>=0, compute float32 movement cost. Match byte1 chooses multiplier1.4/1.2/1.45/1.05/1.15/1.1 for1/2/8/(4 or10h)/20h/40h, default1; match4756==3 multiplies float32(1.05),==4 float32(1.1). The base is original-grid displacement times `(7-(p.d5*0.5+15)/6)`. When repeated tactical lookups differ, classify their first matching bits1/4/8/10h/20h/40h into ranks0/1/2/3/4/5, default3; rank-distance and bit4 choose multiplier1.25/1.15/1.2 minus p.d5*0.005. Getter flags8000h or2000h plus team mask100h can multiply again by1.55-p.d5*0.025. Intermediate float32 stores and repeated getters are retained. Call `006f56c0(p;cost,-1)`; its actual cost application remains a boundary.

If p is currently m.f582 or the reset flag is set, copy committed coordinates to match8ea7/8ea8 and call `006cd490` if out of signed x0..8/y0..11. Otherwise match-state/coordinate/pointer guards can select `006f4920`, commentary1f46h/2113h/1f60h, `006f0630(p)`, clear8ea9 and add4/28 to p+35. Finally, an active slot returns; other routes use side/possession-pointer gates and signed division-by3 to call `006f4920` toward a blend of current, match and central coordinates, then return. The late helper is separate from the direct coordinate commit and can have further effects.

## RNG, stores and remaining boundaries

The sites retain all98 direct RNG sites across the three functions, every argument push and dynamic bound, all branch successors and all non-frame stores. Address order alone is not execution order: jumps, alternative cases, early returns and candidate loops determine the sequence. The three large-body loops are distinct signed-byte scans. Index starts0, increments once and compares signed against a freshly read byte; under normal register/local preservation each executes at most127 iterations even if the count changes. The first/second terminate their paths; only the third follows active-slot processing. SCC collapse with this bound gives a conservative local maximum146 direct RNG calls for `006f09f0`, ignoring correlated predicates. The number is not a demonstrated feasible total and excludes all transitive RNG, recursive dispatch and exception behavior. The smaller functions have maxima2/7.

Thirteen large-body x87 comparisons and one small-body comparison are reported with their exact FNSTSW/test/branch relation. AH mask1 tests less-or-unordered,41h tests less/equal-or-unordered,40h tests equal-or-unordered. Replacing these with ordinary language comparisons can change exceptional-input behavior. Runtime precision, traps, helper conversion behavior and actual match input domains are unmeasured here.

The public direct-store inventories contain13/9/93 sites respectively, preserving byte/word/dword widths and location order. They include occupancy arrays, slot counters/action/scalars, match coordinate/state/pointers/accumulators and the diagnostic global. Their numerical offsets do not establish goals, finances, exclusive ownership or persistence schema. Local output addresses and arbitrary aliases can permit additional helper writes. `006fad40`, `006cfd70`, `006c87e0`, `006cfc60`, `006cfcd0`, `006cd770`, `006f0630`, `006f56c0`, `0070d430` and further commentary/roster/record helpers remain direct dependencies for later admission. Previously mapped helpers retain their prior scopes; no transitive equivalence is inferred from their names.

## Reproduction

Run `scripts/extract_match_dispatch_17.py PRIVATE_EXE --exports PRIVATE_EXPORTS_17 --preflight PRIVATE_PREFLIGHT_17 --output evidence/match-dispatch-17-sites.json` with Python/Capstone5.0.7. The script rejects wrong specimen/manifest/preflight, checks every manifest file digest/size, decodes every exported instruction, checks the PE-only switch closure, validates switches/branches/normal stack/RNG push origins and emits compact public metadata. Bulk exports and original bytes remain private.

Verification includes deterministic regeneration, wrong-specimen rejection, public JSON inventory checks, `git diff --check`, and `npm run check` under Node24. The retained numerical checks concern earlier primitives and do not execute these functions. Optional exact-old name-only proposals are supplied separately; no native annotations were applied in this worktree.

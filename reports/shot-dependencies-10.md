# Investigation 10: action33 side-effect dependencies

`006cfe10` is an RNG and state boundary between the action33 keeper response and shot classification. Its record lookup `0062ed70` can first run `0062c680`, which updates cached rows and has its own conditional RNG. Its selected effect routine `006d0980` can then change slot floats, activity flags and a match counter. Neither helper may be replaced by a pure lookup or omitted when composing an attempt.

These are **static contracts and dependency leads**, not numerical or complete shot equivalence. The specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; addresses are virtual addresses. Baseline is main `944954fd19b73a133f4505afc5b28a486479b45e`. Only this task's report, compact evidence and annotation proposal change.

## Evidence and confidence

The specimen was opened read-only and hash checked; PE virtual addresses were resolved through section raw offsets. Capstone5.0.7 decoded the bounded function ranges. Independent read-only Ghidra exports supplied by the coordinator agree on every instruction address and direct-call site/target: `006cfe10` 887/54, `0062ed70` 60/5, `0062c680` 562/27 and `006d0980` 141/9. Manual checks cover operands, signed comparisons, stack cleanup, switch destinations and write widths. Export and code-range digests are in [findings](../evidence/shot-dependencies-10-findings.json); [sites](../evidence/shot-dependencies-10-sites.json) group call and RNG addresses. Bulk listings, pseudocode and original tables remain private.

Confidence is high for the listed instruction sites, widths and specialized control flow. Meanings such as “status row”, “condition effect” and “stamp” are provisional labels. Runtime reachability, alias safety, floating-point results and transitive effects lack a new original-instruction oracle. No behavioral TypeScript is added.

## Calling boundaries

| Entry | Observed boundary |
| --- | --- |
| `006cfe10` | ECX=context; five stack arguments: participant1 pointer, metadata1 low word, participant2 pointer, metadata2 low word, final low-byte flag. `ret 14h`; no meaningful return value established. |
| `0062ed70` | ECX=lookup object, one stack pointer argument; `ret 4`; EAX is a record pointer or0. |
| `0062c680` | ECX=same lookup object, one stack pointer argument; `ret 4`; update routine, no meaningful return value established. Uses an x86 SEH frame. |
| `006d0980` | ECX=match context; four stack arguments: kind low signed byte, severity low signed byte, target pointer, other pointer. `ret 10h`; no meaningful return value established. |

R09's caller `007024b4` supplies `(shooter,6dh,null,0,0)` to `006cfe10`, after saving keeper EAX at `0070241f`. This is the specialization below. `00702050` remains a dependency; its category, ratio gate and score sites are not newly owned or dynamically validated here. `R(n)` means original `0090cfc0`; `R(0)` returns0 without advancing exposed RNG state.

## Ordered path through `006cfe10`

1. Before either participant check, two groups run: `a=R(102); b=R(a)`. If signed8(b)>50, draw `R(3)`; if nonzero, replace b with `R(R(76))`. First-group calls are `006cfe35/3b/50/5e/64`; second-group calls are `006cfe74/7a/8c/9a/a0`. Thus a null second participant does not eliminate its initial group.
2. Nonnull participant1 calls `0062ed70` with its player pointer `slot+69h` at `006cfec2`. That lookup may execute the update path described below, including RNG, before returning. A nonnull result selects a byte at record+0, calls byte mapper `0062ec00` at `006cfedc`, changes the local factor4 to6, and draws `R(25)` at `006cfee7`; nonzero result doubles the local severity byte with byte wrap.
3. Participant1's local factor uses float32 `slot+4d`, signed8 `*(slot+6d)+2d`, and low-byte `0062ece0` status. For finite ordered inputs the shape is `10000/max(slot4d*0.5+5000,1000) * (4 or6)`, multiplied by either `attribute*float32(0.1)` for attribute>10, or `1+(attribute-10)*float32(0.1)` otherwise. Nonzero status adds a multiplier capped at3 from `1.5+0.5*status`. Original x87 operations and float32 stores are authoritative; this description is not a tested replacement formula. Calls are `006cff72` and, when AL is nonzero, `006cff85`.
4. Participant2 is null, so `006cffc2..006d00d7` is skipped. If participant1 float `+4d` compares below4000 at `006d00e2`, call `006d0980(-1,0,participant1,null)` at `006d00f8` and return. This skips both `R(50000)` and the effect-kind switch.
5. Otherwise final flag0 bypasses `006d0107..006d01fc`. The two-participant loop starts at `006d021e`; participant1 is processed, participant2 is skipped. The ball-owner/other-participant factor path `006d022d..006d035a` requires a nonnull other participant and is skipped. Metadata1=109 bypasses metadata==5 adjustments at `006d0364` and `006d03be`.
6. Call `R(50000)` at `006d0394` and compare it with the x87-truncated local factor*10 (`006d03a8..006d03af`). Draw>=threshold skips the effect. After a passed threshold, the match-state4 paired effect at `006d0423..006d0448` also requires a nonnull other participant and is skipped.
7. Mapper result1..5 selects one direct effect kind respectively1,2,3,4,5 through `006d046b` and the direct blocks `006d05ec/006d0658/006d0610/006d0634/006d067c`. Other mapper values call `R(11)` at `006d0474`. Results0/9/10 select kind1; 1/2/3 kind3; 4/5 kind4; 6/7 call kind2 then kind5; 8 selects kind5. Each selected call passes the local severity byte, participant1 and null. The two-call route is `006d04c5` followed by `006d055f`; it can pass through the match-counter gate twice.

The direct body of `006cfe10` writes its own frame; external slot/object/match effects in this specialization occur through the called routines. General paired-participant and nonzero final-flag paths remain outside the specialized contract. Their direct call sites are retained as inventory, not claimed as action33 execution.

## `0062ed70`: refresh before pointer return

Null input enters diagnostics `0062ed85..0062eddb`, writes global `00b67a34=0` and returns EAX0. Nonnull input with signed32 index `*input >= *00ae2364` also returns0 (`0062edf5..0062edf7`). There is no explicit negative-index rejection in this entry: callers need a valid nonnegative index.

For a passing index, `0062edfc` calls `0062c680` **before** reading the returned record mapping. The row is `*(uint32*)object + 31*index`; its signed32 `+e` field is read at `0062ee0c`. Exactly -1 returns0; otherwise EAX is `*(uint32*)(object+4) + 48*recordIndex` (`0062ee15..0062ee21`). There is no independent record-bound check after the update returns. The cached-stamp path can bypass the updater's normalization, so valid object storage and mappings are preconditions, not proven by this wrapper.

Two read helpers explain values consumed by `006cfe10`: `0062ec00` reads a byte at `009e7ad9 + 13*signed8(argument)` and returns AL only; no bounds check is present. `0062ece0` returns AL0 for null/out-of-range input, null input `+61`, or a negative signed row byte `+12`; otherwise it returns `max(1,signed8(row+13))` in AL. Neither helper contains a call or RNG instruction. Upper return bits on their early paths are not a contract. A whole subsystem meaning for these rows/records is still open; R09's “manager lookup” wording should not be treated as an established semantic type.

## `0062c680`: cached update, branches, RNG and writes

This updater is not a pure accessor. Before input guards it initializes three process-local helper objects when bits1/2/4 of byte `00b63d10` are absent (`0062c6c2/c6ed/c71a`), calling `0054a110` and registering cleanup through `0094627a`. Input-null, signed index>=global count, and input `+61` null return at `0062c738/c748/c757`. On a valid row, its first two16-bit stamp components are compared with `00ae2c90/+2`; equality returns at `0062c790`, bypassing the two direct RNG sites and final row writes. Initialization/transitive helper effects are separate.

| Phase | Instruction evidence and consequence |
| --- | --- |
| Refresh setup | `0054cc30` at `0062c7a7` derives an elapsed-like quantity from the row's8-byte stamp and current global stamp. Arithmetic uses `365*uint16(component)+signed16(component)`. Full date/calendar semantics are not assigned. |
| Record mapping normalization | Row signed32 `+e` becomes-1 at `0062c7d8` if it is greater than object signed32 `+8`, or below-1 (`0062c7cf..0062c7d6`). The upper comparison is **greater than**, not greater-or-equal; this does not certify array safety. |
| Existing record path | A non--1 mapping resolves a48-byte record. Its stamp `+20/+24`, signed16 `+28/+2a` and elapsed quantities select branches `0062c7e3..0062c8b1`. Calls `0062e700` at `0062c895/0062c8ac` may change lifecycle state; their effects and RNG are unresolved dependencies. |
| No record path | Index-1 uses input `+24` and helper calls `0076d780/0076e040` to gate on another stamp. Input `+39` and cached globals `00b63d2c/+30`, stamp `00b63d08`, and helper `00669bd0` determine additional update buckets (`0062c8b6..0062c9f3`). |
| Repeated direct RNG | On the `u16(first helper result)<u16(second helper result)` branch at `0062c9f3`, loop count is the smaller of the first result and the elapsed-like quantity (`0062c9f9..0062ca19`). Each iteration first stops if byte `*(00ae2d0c)+79*inputIndex+ah >=50` unsigned; otherwise `0062ca4f` draws `R(trunc(signed8(input+5bh)/3)+2)`. A zero result increments that byte at `0062ca76`. Repeats in increasing loop-index order. |
| Later optional RNG | After either no-record update-bucket branch, a second helper result below15 selects a fixed bucket adjustment (`0062cac5..0062caf0`). Otherwise, if `trunc(signed16(row+ah)*signed16(row+8)/10000)<8000`, `0062cb18` draws `R(2)` and divides a selected bucket with signed truncation (`0062caf2..0062cb31`). This draw is after any loop draws. |
| Calculated row writes | `0062cb35..0062cdc7` derives/clamps two quantities using row words `+8/+a/+c`, row byte `+1e`, and signed byte `*(input+61h)+34h`. `0062cdd3/cdd7` write16-bit row `+8/+a`; `00417c10` at `0062cddb` copies current stamp data back to the row. Detailed numerical equivalence remains untested. |

When the no-record path reaches this work, the updater may consume zero, one, or multiple RNG calls. A current stamp, an existing record, or a skipped bucket branch can bypass its direct draws; a skipped direct draw does not certify that its untraced callees consumed no RNG. The lifecycle, schedule/stamp helpers, auxiliary-record layout and real initialization state are required inputs to any connected attempt oracle.

## `006d0980`: counter gate and concrete slot effects

Let n be signed16 `match+f639h` at entry. If n>3, draw `R(n)` at `006d099d`; if nonzero draw `R(500)` at `006d09ae`, returning immediately if that is also nonzero. Then n>6 returns regardless (`006d09be..006d09c6`). Thus a counter above6 can still consume RNG before rejecting the effect. This function does not initialize or clear match byte `+8eb5`.

For an admitted effect, kind>=0 calls `0062be00(player,&kind,&severity)` at `006d09ed`; that dependency can modify both bytes and record state. Its assembly has no direct RNG but includes allocation/list helpers, which are not certified here. Kind-1 skips it. Slot pointer `+55` is then overwritten with the supplied other pointer at `006d09f8`; if nonnull, other signed16 `+31` loses10 at `006d09fd`.

The severity is taken as signed8 **after** that possible merge. For finite ordered inputs:

| Branch | Ordered activity and writes |
| --- | --- |
| Severity s>50 | Set target byte `+1c=1` (`006d0a12`); float32 target `+4d` loses s*s (`006d0a23`). No severity RNG in this branch. |
| Severity s<=50 | Draw `R(trunc(s*s*0.5))` at `006d0a41`; convert result to float32 and subtract from float32 target `+4d` at `006d0a59`. Draw `R(trunc(firstDrawFloat*0.5))` at `006d0a6c`; store it as float32 target `+59` at `006d0a7c`; halve target float32 `+d5` at `006d0a8b`. |
| Resulting float `+4d<5000` | Set match byte `+8eb5=1`, target `+1d=1`, target `+1c=1` (`006d0aa1/aa7/aaa`). |
| Otherwise `+4d < 7100 + 25*signed8(*(target+6dh)+2dh)` | Call `007160e0(5)` at `006d0ada`, then set match `+8eb5=1` and target `+1d=1`. The tiny setter writes target `+2b` at `007160e4`. |
| Otherwise | Call `007160e0(3)` at `006d0ae5`. Only when the first severity draw float is>=500 and target `+1c` is already nonzero does this path set match `+8eb5` and target `+1d` (`006d0aea..006d0b08`). |
| Common tail | Clamp float32 target `+4d` to1..10000 at `006d0b0b..006d0b3f`. If match byte `+8eb5` is nonzero, increment16-bit match `+f639` at `006d0b4d`. The latch may have been set by an earlier call; the increment is not evidence of a newly set flag in this call. |

For the specialized low-float path `006d00f8`, kind=-1 and severity0 bypass `0062be00`; both severity calls are `R(0)`. If admitted by the counter gate, slot `+55` clears, `+59` becomes0, `+d5` halves, the low-float flags set, `+4d` is clamped, and `+f639` increments. It still has state effects despite no severity RNG-state advance. For the kind2-then-kind5 route, the first call's latch/counter changes can change the second call's throttle and effects.

## Consequences for an action33 attempt oracle

The expanded order is: keeper response; the two initial nested RNG groups; `0062ed70 -> 0062c680` refresh and its selected RNG/callees; optional `R(25)`; local status reads; then either the low-float effect and return, or `R(50000)`, optional `R(11)`, selected `006d0980` call(s), each with throttle draws, possible `0062be00`, severity draws and writes. R09's later selector draw, event wrapper, category selection, distance draw and score logic follow only after this helper returns.

These owned functions contain no direct tiebreak score-byte write; the R09 score site remains `00707dd6`. Their changes to RNG, player rows, slot floats/activity and match latch/counter can affect subsequent simulation, so score classification alone is insufficient to certify them.

Before behavioral reconstruction, admit the real refresh/lifecycle and effect dependencies or prove concrete bypass preconditions with original instructions. Capture caller frame, lookup-object storage/stamps, player/auxiliary/record pointers, slot floats/flags, match counter/latch, ordered RNG bounds/state and all memory writes. Current-stamp and stale-stamp cases must be distinct; so must low-float, threshold rejection, single-effect and double-effect paths. Preserve x87 control and signed low-byte semantics. The meanings and valid runtime ranges of these fields, nonfinite input behavior, exception paths, and initialization helpers remain open.

`npm run check` passed under Node24.19.0, new evidence JSON parsed, every published RNG site resolved to an original RNG call, and `git diff --check` passed. These checks retain earlier numerical guarantees and verify the new static evidence's shape; they do not dynamically validate the new contracts. No new numerical oracle is claimed.

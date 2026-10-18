# Investigation 09: action `0x33` in the shared shot resolver

The caller connects the previously checked keeper response, quality category and ratio gate, but adds substantial RNG activity between them. In particular, the unconditional `006cfe10` call consumes RNG even when action `0x33` supplies a null second participant. Joining the earlier independent oracles would therefore give an incorrect shared RNG stream.

This is **static instruction mapping**, not a new connected outcome oracle. No TypeScript behavior, native database, checkpoint or existing validation claim changes here. The specimen is SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; every address below is a virtual address. Names and field meanings remain working annotations.

## Evidence and method

The read-only private specimen was hash checked and its PE sections decoded with Capstone 5.0.7 in 32-bit x86 mode. Private generated listings remain in ignored `results/`. Existing Ghidra exports of `00700420`, `00713e90` and `006ce310` corroborate the call boundaries and output widths. The existing code atlas supplies helper call dependencies. The accompanying [findings](../evidence/shot-resolver-09-findings.json) record selected byte-range digests and the two relevant switch resolutions, without copying instructions or lookup tables.

The author inspected `00702050..0070a592`, `00700bd0..00701fde`, the tiebreak caller `006be710..006bee97`, and selected dependencies. This report follows action `0x33`, concentrating on caller mode 3, while identifying mode 1 and 4 differences. It does not assign a stable prototype to the whole 34 KB resolver or claim all helper side effects are recovered.

The coordinator's subsequent read-only Ghidra `exports-09` corroborates the static map. `00702050.asm` agrees with the independent listing on all 10,263 instruction addresses and all 688 direct-call sites/targets; `00700bd0` agrees on 1,572/82 and `006cfe10` on 887/54. Manual operand checks confirm the nested RNG calls `006cfe35/3b/74/7a`, keeper suppression `00703fb7`, signed16 loads `00703ffb/00704004`, attempt-byte write `00703d80` and score-byte write `00707dd6`. No discrepancy was found in those claims. Compact counts and export hashes are recorded in the findings; the bulk exports remain private. This agreement does not execute the caller or validate helper side effects.

## Caller contract and preparation

`00702050` receives its slot in ECX and returns with `ret 18h` (`00704b0c` and other exits). After its `684h` allocation and four saved registers, the first six arguments are at frame `+698/+69c/+6a0/+6a4/+6a8/+6ac`. In the mapped path these are action, quality, event code, mode and two further arguments. Frame offsets in this report mean ESP after this fixed prologue and with temporary arguments removed.

The tiebreak caller sets action `33h` at `006beae6`, calls `00700bd0` at `006beaeb`, sign extends AX at `006beaf0`, subtracts its pressure/error draw at `006beb04`, and calls the resolver at `006bedb0` with mode 3 and the two final arguments zero (`006beb06..006beb0d`, `006beda9..006bedb0`). Action and mode are distinct values: action `33h` is also used in normal mode 1, while mode 4 has additional non-penalty tiebreak handling.

`00700bd0`'s action33 early return sets the output event word to `1f7f` at `00700d20` and returns `150 + R(5 * signed16(slot+180h))` at `00700d25..00700d47`. Its prelude already selects a keeper, reads coordinates, calls the tactical-position lookup conditionally and reads the distance grid before the action test (`00700beb..00700d15`). The earlier preparation oracle covers the calculation branch, not that prelude. Here `R(n)` denotes a call to original `0090cfc0`; a zero bound makes no RNG-state advance.

## Quality and keeper data flow

| Boundary | Address evidence and consequence |
| --- | --- |
| Initial quality | Argument 2 is loaded into EDI at `0070209d`; action33 sets the category threshold to 120 at `007021c9..007021cd`. |
| Early adjustment | `00702222` calls `00713e90`. Its action33 branch `00713eeb..00713eef` takes the early return with AL=2 and adjustment word 0. Caller still calls `R(0)` at `00702241`, so the quality subtraction at `0070224d` changes nothing. |
| Keeper selection | `0070230c` calls `006ce110` for the opposing side. EBX and frame `+48` retain its pointer; the null case enters an error path rather than a safe zero-keeper path (`00702313..00702389`). |
| Variant selection | Action33 maps through byte-table index 4 to `007023e1`; `007023e3` calls `R(2)`, storing AL at frame `+1c`. This is a fresh RNG call. It chooses rating `+168h` for zero, `+16ah` otherwise in the previously checked keeper routine. |
| Keeper response | `00702416` calls `00700420` on the selected keeper, passing shooter coordinates, variant and action. EAX is saved at frame `+38` (`0070241f`). Only its signed low word is subsequently used. |
| Two output bytes | Argument 5 points to frame `+20`, the first keeper output; argument 6 points to frame `+14`, the common-postlude fallback flag. Action33 keeps the first byte zero; the second can become one. These are different flags. |
| Response quality markers | When fallback byte `+14` is zero, signed AX>375 sets frame `+1a`; otherwise AX>260 sets `+19` (`0070241b..0070243a`). Those markers affect later keeper statistics/presentation; they do not replace the response. |
| Collision path bypass | Action33 jumps at `00702461` to `00702498`, setting EDI=0. It bypasses `006c87e0`, but still calls `006cfe10` at `007024b4`. The subsequent zero-EDI branch reaches `0070354d`, where action33 jumps directly to `00703634`. |
| Pre-shot presentation | If local byte 2 from `00713e90` equals slot `+2c`, `00703641` calls `R(10)`. This changes a presentation selector, not the stored quality. `0070387e` calls the event wrapper for the supplied event, before classification. |
| Action33 quality bypasses | Quality is loaded into EBP at `00703883`; action33 bypasses `006cfd70` at `0070389c` and `006cc540` at `0070394f`. Local `+11` stays zero, bypassing the commentary and `R(2000)/R(1000)` quality modification at `00703aaf..00703b1e`. Thus the mapped action33 caller itself preserves the supplied quality up to classification. |
| State before category | Slot action word `+198=6dh` (`0070388a`); match `+8eae=ffh`, `+1a7=0`, slot words `+29/+19c=0` (`0070391e..0070393a`); matching ball-owner pointer `match+f582` is cleared (`00703aa9`). |
| Category | The previously checked slice `00703b25..00703be7` uses signed BP and threshold120. Only categories 1, 14, 15 enter the later ratio gate. Category selection may itself consume RNG. |
| Intervening work | `00703e24` unconditionally calls `R(15)`. If the signed quantized distance exceeds `25+draw`, `00703e37..00703ec4` temporarily sets match `+8ea9=5` and calls `007103e0` on eligible other slots across two arrays, restoring the saved byte afterwards. These calls can themselves consume RNG and mutate match state. |
| First flag bypass | Action33's zero first output at frame `+20` bypasses `00703ed6..00703fa2`, including the quality additions there. The fallback output at frame `+14` is not the flag tested here. |
| Keeper suppression | If selected keeper EBX equals current `match+f5ae`, caller zeroes saved response at `00703fb7`. Field `f5ae` has contact-candidate producer leads; a stable semantic name and reachable-state proof remain open. |
| Gate inputs | After `006ce310` at `00703ff2`, `00703ffb` sign extends the saved keeper word into EBP; `00704004` sign extends quality into EDI. Category 1/14/15 jump to `00706cba` at `007040b5/bd/c5`. The action33 scale switch uses default `1.0f`, affecting a match momentum write at `007040af`, not replacing these gate inputs. |

The retained keeper-entry oracle establishes its action33 flags and low-word return under supplied inputs. It does not prove that `006cfe10`, presentation, or the other-slot updates leave all live slot/match inputs untouched. This mapping must not be promoted to an executable connected contract without those effects and alias conditions.

## Ordered RNG ledger up to the gate

The ordering below is within the mapped action33 caller; helper internals are explicitly expanded only where inspected. **A function call and an RNG-state advance are different counts** because `R(0)` is an identity operation.

| Order | Site | RNG activity or unresolved dependency |
| --- | --- | --- |
| 1 | `00702241` | `R(0)`, from the action33 adjustment helper. No advance. |
| 2 | `007023e3` | `R(2)` variant draw, after keeper-slot selection. |
| 3 | `00702416` | Keeper entry: no draws if rejected. Eligible action33 has the two base draws, two postlude comparison draws, and, on fallback, two choice draws plus one redraw; preserve the existing precision-dependent bounds and signed16 casts. |
| 4 | `007024b4` | `006cfe10(shooter,6dh,null,0,0)`; see the expansion below. This call is unconditional on action33. |
| 5 | `00703641` | Conditional `R(10)` when slot `+2c` equals the local selector2. |
| 6 | `0070387e` | `007002f0` wrapper calls `006d6f70`; event presentation can consume the shared RNG unless its actual suppression guard is satisfied. |
| 7 | `00703b32/00703b6e/00703b9d` | Classification: `R(signed16(quality))` when quality>120; nonzero-variant low-quality categories have conditional `R(4)`; remaining cases have no classification draw. See investigation06. |
| 8 | `00703d2f` | Only normal mode1, ineligible category: `R(signed8(player+5ah))`, with conditional `007172d0` and `006eecb0` work. Mode3/4 skip this block. |
| 9 | `00703e24` | Unconditional `R(15)`; optional `007103e0` calls follow, each with transitive RNG and state dependencies. |
| 10 | `00703ff2` | `006ce310` reads score/context and writes five output bytes; its retained export has only direct callee `004b0850`. No direct RNG instruction appears in that helper. Transitive behavior has not been certified here. |
| 11 | `00706cba..00706d26` | Ratio arithmetic and successful-gate comparison consume no RNG. A failed gate then runs the separate keeper-statistics path below. |

### The previously unaccounted `006cfe10` call

Before examining either participant, this routine always executes two ordered groups:

1. `a=R(102)` at `006cfe35`; `b=R(a)` at `006cfe3b`. If signed AL of b>50, `R(3)` at `006cfe50`; if that result is nonzero, replace b with `R(R(76))` at `006cfe5e/006cfe64`.
2. The same pattern at `006cfe74/006cfe7a`, optional `006cfe8c`, and optional `006cfe9a/006cfea0`.

Only then does `006cfeb0` test participant1. For the action33 invocation it is the shooter, so its `0062ed70/0062ec00/0062ece0` lookups remain relevant. A successful `0062ed70` lookup adds `R(25)` at `006cfee7`. The null second participant skips its corresponding lookup branch, but does **not** skip the second entry RNG group.

If shooter float `+4d` compares below the constant at `0096d40c`, `006d00f8` invokes `006d0980` and returns. Otherwise the final argument0 bypasses the special branch `006d0107..006d01fc`; the participant loop still calls `R(50000)` at `006d0394` for the shooter. Its threshold depends on supplied runtime floats and manager lookups. A passed threshold can call `R(11)` at `006d0474` if its metadata selector misses the direct cases, then `006d0980`; some switch routes call that helper twice (`006d04c5`, `006d055f`). Null participant2 is skipped by the loop. This helper's selected state effects and transitive RNG need their own admitted original-instruction test before connecting an attempt.

The new native `006d0980` export pins further dependency sites: conditional `R(signed16(match+f639h))` at `006d099d`, conditional `R(500)` at `006d09ae`, and later calculation-dependent draws at `006d0a41/006d0a6c`. Its selected branches write slot float `+4d` at `006d0a23/006d0a59`, `+59` at `006d0a7c` and `+d5` at `006d0a8b`. These are additional address-specific leads, not a recovered contract or a replacement for the missing original-instruction oracle.

## Gate, score writes and outcome branches

For categories 1/14/15, `00706cba` adds signed16 keeper and quality terms. The existing oracle checks the float32 ratio `100*quality/(keeper+quality)`, zero denominator handling and state2/8 addition. Strict ratio>71 enters `00706dfd`; exactly71 fails. This is a deterministic branch comparison, not a percentage probability.

A failed gate can first update keeper word `+35` and consume further RNG. With marker `+19` and valid tactical keeper: add350, draw `R(20*signed8(keeper+17h)+50)` at `00706d5f`, and if zero draw `R(4)` at `00706d6d`, then call `007172d0` and possibly `006eecb0`. Otherwise marker `+1a` selects add600, `R(20*(signed8(keeper+17h)+1))` at `00706dbd`, optional `R(7)` at `00706dcb`, then the same helpers. Fallback flag1 leaves both markers zero. The ratio is compared again at `00706de8..00706df7`; the fail destination is `00708e84`.

The subsequent non-scoring dispatch compares ratio against 61 at `00708e88` and another threshold at `007092d4`. Mode3/4 emit `2008` (`00708f12` or `0070935e`); mode3 also reaches keeper event `2122` (`00708ef1` or `0070933d`). The pinned community config labels them `EVENT_MISSED_IN_SHOOTOUT` and `EVENT_SAVES_PENALTY`; this does not identify every failed-gate state as a completed save. Other ratio bands and helper paths require mapping. Noneligible categories bypass the ratio gate and enter their own event switch (`007042eb..0070438f`); mode3/4 emit `2008`, then the mode3 path eventually returns at `00704b02` rather than entering ordinary rebound logic at `00704b0f`.

Mode3/4 reaching the successful branch at `00706dfd` jump through `00706ec5..00706ecf` to `00707db2`. This block increments the **byte** at `match + f5bch + 54*signed8(slot+27h)` at `00707dd6`: home `f5bc`, away `f5f2`, the existing tiebreak-score fields. It emits event `2000` (`00707df2`), community label `EVENT_SHOOTOUT_SCORED`; mode3 then also emits `212e` (`00707e21`), `EVENT_SHOOTOUT_SCORED_COMMENT`. The byte increment occurs before these event calls, so it is a useful bounded stop point for an original-instruction score-write experiment.

After those events, `00707cfa` still draws `R(3)`. Additional clock/state commentary can draw `R(40)` at `00707d7a`, and other presentation paths can draw before the mode3/4 branch at `00707e34..00707e3c` reaches `0070882b`. Subsequent `006bb950`, clock helpers, event wrappers, and optional `00716e10` remain dependencies. Therefore stopping at the tiebreak-score increment proves neither return state nor final RNG cursor.

Normal mode1 has different effects: action33 attempt byte slot `+d` increments at `00703c19`, successful branch increments slot `+e` at `00706ec0`, calls the existing golden-goal predicate and may set match `+1a8=1` at `00706eaf`, and has ordinary stat/momentum/presentation work. A later score increment site at `00708a3a` targets `match+f5bd+54*side` on paths reaching it. That entire normal-goal path, its possible rollback and helper effects are not reconstructed by this report.

Mode3/4 increment match byte `+1a9+side` at `00703d80` before the post-category distance draw. These are separate from the tiebreak-score bytes and are not used as a replacement score signal. The caller `006bedb5..006bedcd` subsequently decrements the current side's remaining count at `match+8ea1+side` and toggles the side byte at `006bede3`.

## Dependencies that prevent a connected attempt claim

| Dependency | Concrete missing evidence |
| --- | --- |
| `006ce110` | Cached keeper selection, reassignment and fallback effects; supplied keeper validity remains insufficient. |
| `006cfe10`, `006d0980`, manager lookups | The unconditional nested RNG stream, float thresholds and chosen state effects described above; no original-instruction oracle retained for these. |
| `006d6f70` via `007002f0` | Actual event suppression, variant draws and side effects for each path, including the pre-shot event between keeper and classification. |
| `007103e0` | Whether the quantized-distance branch is reachable for the intended live penalty frame; ordered work/RNG for other active slots if it is. |
| `match+f5ae` | Producer and lifetime of the candidate that suppresses the keeper term; cross-boundary leads include setter `006cd462/006cd47e`, clearer `006cc57a`. Semantics remain partial. |
| `006ce310`, `004b0850` | Exact context and output-byte contract for the score snapshot used by later branch/presentation logic. |
| `007172d0`, `006eecb0`, `00716e10`, clock helpers | Failed-gate stat changes and post-score mutations/RNG; a score write is earlier than the complete return. |
| Preparation and precision | Real producer values, valid side/coordinate/slot state, live RNG seed/table/cursor and match-entry x87 precision. The existing synthetic oracles do not establish these runtime conditions. |

The next bounded experiment should execute original caller instructions from a declared action33 frame through classification and gate, admit the unconditional side-effect helper and event path, and check all memory writes plus ordered RNG bounds/state. A separate successful mode3 slice can stop immediately after `00707dd6` to check score-byte wrap and side indexing. Both require new original-instruction oracles before adding behavioral TypeScript. A complete attempt needs a return-state oracle including all selected dependencies; a complete shootout additionally needs the tiebreak loop.

`npm run check` passed with Node24.19.0 after these documentation/evidence additions. It rechecks the retained numerical fixtures and checkpoint metadata; it does not validate the new static caller map dynamically. No new numerical oracle is claimed.

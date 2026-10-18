# Investigation 11: the other-slot shot helper

`007103e0` can consume additional RNG and write slot/match state during the shared shot resolver's other-slot scan. It is not a pure notification. Its five candidate loops can invoke `00714d40`; other routes invoke `00713fc0(1)` or `007109f0(0)`. The last route can return to the helper's entry checks after the callee has changed state. Omitting these boundaries or assigning one fixed draw count would leave a connected attempt incorrect.

This is an **assembly-backed static contract**, not an original-instruction execution oracle or full shot outcome. The pinned executable SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; all addresses below are virtual addresses. Baseline is `2c6bb83f13c92a3f9d2309e71e5e77aac7715383`. Field meanings and names remain provisional. The three large callees are immediate call/return dependencies only; their bodies are not assigned by this report. `00702050` and `006be710` are read-only caller dependencies.

The [compact sites](../evidence/shot-helper-11-sites.json) identify the owned 1,547-byte range `007103e0..007109eb` (end exclusive), raw file offset `3103e0`, code digest, 454 instructions, 34 direct calls, 14 direct RNG sites, six return sites and ten explicit writes outside the frame. Independent Capstone 5.0.7 decoding agrees with every instruction address and direct-call site/target in the coordinator's read-only Ghidra export. Selected operand widths, signed branches, stack effects and x87 comparisons were inspected manually. Native export hashes and matching coordinator manifest checks are retained; original bytes, bulk listings and decompilation remain private.

## How action33 reaches it

The mode3 tiebreak path sets action `33h` at `006beae6`, calls preparation at `006beaeb`, subtracts its pressure draw, and supplies mode3 with final arguments zero to `00702050` at `006bedb0` (`006beb06..006beb0d`, `006beda9..006bedb0`). This corroborates R09's route. It does not establish live coordinate values or prove that the following distance branch is taken during a real penalty.

The resolver obtains a distance through `006f09b0(4, side==0 ? 11 : 0)` at `00702088`, stores float32 at frame `+80`, then quantizes it at `00702180..007021b1`. For ordinary finite conversion inputs, first take the signed low byte of x87 truncation of `9*distance+2.5`, divide that signed integer by 5 with truncation toward zero, multiply by 5, and retain the low byte at frame `+1b`. This is a quantized signed byte, not the unrounded distance. Constants and the selected range digest are recorded. The original conversion instructions remain authoritative outside that domain.

At `00703e19`, sign extend that byte into EDI. Always draw `R(15)` at `00703e24`; compare EDI with `25+draw` at `00703e2f`. EDI<=threshold skips the entire scan (`00703e31`). In particular a quantized value<=25 bypasses it for ordinary `R(15)` results, while 30 passes for draws0..4, 35 for0..9, and >=40 always passes. No action33-specific bypass is present at this gate.

On a passed gate, save match byte `+8ea9` and replace it with 5 (`00703e4d..00703e5a`). Scan 20 contiguous slots starting at `match+4796` with stride `1be`, then 20 more starting at `match+6a6e` (`00703e68..00703eb1`, second base offset `22d8`). Each slot must have signed byte `+19` in 0..10, byte `+2b==0`, and differ from the shooter pointer (`00703e74..00703e88`). Call `007103e0` with ECX=that slot at `00703e8c`, then continue the scan. Restore the saved `+8ea9` byte at `00703ec4`. That restoration covers this byte only; callee changes elsewhere persist.

**Action33 belongs to the shooter resolver argument.** `007103e0` receives another slot pointer and no action argument. Its later `slot+198==6dh` test concerns that other slot's own word. On entry from this scan its `+2b` is zero, so the direct nonowner/+2b-nonzero route is initially excluded; transitive mutations still need observation. R09's earlier action33 writes include match `+8eae=ffh` and shooter `+198=6dh`, but this report does not assume the intervening dependencies preserve either value.

## Entry, branch order and RNG

Entry takes ECX=slot, saves EBX/ESI/EDI and allocates 14h local bytes (`007103e0..007103e6`). All six returns use plain `ret`, without explicit stack arguments to clean. No meaningful return value is established. Let `m=*(slot+19e)`, `owner=*(m+f582)`, and `R(n)` mean the original `0090cfc0`; a call is not necessarily an RNG advance, because `R(0)` returns 0 without advancing its exposed state.

The body reads `m+f582` before testing m for null (`007103e8..007103f8` and repeated guards). Null context is not an admitted safe input. Candidate pointers, side/coordinate bounds, array capacity and helper validity are also caller preconditions, not checked structural guarantees.

1. **Initial float gate.** For a nonowner slot whose low-bit tactical lookup `006c38c0` is clear, snapshot float32 `slot+4d`, then draw `a=R(65)` at `00710411` followed by `b=R(10)` at `00710424`. Compute x87 `x=snapshot/128+b`. Ordered `x<=a`, and also an unordered comparison, jump at `00710449` to loop `007106e4`. That loop is followed by word `slot+198=67h` and return at `00710767`. Owner or tactical-bit1 slots bypass these two direct draws. The constant at `0096d818` is float64 `1/128`; this is a static expression, not a tested replacement formula.
2. **Side/region gate.** Again require nonowner and tactical low bit clear (`0071044f..00710471`). With `s=slot+27` and signed8 `t=m+8eae`, reach `R(20)` immediately if `t==(s==0 ? 1 : 0)`. Otherwise skip this gate when raw side byte s equals `m+8eae`, or when nonnull `m+f57a` points to a same-side slot. In remaining cases call `006cb960` at `007104b9` with low-byte opposite-side/coordinate arguments from `m+8ea7/+8ea8`; reach the draw if AL==0 or `m+8ea9==ffh`. `R(20)` at `007104cd` equal 0 and `slot+10d==0` choose loop `00710778`; otherwise continue.
3. **State5 distance gate.** Require nonowner, byte `m+1ab+signed8(s)==5`, and tactical low bit clear (`007104e7..0071051b`). Side0 reads the original float32 grid at `00a15e44`, indexed by `9*signed8(low8(abs(signed8(y)-11))) + signed8(low8(abs(signed8(x)-4)))`, x/y=`slot+102/+103`. Nonzero side calls `006f09b0(4,0)` at `00710560`. The selected distance is stored float32. Draw `R(12)` at `0071056b`. Only an ordered strict draw>distance proceeds; equal, less and unordered continue at `007105a1`. Then draw `R(10)` at `0071058e`; signed8 `slot+10d < draw` chooses loop `00710837`.
4. **Existing byte flag.** Nonzero `slot+2b` and slot!=owner choose loop `007108f1` (`007105a1..007105b4`). Its only subsequent direct write is `slot+198=67h`, then return. This route is excluded on the initial action33 scan entry by the caller's eligibility test.
5. **Owner continuation.** If slot==owner at `007105c0`, execute loop `007105dc`, then `007109f0(0)` at `00710654`. Clear match byte `+1a7` at `0071065f`, then re-read owner and other state after return. Return if slot is still owner, slot word `+198==6dh`, slot byte `+2b!=0`, match byte `+8eb2!=0`, or slot byte `+107==0` (`00710666..007106a7`). Otherwise truncate x87 float32 `slot+7d` through `00945640`, draw `R(converted)` at `007106b6`, then `R(5)` at `007106bf`. Signed first draw>second jumps at `007106cf` back to `007103e8`, repeating entry checks with the updated state. No fixed retry count is established.
6. **Remaining nonowner dispatch.** At `00710975..007109cb` repeat the side/region decision without `R(20)` or the `+10d` test. Opposite-side state, AL==0 from `006cb960`, or `m+8ea9==ffh` choose `00714d40` at `007109df`. Own-side state, same-side `m+f57a`, or AL!=0 with `m+8ea9!=ffh` choose `00713fc0(1)` at `007109d1`. Both return to a plain helper epilogue. The temporarily forced5 in the action33 caller satisfies the !=ffh test if no admitted dependency changes it; it does not by itself select one target.

The three tactical lookups are separate calls at `007103fb/00710466/00710510`. The two region lookups are separate calls at `007104b9/007109bb`. Treating them as cached pure predicates requires evidence about their effects and the state between calls.

## Five candidate loops and direct writes

Each loop initializes a byte index 0 and runs only while it is less than the signed byte `slot+101`. It obtains a candidate pointer from `slot+1ae+4*index` and calls `006bce20` with ECX=match and stack `(candidate, x low byte, y low byte)`. Only nonzero AL draws `R(900)`. It snapshots signed bytes `slot+107` and `slot+104` before that draw; if their signed product<=50+draw, call `00714d40` on the candidate pointer. It re-reads the signed count for each loop continuation. Mutation/alias effects can therefore change later iteration behavior. Upper bits of pushed coordinate registers are not established as meaningful by this caller.

| Path | Loop entry / predicate / R(900) / candidate call | Direct tail after loop |
| --- | --- | --- |
| Owner continuation | `007105dc / 007105fd / 0071061b / 00710637` | `007109f0(0)`, byte match `+1a7=0`, post-return tests and possible retry |
| Initial float gate | `007106e4 / 00710705 / 00710723 / 0071073f` | Word slot `+198=67h`; return |
| R(20)==0 and +10d==0 | `00710778 / 00710799 / 007107b7 / 007107d3` | Add -15 to word `+35`; word `+198=67h`; set byte `+2b=1` if zero; draw `R(5)` at `00710807`; x87 add 5+draw to float32 `+4d`; return |
| State5 distance/+10d gate | `00710837 / 00710858 / 00710876 / 00710892` | Word `+198=67h`; set byte `+2b=1` if zero; draw `R(5)` at `007108c1`; x87 add 5+draw to float32 `+4d`; return |
| Nonowner +2b!=0 | `007108f1 / 00710912 / 00710930 / 0071094c` | Word `+198=67h`; return |

The exact ten write sites and widths are retained in the compact evidence; word arithmetic wraps at 16 bits. There is no direct score-byte write in this owned function. Called routines may write additional state, consume RNG, change pointer relationships or fail to return. Neither the table nor the direct-call inventory certifies those transitive effects.

## Immediate large-callee boundaries

| Dependency | Owned call boundary | Observed normal return boundary |
| --- | --- | --- |
| `007109f0` (13,162 bytes) | ECX=current slot, one pushed dword 0 at `00710654`; result is ignored here | `00713bf6: ret 4`; caller re-reads owner/action/flags after return |
| `00713fc0` (3,226 bytes) | ECX=current slot, one pushed dword 1 at `007109d1`; result is ignored | All 16 exported returns use `ret 4`; caller exits immediately |
| `00714d40` (4,583 bytes) | ECX=candidate in five loops, or ECX=current slot at `007109df`; no explicit stack arguments; result is ignored | All 20 exported returns use plain `ret`; loops continue or helper exits |

These are ABI boundaries only. The larger functions' full control flow, RNG streams, state writes, dependencies and exception paths are open. The export-derived return inventory is independently checked at the listed original addresses; code hashes identify the declared source ranges without publishing them. The helper's owner continuation cannot be composed by substituting a constant return value for `007109f0`, since the caller explicitly reads its resulting memory state.

## Reproduction, checks and next admitted experiment

Run `scripts/extract_shot_helper_11.py PRIVATE_EXE --exports PRIVATE_EXPORTS_11 --output evidence/shot-helper-11-sites.json` using Python with Capstone 5.0.7. The script rejects a wrong specimen hash or decoder version, checks contiguous owned/selected caller decoding, validates every owned export address/direct call, checks loop/callee sites, verifies the exhaustive direct non-frame write inventory and widths, and checks the four relevant export digests/sizes against the coordinator manifest. It emits selected metadata and addresses only. Running without `--exports` omits native corroboration and large-callee boundary metadata.

The next original-instruction oracle must first admit or provide proven bypasses for `006c38c0`, `006cb960`, `006bce20`, `006f09b0` and each selected large callee. Capture slot/candidate/match aliases, all writes, coordinate/grid inputs, signed count/side state, x87 control, ordered RNG bounds and full RNG state. Include each direct exit, failed and passed comparisons, equal/unordered x87 cases, zero/positive signed counts, changing candidate state, and the post-`007109f0` retry. To omit this helper from an action33 oracle, prove the caller distance comparison fails under that oracle's actual frame and all intervening admitted dependencies. A live penalty reachability claim remains open.

The extractor and deterministic regeneration, wrong-hash rejection, JSON parsing, staged privacy review, `git diff --check`, and `npm run check` under Node 24 are the verification scope for this static addition. Retained numerical checks validate earlier primitives only. No new numerical equivalence, complete attempt, score formula or full match is claimed.

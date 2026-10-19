# R27-C — league caller and CRT sort boundary

`00682b30` still has the complete local **static** contract established in R10-C. This investigation verifies its unchanged body and maps the new local static contract of its sort callee `00945333`. The callee is a generic record sorter with two indirect comparator call sites, a small-partition helper and a byte-swap helper. No connected sort execution or TypeScript equivalence is claimed.

All addresses here are **virtual addresses** unless a file offset is explicitly labelled. The 7,192,576-byte PE32 `cm0102.exe` is pinned by SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline main is checkpoint-26 commit `495f3cbec7e95e3a7340fb75f5add400cf852396`. The private checkpoint-26 archive SHA-256 is `4acf11ca1ab79b275436c6365813904d87634436de1723ce24a2274f83a087c4`; selected native export manifest SHA-256 is `bbd00280029a738f4f4dfa6462c7d34a4379887626749d9f20eef20873655f14`, and exact-old preflight SHA-256 is `fb1be5075c72e92045f4d802f649665801d8ebc85b049a25e0f652e282f6015d`.

| Entry | File offset | Body | SHA-256 | PE/native instructions | Local CFG edges |
| --- | --- | ---: | --- | ---: | ---: |
| Existing R10-C `00682b30` | `00282b30` | 730 bytes | `74f00180f47f39e48344b4192ffe22dbfe17e4e86d8eaa2ba9964ade4c1a8222` | 215 | 230 |
| New `00945333` | `00545333` | 340 bytes | `356fe0ff196d09bb788da5a1ff7eb17bedc6ccea9bce6e749175988e6483ca7f` | 132 | 145 |

The [extractor](../scripts/extract_league_sort_27.py) checks the pinned PE, all six selected private export pairs, old native names/body sizes, every opcode and operand of both bodies, every local branch target, reachability and exact direct/indirect call sets. [Compact evidence](../evidence/league-sort-27-sites.json) retains branch edges, direct memory widths, selected sites and digests without redistributing body bytes or bulk decompilation. The existing `00682b30` span digest is identical to [R10-C's earlier digest](../evidence/league-boundary-10-sites.json); it is **not** counted as a new or upgraded static entry. Context-only pinned PE spans are `00945487` (78 bytes, SHA-256 `e9602fb435ba6e492a49997a9809e95763bc31dcb8f36acdd7a1bdd6620b72de`) and `009454d5` (44 bytes, SHA-256 `8cc073e4161c512ba0dc2a7bb381d401f4f08e67cba8d2176b495fd552a36df1`). No complete helper contract or native annotation is proposed in this lane.

## Caller/callback boundary

The R10-C caller takes a receiver in ECX and a borrowed table pointer at entry `[ESP+4]`. At `00682d1a..00682d27`, it sign-extends receiver WORD `+0x3e` to a DWORD count, pushes callback `006834f0`, row width `0x3b`, count and the allocated scratch base, then calls `00945333`. It restores its own 16 outgoing argument bytes at `00682d30`. A negative signed16 count would become a large unsigned count in the sorter; the caller's ordinary nonnegative-count invariant has not been proven. The scratch rows are 59 bytes wide; the caller's pre-sort peer aggregation, post-sort first-match key search, input row byte `+4` bucket writes and scratch release remain as in [R10-C](league-boundary-10.md). Its direct adjacent-row comparator call at `00682dd2` can decrement the bucket count. A different caller can later overwrite input row byte `+4`.

The callback `006834f0` is separately [mapped and bounded original-entry validated](league-comparator-26.md). It reads shared pointer `00b679fc` and a five-entry switch table outside its Ghidra body. Stable nonzero-key rows and stable shared rule bytes support a lexicographic interpretation, but zero-key rows produce a concrete equality-transitivity counterexample. The league caller has not established that all real rows satisfy the comparator's stable, nonzero-key domain. This matters to any claim about a final sorted order.

## `00945333` local contract

The entry reads four DWORD stack arguments: base at `[ESP+4]`, count at `+8`, element width at `+12`, callback address at `+16`. It returns with a plain `RET`; the caller removes 16 bytes. EBX, ESI, EDI and EBP are saved/restored. EAX is a working register and has no established semantic return value. The native decompiler's pointer-typed count is not a pointer argument: `CMP ESI,2` at `00945342`, unsigned `DIV` at `0094537b` and pointer arithmetic show a 32-bit count.

At `00945342..0094534f`, unsigned count below two or zero width exits before base dereference and without a callback/helper call. An active path has no null-base, null-callback, range overflow or mapped-memory guard. It computes the inclusive end pointer `base+(count-1)*width` with 32-bit arithmetic (`00945359..0094536d`), then rederives an element count by unsigned `(end-base)/width+1` at `00945375..0094537d`. Width is nonzero before the divide, but the ordinary array interpretation requires nonwrapping, mapped address arithmetic. The body does not prove that precondition for all callers.

For a computed count of at most eight, it calls `00945487(base,end,width,callback)` at `00945389`. The helper has an indirect comparator call and invokes the byte-swap helper `009454d5`; this body's apparent lack of direct row reads is therefore not a lack of row effects. For a larger interval, `009453b2..009453bc` chooses its midpoint and swaps that record with the base through `009454d5`, placing the pivot at base. Its left scan calls `callback(scan,base)` at `009453d8` while the signed result is `<=0`; its right scan calls `callback(right,base)` at `009453ea` while the signed result is `>=0`. These are exactly the two indirect calls in this body; both read the DWORD callback address at `[EBP+0x14]`. Record addresses are compared unsigned, while callback return conditions use signed tests. The crossed pair or pivot is swapped through `009454d5` at `009453ff` or `0094540a`.

The sorter then handles a residual interval and saves the other in two DWORD local partition arrays starting at `EBP-0x80` and `EBP-0xf8` (`0094542c..00945469`). A signed counter at `EBP-4` indexes those pending intervals, and `00945391..009453b0` pops one after a small interval finishes. The body also repurposes its own incoming argument slots `[EBP+8]` and `[EBP+0xc]` as cursors into those local arrays. Direct body memory reads are DWORD frame/stack accesses; direct writes are DWORD local, pending-array and repurposed argument-slot writes. The two `0094543f/41` and `00945460/69` store pairs write pending partition addresses, not record bytes. Implicit PUSH/POP/CALL/RET stack traffic is additional. The byte-swap helper performs record writes, outside this local body.

No explicit bound check protects the pending-array cursors in this body. A familiar quicksort interpretation is supported by the local control flow, but a proven stack bound, exact helper/indirect-callback effects for connected executions and all real input preconditions require separate work. The PE read-only helper spans alone do not validate the connected sorter.

## Execution boundary and reproduction

No TypeScript reconstruction was admitted for `00945333`: a faithful connected run must execute the two helper bodies, their comparator calls, the R26 comparator and its shared rule table while comparing callback order, every record mutation, stack/ABI effects and return state to original instructions. The R26 comparator oracle covers its own calls, not this sort invocation. A trivial early-return port would add no meaningful sort validation. The [findings](../evidence/league-sort-27-findings.json) keep this static status explicit. The [name-only proposal](../evidence/league-sort-27-annotations-proposal.json) suggests `FUN_00945333` → `cm0102_sort_records_with_callback_candidate` with its exact old 340-address body; it leaves R10-C's name/comment and all prototypes, bodies and structures untouched. The coordinator owns any canonical Ghidra change.

From this checkout root with the pinned private files:

```text
python scripts/extract_league_sort_27.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_27 --preflight PRIVATE_PREFLIGHT_27 --output results/league-sort-27-sites.json
python -O scripts/extract_league_sort_27.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_27 --preflight PRIVATE_PREFLIGHT_27 --output results/league-sort-27-sites-optimized.json
npm run check
```

The extractor uses explicit integrity gates under optimized Python. Normal and `-O` output must be byte-identical. `npm run check` verifies retained repository oracles and metadata; it does not execute this sort. Real league rows, complete ranking, fixtures, final standings and transitive callback effects remain outside this result.

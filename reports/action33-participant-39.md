# R39-B: participant provenance and the CRT heap boundary

The original staff lookup and slot store can supply the record pointer consumed by a **separate** `0062ed70` entry. Continuing that original machine beyond R32-B's stop advances all 80 synthetic cases to **pre-`0094bf49`, `KERNEL32.dll!HeapSize(0,0,0)`**. No Windows call executes. The lookup global remains zero; no initialized lookup object, completed placement, resolver continuation, effect return or live state has been produced.

The pinned PE32 x86 specimen is SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses here are virtual. The [oracle](../evidence/action33-participant-39-oracle.bin) separately records raw-file offsets and range digests. The baseline is `58f3033`. Private executable/native exports are read-only; no native annotations or shared queue, runner, atlas or frontier are changed.

## Exact participant producer and lifetime

The following producer contracts are established by [R30-D](action33-state-30.md), [R31-B](action33-lifecycle-31.md) and [R32-B](action33-slot-32.md). This unit regenerates and matches the complete represented R32-B prefix for each case before advancing its status call.

| Link | Original source and width | Validity and ownership |
| --- | --- | --- |
| Staff storage | `00528540` allocates `0x6e * count`, stores count at `00ae2364` and the returned base at `00ae23bc` (`00528d25`). Another allocation replaces the base at `00529e07`. | Selected loader ranges, not a loaded database. The record storage belongs to the database allocation. |
| Staff lookup | `008968f0` selects a DWORD ID from `tactics->table + 0x91*row + 2 + 4*index`; it computes `00ae23bc + 0x6e*ID`. | Original admitted callees return a pointer in the synthetic domain. The final calculation has no independent upper-ID check. Valid table, count, record and attribute storage remain prerequisites. |
| Placement wrapper | `006e0d00`, ECX=manager, uses signed argument-1 low byte 0..19, computes `manager->slots + 0x1be*index`, and calls `006eaea0`. | Three caller DWORDs; `RET 0x0c`. The five outgoing DWORDs are `(manager+0x12 value, record, manager+0x18 low byte with preserved upper bits, original arg1, original arg3)`. |
| Borrowed record store | `006eaead` takes entry argument 2 into EBP; `006eaecb` stores EBP as a DWORD at slot `+0x69`. | This aliases the lookup result. It does not allocate, copy, retain or transfer ownership of the staff record. |
| Borrowed attribute store | `006eaed3` reads record DWORD `+0x61`; on the nonnull branch `006eaeda` writes that value to slot DWORD `+0x6d`. | The two pointer roles differ. Null attributes select a separate fallback; this unit uses the existing nonnull domain. |
| Initial slot state | `006eada0` originally zeros slot DWORDs `+0x69/+0x6d/+0x19e` and BYTE `+0x27`. | Caller-owned slot storage. The enclosing constructor statically uses 40 elements of stride `0x1be`; it has not executed here. |
| Consumer | `006cfeb8` loads slot DWORD `+0x69`; `006cfebb` loads ECX from global `00b63d28`; `006cfec1` pushes the record; `006cfec2` calls `0062ed70`. | Static effect-call context from R30-D. This instruction sequence is not reached by this unit's separate-entry fixture. |

`006eaea0` uses ECX=slot and five DWORD arguments, ending with `RET 0x14`; the placement oracle still stops before `006eaf8f` reads match `+0x4792`. It has not completed or returned. Subsequent placement may update existing slot state, so rerunning initialization before every replacement is not an established lifecycle.

The staff base/count teardown is concrete: `00528080` calls `009452ca` on the base at `00528172`, then clears base and count at `0052817a/00528180`. References also become invalid if the base is replaced. No match shutdown order or relocation of existing slot aliases has been established. A saved numeric staff ID alone is insufficient evidence for a valid runtime pointer.

## Lookup object publication, contents and destruction

`00b63d28` is loader-zero in the PE's virtual `.data` tail. R30-D's encoded-reference census identifies these three direct absolute stores; it does not exclude computed or bulk writes:

| Site | Original production or destruction | Execution status |
| --- | --- | --- |
| `00829325` | Setup `00828110` allocates `0x2c` bytes through `00944cf1`, calls `0062a680` with ECX=allocation and argument zero, then publishes returned EAX. A null allocation publishes zero. | Static caller range. |
| `0082c35b` | Setup `0082a9c0` allocates the same size and calls `0062a680`, forwarding EDI as its argument. | Static caller range; EDI's complete file/input production remains unresolved. |
| `00830102` | Teardown `0082ff40` calls `0062a8a0`, releases the receiver through `00944c94`, then clears the global. | Static range. The pointer is not valid after release. |

Constructor `0062a680` takes ECX=44-byte receiver, preserves it in EBP and returns it in EAX with `RET 4`. Before member initialization it calls `GetLogicalDriveStringsA` at `0062a6b1`, then queries drive types and probes a file. R31-B's original-entry evidence stops before the first drive query. Supplying an OS return, drive string, allocation or file handle would cross this unresolved boundary.

On the later static path, `0062a7c7` stores a separately constructed member at `+0x0c`. `0062a846..0062a860` zero DWORD members `+4,+8,+0x10,+0x14,+0x18,+0x1c,+0x20,+0x24,+0x28`. **This range does not initialize member `+0`.** Nonzero entry input reaches load helper `0062ab00`; zero input or failed load reaches new-state helper `0062cf70`. Global publication follows constructor return, so the allocated 44 bytes or that zeroing range alone cannot supply a valid lookup object.

The new PE-only static ranges resolve the missing `+0` allocation source:

- `0062cf76..0062cf91` read DWORD `00ae2364`, compute `31*count` in 32-bit arithmetic, and pass it to `00944e46`; `0062cf9b` stores the allocation result at receiver `+0`. No independent size/overflow validity is established here.
- On allocation success, the loop advances staff records by `0x6e` and lookup rows by `0x1f` (`0062d0f5/0062d0f8`). It copies date state through `00417c10`, writes row WORDs `+8/+0x0a=10000`, WORD `+0x0c=0`, DWORD mapping `+0x0e=-1`, DWORDs `+0x14/+0x18=-1`, and selected bytes. Nonnull attributes cause original RNG calls and can reach `0062d140/0062d250`. These calls and table data remain unexecuted here.
- The load path likewise computes `31*00ae2364`, allocates through `00944e46` at `0062abe6`, and stores receiver `+0` at `0062abf0`. A separate allocation at `0062ad0a` supplies receiver `+4` at `0062ad16`, using `48*[EBP]`; the provenance and validity of that load-time count are not closed by this local data flow.

`0062ed70` takes ECX=lookup object and one record argument, returning with `RET 4`. A null record reaches diagnostics; a signed record index at least `00ae2364` returns zero. Otherwise it calls `0062c680`, then reads DWORD mapping `rows + 31*index + 0x0e`; `-1` returns zero and other mappings yield `records + 48*mapping`, using object `+0/+4`. Negative indices, allocation validity, mapping bounds, date freshness and refresh effects require original producer state. Nulling or inventing those members is not an admitted success path.

Destructor `0062a8a0` conditionally releases members `+0,+4,+0x10,+0x1c` through `009452ca`; `+0x0c` and `+0x28` receive their own destructor/release calls. These selected native instructions establish owned-member release dependencies, not a safe post-destruction state or an observed lifecycle.

## New original execution and the first blocker

Each of the 80 cases repeats the existing slot initializer, the actual staff lookup and its four callees, placement to pre-`006eaf8f`, and the separate original status entry to pre-`00946214`. All 25,280 prefix instruction steps, ordered-memory digests, call frames and complete region digests must equal the retained R32-B records. The status argument is read from the **original-produced slot `+0x69` store**, and ECX comes from the unchanged loader-zero lookup global. Preparing a separate entry frame is explicit synthetic fixture setup; the resolver is never entered.

From the suspended status machine, execution continues without resetting registers, flags, stack, x87 or memory:

| Instruction path | Observed effect |
| --- | --- |
| `00946214 -> 0094bef1` | Original CALL enters with exit-list base argument zero from `00de4638`. |
| `0094bef6` | Read DWORD heap mode `00de4404=0`; the mode-3 and mode-2 branches are bypassed by original comparisons. |
| `0094bf3e` | Push the original block argument, zero. |
| `0094bf41` | Push flags zero. |
| `0094bf43` | Read DWORD CRT heap handle `00de4400=0` and push it. |
| pre-`0094bf49` | Stop before indirect IAT call `009670dc`, independently resolved from the pinned import directory to `KERNEL32.dll!HeapSize`. |

This adds **14 steps and 11 ordered memory events per case: 1,120 steps and 880 events**. The eight stack DWORD writes are independently reconstructed and compared against the complete 64 KiB stack. All fourteen other represented regions are unchanged. Complete integer registers, EFLAGS and observed x87 control/status/tag values are checked at both boundaries; the inherited emulator x87 defaults are not claimed as a game control word. No RNG call occurs in this extension.

The next blocker is therefore an actual Windows/CRT initialization boundary, with pending status, refresh, registration and heap-size calls. It is not a demonstrated null-object fault. In this execution the lookup object has still not been dereferenced.

PE-only startup evidence identifies the missing producers: `00948aeb` prepares `HeapCreate` at IAT `00967110`, stores the returned handle to `00de4400` at `00948b04`, and stores the mode returned by `009489a3` to `00de4404` at `00948b13`. Exit-list initializer `0094628c` requests `0x80` bytes through `00944e46`, publishes the returned base at `00946299`, zeros its first DWORD and sets end `00de4634` at `009462b5`. These startup routines have not executed in this fixture. Executing `HeapSize` with loader-zero state, fabricating its return or setting the initialization flags would not establish that lifecycle.

## Evidence checks and reproduction

The [extractor](../scripts/extract_action33_participant_39.py) reuses the hash-pinned R32-B native inputs and performs **875 inherited PE/native instruction comparisons**. The five new ranges have **819 PE-only instructions**, including unexecuted branches; there is no focused native export for them. Their exact specimen bytes are pinned by PE hash and per-range hash, Capstone 5.0.7 decodes their complete lengths, and 23 independently authored operand/source checks cover critical branches, allocations and stores. This distinction is retained in every new range record. No new whole-body semantic or TypeScript claim is made.

The [verifier](../scripts/verify_action33_participant_39.py) regenerates the oracle under normal Python and `-O`, checks byte identity, and uses explicit exceptions for integrity gates. Fourteen negative probes cover the specimen, inherited manifest, authored operand, executed wrong heap/mode sources, executed wrong participant store, native width mutation, late raw/hex excerpts, all three embedded base64 alignments and bounded gzip expansion. Privacy scans enumerate every 32-byte excerpt in each admitted range, all padding-free base64 alignments, both hex cases and the diagnostic source; they scan the compressed/expanded oracle, receipt and all four authored task files. Private instructions, diagnostic strings, original tables, exports and memory pages are absent from public evidence.

```text
python -B scripts/extract_action33_participant_39.py PRIVATE_PE PRIVATE_STATE PRIVATE_STAFF PRIVATE_LIFECYCLE PRIVATE_SUPPORT PRIVATE_EXPORTS_25 PRIVATE_SLOT evidence/action33-participant-39-oracle.bin
python -B scripts/verify_action33_participant_39.py PRIVATE_PE PRIVATE_STATE PRIVATE_STAFF PRIVATE_LIFECYCLE PRIVATE_SUPPORT PRIVATE_EXPORTS_25 PRIVATE_SLOT evidence/action33-participant-39-oracle.bin evidence/action33-participant-39-validation.json
python -O -B scripts/verify_action33_participant_39.py PRIVATE_PE PRIVATE_STATE PRIVATE_STAFF PRIVATE_LIFECYCLE PRIVATE_SUPPORT PRIVATE_EXPORTS_25 PRIVATE_SLOT evidence/action33-participant-39-oracle.bin results/action33-participant-39-optimized.json
node scripts/check-action33-participant-39.mjs
npm run check
```

The [retained Node checker](../scripts/check-action33-participant-39.mjs) validates the prior R32-B checker, the complete prefix hashes, alias provenance, CPU, ordered operands, memory continuity, counters, static/source classifications and validation receipt. It includes independent semantic mutations. Task checker, normal/optimized reproduction, privacy/integrity checks and the full existing suite pass under Node 24.19.0. This task checker is intentionally unregistered in the coordinator-owned shared runner.

## Next usable producer input

A producer-backed synthetic domain needs both staff/tactics loading and the entire lookup constructor, including Windows, allocator, original-data and RNG state, **before** resolver entry. The first missing constructor input remains the drive-query boundary `0062a6b1`; admitting the heap-size helper does not solve it.

For a future authorized capture, useful publication points are after original `00829325`/`0082c35b` and before effect `006cfeb8`: correlate object identity and owned row/cache extents, staff base/count/attribute allocation identity, selected slot aliases, date/static flags, CRT heap and exit-list state, original RNG order/state and thread x87 state. Preserve the original setup-to-match lifetime and detect intervening replacement/destruction. Capturing only the two pointer values cannot certify their referents. No process probing or capture was performed here; R30-B's 160-case null domain and R39-A's connected resolver domain remain separate.

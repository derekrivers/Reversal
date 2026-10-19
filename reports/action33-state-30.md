# R30-D: action33 participant and lookup-object provenance

The null value read from shooter `+0x69` in R30-B is an omitted initialization dependency in the synthetic fixture. There is an original producer: `006e0d00` passes a roster record to `006eaea0`, which stores that pointer at slot `+0x69` and, on its nonnull attribute branch, copies record `+0x61` to slot `+0x6d`. The separate global `00b63d28` is assigned from a 44-byte object constructor on two setup paths. Neither original producer ran in the R30-A/B fixture. Supplying two arbitrary nonnull pointers would not establish the original state or its lifetime.

This investigation uses the PE32 x86 specimen SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses are virtual unless explicitly labelled PE file offsets. It provides selected static provenance and **80 synthetic original-entry producer prefixes**, not a complete constructor, live roster, returned participant effect, or shot outcome. No TypeScript behavior or shared semantic/validation registry is added.

The [extractor and producer harness](../scripts/extract_action33_state_30.py) and [compact evidence](../evidence/action33-state-30-evidence.json) pin all inputs. Fresh native exports were obtained read-only without reanalysis from a separate checkpoint-28 extraction, archive SHA-256 `ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a`. The three private manifests are `b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a`, `c6457fcd1b68d524d2d4ce623d144e77a3e5ae23c9a4699e157b9ec2181f7b35`, and `83d24d0790139ab37f7e3c82e12dfff9844456a8273e8d5ee10d1036359c7daf`. Existing R24 path-split and R25 status-lookup exports are separately hash pinned. Every instruction and operand in each retained range is compared with its native export; range sizes, PE offsets and hashes are retained without executable bytes or full listings.

## The observed continuation boundary

R30-B separately continued the same 160 R30-A original machines from `007024b4` through the two entry RNG groups to the stop before `0062ed99`. This unit consumes that supplied boundary; it does not rerun or adopt R30-B's execution claim.

The causal instructions are independently checked here: `006cfeb8` reads the participant's DWORD `+0x69`, `006cfebb` loads ECX from `00b63d28`, and `006cfec2` calls `0062ed70` with the record pointer. R30-B observes both values as zero. In `0062ed70`, the stack argument is loaded into EDI at `0062ed78`, and `0062ed81..0062ed83` select the diagnostic route when it is null. ESI saves ECX at `0062ed7f`, but the null route does not dereference that lookup object. The null participant reference therefore explains this diagnostic stop independently of the zero global.

For a nonnull record, `0062edee` reads its signed DWORD index and `0062edf0..0062edf7` compare it against global count `00ae2364` with signed `JGE`. An index at least the count returns zero without dereferencing the lookup object. An admitted lower index reaches `0062edfc -> 0062c680`, then reads mapping `object->rows + 31*index + 0x0e`; mapping `-1` returns zero, otherwise the return is `object->records + 48*mapping`. Negative indices and invalid object storage are not independently guarded. This remains the earlier static R25 contract; normal refresh behavior is not executed here.

## The slot reference is produced from a roster record

| Link | Exact original evidence | Scope |
| --- | --- | --- |
| Tactics lookup | `006dbbb1` loads manager `+0x2f`; `006dbbb7` loads ECX from `00de1d08`; `006dbbbd -> 008968f0` returns EDI | Static selected caller range |
| Lookup filtering | `006dbbc4` tests EDI; `006dbbcf -> 0062c400` checks it, with AL=2 skipped at `006dbbd4..006dbbd6` | Static caller context; callees not executed |
| Slot placement | `006dbc15..006dbc1a` pass `(index, EDI, index)` to `006e0d00`, ECX=manager | Static selected call site |
| Slot address | `006e0d00` uses the signed low byte of argument 1, admits 0..19, reads slot-array base from manager `+0x23`, and computes `base + 0x1be*index` at `006e0dca..006e0ddb` | Original producer prefix also executed |
| Reference store | `006e0dde -> 006eaea0`; at `006eaead`, EBP receives the second entry argument; `006eaecb` writes it as a DWORD to receiver `+0x69` | Original producer prefix also executed |
| Attribute alias | `006eaed3` reads DWORD `[record+0x61]`; when nonzero, `006eaeda` stores it at receiver `+0x6d` | Original nonnull branch also executed |

`006e0d00` is a thiscall-shaped wrapper: ECX is manager and three caller arguments are removed by `RET 0x0c`. Its second argument is tested for null before placement (`006e0d9e..006e0db2`). For valid input it calls `006eaea0` with ECX set to the selected slot and five DWORD arguments: manager `+0x12`, the same roster pointer, a DWORD whose low byte comes from manager `+0x18`, the original first DWORD, and the original third DWORD. Upper argument bits are not normalized. `006eaea0` consumes five arguments (`RET 0x14` at `006ebd57`); this unit stops before its return.

The `+0x69` and `+0x6d` values are distinct pointer roles. The former aliases the roster/staff array record; the latter aliases that record's attribute pointer. The constructor's initial prefix neither allocates these records nor transfers ownership. If record `+0x61` is zero, `006eaedf..006eaf43` enter a formatting/RNG fallback and select an attribute record from a different global. That fallback is static here and is excluded from the 80 executed prefixes. The subsequent test of slot `+0x69` at `006eaf46` is the execution stop.

## Where the roster pointer comes from, and when it expires

`008968f0` takes ECX=tactics manager and three stack arguments, ending in `RET 0x0c`. Its first argument must be nonnull, and the signed low byte of its second argument is checked for 0..19. It passes the first and third arguments to `008982b0` at `0089695c`. A returned row number other than `-1` selects the table rooted at tactics manager `+0x601`: the row stride is `0x91`, and the roster ID is read as a DWORD at `row + 2 + 4*index` (`00896972..00896989`). Only signed IDs greater than `-1` proceed.

`00896996..008969a4` multiply that ID by `0x6e` and load staff-array base from `00ae23bc`. A nonnull DWORD at `base + 0x6e*ID + 0x61` is required. A null value rewrites the tactics-table ID to `-1` at `008969b1` and returns zero. The additional `0053b900`/affiliation path can also invalidate the entry at `008969fe`. The success exit returns `00ae23bc + 0x6e*ID` at `00896a14`. There is no independent upper staff-ID bound at that final address calculation. Table and database validity remain required caller state.

This gives a concrete source for `+0x69`; its lifetime depends on the staff-array allocation. The selected `00528540` load range stores a count in `00ae2364`, multiplies it by `0x6e`, passes the size to `00944e46`, and assigns EAX to `00ae23bc` at `00528d25`. A separate allocation result replaces that base at `00529e07`; this unit does not infer its size from the untraced incoming stack value. Teardown `00528080` zeroes ESI at `00528086`; if the base is nonzero, `00528172` calls `009452ca` on it, then `0052817a` and `00528180` clear base and count. Release semantics remain external. Retaining a slot reference across release or replacement of its backing array is not an admitted lifetime. Match shutdown order, relocation of saved IDs, and indirect or bulk slot copies are still unresolved.

`008982b0` is the next dependency for producing the row through the original caller: it unconditionally invokes `00600a50` at `008982c8` before its later row-selection logic. This unit has not supplied or executed that call chain. The staff/tactics database loader `00528540` also remains a selected-range finding rather than a complete initialized-database oracle.

## `00b63d28` has an independent setup and teardown

The global is in the zero-filled virtual tail of `.data`: section VA `00987000`, raw size `00153000`, virtual size `0045d63c`, global delta `001dcd28`. It has no PE raw backing. Its initial loader value is zero; this is not evidence that an initialized game should retain zero. R30-A/B mapped that image and supplied synthetic match state without executing game initialization.

The extractor searches the raw `.text` bytes for the little-endian global address. It finds 299 encoded occurrences and confirms three direct absolute write instructions against the selected native ranges. This is an encoded-reference census, not proof that no computed-address, bulk or alias write exists.

| Store | Local producer and lifetime evidence |
| --- | --- |
| `00829325` | `00828110` pushes `0x2c` to `00944cf1`, passes the allocated pointer in ECX to `0062a680` at `00829313` with a zero argument, then stores returned EAX. The local zero register is restored at `0082876e`. Null allocation takes the explicit zero-result branch. |
| `0082c35b` | `0082a9c0` also allocates `0x2c` and calls `0062a680` at `0082c348`, forwarding EDI as its argument. The producer of that incoming EDI/file state is not closed here. |
| `00830102` | `0082ff40` has EBX=0 from `0082ff4f`. For a nonnull global it calls `0062a8a0` at `008300f4`, calls `00944c94` at `008300fa`, then stores zero. Destructor/release behavior and exception paths are not executed here. |

`0062a680` preserves its receiver in EBP and returns it in EAX with `RET 4`. Its **first external call**, `0062a6b1`, is an indirect import through `009670f8`, resolved from the PE import table to `KERNEL32.dll!GetLogicalDriveStringsA`; the call receives `(0xc8, local_buffer)`. Later `0062a6ca` calls the import at `00967100`, `GetDriveTypeA`, and compares its result with numeric type 5. File probing, a loop and diagnostics precede normal member initialization. None of these OS or file effects is stubbed or executed by this unit.

After that work, the constructor's final selected range initializes members and tests its one entry argument. A nonzero argument is passed to `0062ab00` at `0062a868`; a zero argument or failed load reaches `0062cf70` at `0062a873`. Those load/new-state callees, their allocations and RNG, and the preceding OS boundary are required to establish an initialized lookup object. A fabricated 44-byte object would skip these dependencies. `0062a8a0` later releases several owned members through external helpers; its receiver body is not safe evidence of a live object after teardown.

## The diagnostic call is path splitting, followed by more diagnostics

The five caller-cleaned DWORDs at `0062ed99 -> 00944cff` are `(source=009e7f28, drive=0, directory=0, basename=E-0x100, extension=E-0x200)`, where E is `0062ed70`'s entry ESP. They point to the two 256-byte local buffers, not heap allocations. At R30-B's stop the corresponding actual values are `[009e7f28,0,0,02007824,02007724]` with ESP=`02007708`. The callee has not yet executed there.

`00944cff` is the earlier R24 path-splitting body with five stack arguments and plain `RET`. Its first transitive call is `00944d0e -> 009488e0` (`_strlen`) on the original source pointer. That is the next original instruction dependency if continuing the **diagnostic** branch. Later it scans the original string using the lead-byte table at `00de4521` and calls `00948851` for nonnull output copies. Those original source bytes and tables must remain private. This unit retains only the source address, NUL-inclusive size 41 and SHA-256 `c326a371dc9f4b8f72f6d05333078049b422d476a96c8a57c02255b7cb34d1a1`.

Returning from the splitter would still leave `0062edb3 -> 0090d130`, `0062edc3 -> 00944c9f`, and `0062edd3 -> 005e8290`; only afterward does the local code store `00b67a34=0` and return zero. Prior bounded `_strlen` and copy oracles do not establish this connected diagnostic execution or its external presentation effects. Continuing diagnostics would not provide a normal participant status record.

## Executed producer scope and reproduction

The new oracle runs **80 original-entry `006e0d00` prefixes**: indices 0..19, four deterministic synthetic seeds, nonnull mapped roster pointers and nonnull record `+0x61` values. Manager `+0x18` contains `seed`, while the wrapper's forwarded third argument is `0x89abcd80 | seed`. Thus the outgoing third DWORD is `0x89abcd00 | seed`, and the outgoing fifth DWORD remains `0x89abcd80 | seed`; their low bytes differ in every case. The initializer's slot `+0x2e` receives that fifth argument's low byte, `0x80 | seed`. This distinguishes both argument provenance and the observed byte store. The original wrapper executes its actual CALL into `006eaea0`, with no callee stubs or fabricated return. It stops before `006eaf46`, after 46 instructions per case, **3,680 total**. It checks the outgoing receiver and all five raw arguments, the pointer/byte stores, and all six admitted data/stack regions against independently assembled expected memory, including original stack PUSH/CALL/local-write effects. Only digests of complete regions and traces are retained. No full final-register ABI equivalence or TypeScript comparison is claimed. These synthetic records do not establish valid staff IDs, tactics row selection, database loading, remaining slot initialization or live match reachability.

The actionable next input work is to connect `008968f0` and its `008982b0 -> 00600a50` row-selection path to the staff/tactics database, then run slot placement and the remaining initializer before resolver entry. The lookup-object work has an independent first external boundary at `0062a6b1`; after it, load/new-state initialization must be admitted before the normal refresh path. The current null fixture remains a valid diagnostic-frontier observation.

Run from the worktree, with the pinned private inputs:

```text
python -B scripts/extract_action33_state_30.py PRIVATE_PE PRIVATE_STATE_EXPORTS PRIVATE_EXPORTS_09 PRIVATE_EXPORTS_24 PRIVATE_EXPORTS_25 PRIVATE_STAFF_EXPORTS PRIVATE_LIFECYCLE_EXPORTS evidence/action33-state-30-evidence.json
python -B scripts/verify_action33_state_30.py PRIVATE_PE PRIVATE_STATE_EXPORTS PRIVATE_EXPORTS_09 PRIVATE_EXPORTS_24 PRIVATE_EXPORTS_25 PRIVATE_STAFF_EXPORTS PRIVATE_LIFECYCLE_EXPORTS evidence/action33-state-30-evidence.json evidence/action33-state-30-validation.json
node scripts/check-action33-state-30.mjs
npm run check
```

The verifier reproduces the entire evidence byte-for-byte under normal Python and `-O`, rejects a changed PE, changed manifest, resealed native store operand, executed wrong store and swapped third/fifth call arguments, and checks that the original diagnostic source is absent in raw, hex and base64 form. The argument mutation reaches the ABI provenance gate independently of artifact hashes. Its normal and optimized validation receipts are also byte-identical. There are 25 selected ranges with 538 PE/native instruction comparisons. All integrity gates use explicit exceptions. [Validation](../evidence/action33-state-30-validation.json) records the retained evidence hash. Original source strings, native exports, PE bytes and memory pages remain outside Git. Canonical native state, queue, atlas and checkpoints are unchanged.

After integration with `origin/main` at `2c1a5212918c95924364eb0d67da577c48782525`, the [retained checker](../scripts/check-action33-state-30.mjs) is registered in the shared research runner. It pins both evidence and validation-receipt hashes, checks exact nested schemas, cross-checks counts and provenance, verifies the synthetic case schedule and raw argument widths, and preserves the explicit static-only and stopped-before-return limits. Its third/fifth argument mutation also reaches the exact ABI provenance check independently of artifact hashes. This public check does not emulate original instructions or reconstruct live state. `npm run check` passes under Node 24. Mutating the retained case's return flag or either receipt status/negative-probe list is rejected by the corresponding hash gate.

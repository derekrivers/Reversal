# Investigation 11: league credit target and finance array boundary

The arithmetic league-credit path now resolves to a borrowed **359-byte (`0x167`) finance row** inside an allocated array. `005999a0` updates two DWORD accumulators and one 64-bit accumulator in that row. The array constructor and optional `finance.dat` loader explain the pointer used by this path. This is static evidence for four functions, not a recovered finance subsystem, currency convention or completed transaction.

All addresses are **virtual addresses**, except explicitly labelled file offsets. The read-only PE32 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Research starts at `2c6bb83f13c92a3f9d2309e71e5e77aac7715383`. `009c8784` anchors `E:\dev\CM3\cm3 00-01\cm3\code\finance.CPP`; this corroborates source ownership, not original function or field names.

| Entry | Inclusive inferred body | Entry file offset | Instructions | Assembly contract |
| --- | --- | --- | ---: | --- |
| `005a0590` | `005a0590..005a0647` | `001a0590` | 60 | ECX holder, one record-pointer argument; EAX row pointer or zero; `RET 4` |
| `005999a0` | `005999a0..005999d3` | `001999a0` | 17 | ECX row, one signed32 amount; `RET 4`; no semantic result established |
| `0059a370` | `0059a370..0059a59a` | `0019a370` | 164 | ECX holder, one raw32 optional load context; returns holder; `RET 4` |
| `0059b2a0` | `0059b2a0..0059b3ae` | `0019b2a0` | 78 | ECX holder, one raw32 load context; EAX exactly 0/1; `RET 4` |

These have thiscall-style evidence. Argument widths follow loads and `CDQ`, not inferred decompiler types. No native prototype or structure replacement is proposed.

## Target resolution and ordered mutation

On the weighted arithmetic path of `00682e10`, the amount remains on the stack while row +0 from its 59-byte league table is pushed as a record pointer. At `00682f12`, ECX loads the holder from `00ae2a38`; `00682f18` calls `005a0590`. Its `RET 4` consumes only the record pointer. EAX is moved to ECX at `00682f1d`, and `005999a0` consumes the outstanding amount at `00682f1f`. There is no row-pointer null test between these calls. The selector-3 registry/vtable path documented in [investigation 10](league-boundary-10.md) is separate; its concrete dispatch target remains unresolved.

`005a0590` rejects a null record: it emits diagnostic constant `0x20b5`, clears DWORD `00b67a34` and returns zero. The holder and its array pointer are not checked. For a nonnull record, it calls `00540a50(record, &flag32, 1)` at `005a0616`. It substitutes returned EAX for the record **only when EAX is nonzero and the output DWORD flag is zero** (`005a061e..005a062a`). Otherwise it retains the original record. The local flag is only read when EAX is nonzero; there is no local preinitialization in this resolver.

The effective record's first **DWORD**, loaded at `005a062c`, is the row index. The LEA/shift/subtract sequence at `005a062e..005a0637` computes `index*359 modulo 2^32`. The result is added to the **DWORD pointer at holder +0** (`005a0639..005a063c`). No count, sign, index bounds or pointer-validity guard occurs here. The result is an interior pointer into the array on valid inputs; it is neither a new allocation nor a transferred owning pointer.

Supporting inspection of `00540a50` establishes why normalization cannot be treated as a pure identity lookup. It reads a pointer at record +0x53 and, for the supplied nonzero third argument, tests byte +0x244. Its mapped branches write output flag 0 at `005412a7` or 1 at `0054187c`. Successful mapped pointer formation uses `00ae23b4 + mapped_index*0x245` at `00541e42..00541e52`. Failure branches at `00541861` / `00541e32` can **clear the input record's byte +0x244** before returning zero. The resolver then falls back to the original record. The helper's global mapping tables, complete admissible domain and semantic record relationships remain dependencies; no complete helper contract is claimed.

`005999a0` reads the argument as a **DWORD amount**, then performs these stores in order:

1. `row+0x148 = old32 + amount32 modulo 2^32` at `005999b5`.
2. `row+0xa8 = old32 + amount32 modulo 2^32` at `005999bb`.
3. Low DWORD `row+0` is updated at `005999c6`; `CDQ` at `005999c3` and `ADC` at `005999cb` then update high DWORD `row+4` at `005999ce`. Together this is `old64 + sign_extend_64(signed32(amount)) modulo 2^64`.

The helper allocates nothing, calls nothing and has no amount-sign, overflow, duplicate-application or null guard. Negative signed amounts subtract from the 64-bit total; the DWORD operations wrap. These are arithmetic effects only. Field purpose, accounting category, units and transaction completion are unproved. The final EAX happens to hold the updated high DWORD; callers here supply no evidence that it is a success result.

## Holder creation and optional loading

`0059a370` has a prerequisite/retry prelude through `0059a39b..0059a46d`, involving drive enumeration and `004c0aa0`/`004c0c10`. It can loop through a prompt; reaching the allocation block is a precondition for the following bounded path. The complete external prerequisite is outside this contract.

At `0059a472`, the constructor reads raw DWORD count `00ae235c`, computes `count*0x167+4` in 32-bit arithmetic and calls operator-new-labelled `00944cf1`. There is no count/domain/overflow validation in this block. On nonnull allocation, it writes the saved count into the four-byte prefix at `0059a4b4`, and uses allocation+4 as the first row. Vector helper `009463af` receives `(rows,0x167,count,005961c0,005a8f60)` at `0059a4b6`. Supporting inspection shows its normal loop invokes `005961c0` once per row with ECX advancing by 359. The inspected `005961c0` is only `MOV EAX,ECX; RET`; `005a8f60` is a single `RET`. **The allocation is not zero-filled by this constructor loop.**

The holder's DWORD +0 receives the row-array pointer at `0059a4ca`. Allocation failure stores zero there, emits diagnostic `0xf1d`, clears `00b67a34` and still returns the original holder at `0059a531`. Thus the returned holder pointer alone does not certify a populated array.

For a nonnull array and nonzero optional argument, `0059b2a0` is called at `0059a55c`. Return 1 skips the fallback loop. Zero optional argument or return 0 enters per-row initialization: ECX starts at holder +0's array pointer; the argument starts at `00ae23b4`; `005961d0` is called at `0059a57a`. The array advances by `0x167`, the source records by `0x245`, and the loop uses signed positive/current-count tests against `00ae235c` (`0059a575`, `0059a57f..0059a593`). The initializer's transitive effects remain open. Its success is not independently tested here.

`0059b2a0` returns 0 without diagnostics for a null argument. Otherwise it calls `009326e0(context, "finance.dat", 0, 0x16, 4)` at `0059b2c1`; the string is at `009c87b0`. The context's complete type and container semantics are unresolved. For a nonzero returned stream pointer it calls the previously inspected custom read helper as `00932c30(holder[0],0x167,count,stream)` at `0059b312`. This **writes into the existing array**; supporting write site `00932cc6` and alternative ordinary-read call `00932df7` corroborate direction, as in [investigation 09](database-boundary-09.md).

The requested count is loaded at `0059b302`; after the read, `00ae235c` is loaded again at `0059b317` and compared with returned EAX. Equality calls `00932b00(&stream)` and returns exactly 1. Supporting cleanup sites `00932c06`, `00932c16` and `00932c1e` close the underlying file, free the wrapper and clear the supplied local stream pointer. This releases the stream wrapper, **not the destination array**. Open failure and count mismatch emit diagnostics `0x1137` / `0x113f`, clear `00b67a34` and return 0. There is no direct close call on the nonnull short-read path in this body, no destination rollback and no record-content validation. A zero requested/rechecked count can satisfy count equality. The caller may subsequently overwrite rows through fallback initialization; this does not make the failed read atomic.

## Ownership, callers and remaining boundary

The two verified direct callers of `0059a370` are `0082976f` in `00828110` and `0082c75d` in `0082a9c0`. Each allocates a **four-byte holder**, supplies that pointer as ECX and a single raw argument, then publishes the returned holder in DWORD `00ae2a38` at `00829781` / `0082c770`. Their selected sites establish the global-to-holder-to-array-to-row chain. These large setup callers also initialize other systems; the presence of transfer construction calls elsewhere in them does not establish a direct finance-transfer transaction or common completion condition.

The adjacent destructor-shaped helper `0059a5a0` is a **lifetime lead**, not an owned complete teardown contract. It reads holder[0], reads the prefix at rows-4, passes row stride `0x167` and `005a8f60` to `009462bb`, then frees rows-4 at `0059a5bf`. This agrees with the constructor's count-cookie allocation. This excerpt does not clear holder[0], and does not establish when callers invoke teardown or who releases the four-byte holder. Borrowed row pointers must therefore be treated as valid only while the owning array remains alive; actual replacement/teardown timing is unresolved.

The native reference lists contain 161 direct incoming calls to `005a0590`, 25 to `005999a0`, two to `0059a370` and one to `0059b2a0`. All 189 listed E8 calls were independently checked against the pinned image. This is an inventory of recognized direct references, not proof that unrecognized/indirect uses cannot exist. Only the selected league/setup call contexts are contracted here.

## Evidence and reproduction

- [Compact sites](../evidence/finance-boundary-11-sites.json): 319 decoded instructions compared completely with the coordinator's four read-only Ghidra exports, while retaining 120 owned instruction sites, 107 supporting caller/dependency sites, body/native-export digests and incoming call addresses. Inferred bodies exclude alignment padding.
- [Extractor](../evidence/finance-boundary-11-extract.py): SHA-pinned PE section mapping, `capstone==5.0.7`, exact native instruction comparison after documented spelling normalization, and direct-reference verification. It reads but never executes or changes the image.
- [Annotation proposal](../evidence/finance-boundary-11-annotations.json): candidate labels/comments with evidence and confidence, confined to the four owned bodies. Canonical Ghidra, shared queue/atlas/checkpoints and transfer bodies are coordinator-owned and unchanged here.

```text
python evidence/finance-boundary-11-extract.py PATH_TO_PINNED_EXE results/finance-boundary-11-sites.json --native-dir PATH_TO_PRIVATE_EXPORTS
```

The evidence was regenerated twice identically, and a synthetic wrong-hash input was rejected before PE decoding. `npm run check` passed with Node 24.19.0. Those checks validate existing numerical fixtures/metadata; they are not a runtime finance oracle. Original bytes, bulk listings, pseudocode, native exports and dependencies remain outside Git. Remaining uncertainties include allowed counts and indices, complete normalization mappings and initializer effects, array teardown timing, concrete registry dispatch, accounting meaning, currency, external notifications and full transaction completion.

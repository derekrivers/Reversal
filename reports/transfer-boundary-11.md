# Transfer manager construction boundary, investigation 11

`008bba30` constructs a `0x94a`-byte, partially packed receiver and chooses between a load dependency and fresh dependent construction. Every normal return supplies the original receiver, including allocation-error paths. A nonnull constructor result therefore does not prove that its internal allocations succeeded.

This is static research against SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`, baseline `2c6bb83f13c92a3f9d2309e71e5e77aac7715383`. Addresses below are virtual addresses; offsets beginning `+` are hexadecimal byte offsets within the receiver. The owned body is `008bba30..008bbe1a` (1,003 bytes; file offset `004bba30`). `008bc020`, `00828110` and `0082a9c0` supply immediate boundary evidence only. No complete transfer, money or persistence behavior is recovered here.

## Entry and caller contract

ECX is retained in ESI at `008bba4f`; the sole raw32 stack argument is read at `008bbd0d`. The routine returns ESI in EAX at `008bbe05`, restores EBX/EBP/ESI/EDI and FS:[0], and executes `RET 4` at `008bbe18`. It requires a writable receiver and initialized host/global dependencies. There is no receiver null or extent check. Exception registration and construction stages exist, but their unwind bodies have not been audited.

Both inventoried callers first request `0x94a` bytes through `operator_new`, check the allocation, and call with that allocation in ECX. Call site `008298b8` in `00828110` passes zero; EBP was last zeroed at `0082876e`. Call site `0082c854` in `0082a9c0` passes EDI, loaded from frame `ESP+1674` at `0082bb10` or `0082bb21`. Neither register is overwritten again before its call. Both callers publish EAX into DWORD `00de1f54` and test the pointer. Their complete setup and finance behavior remains outside this assignment.

## Construction and allocation sequence

The initial `009463af` call constructs 150 rows of 14 bytes from `receiver+18`, using callback `0068d020` and a `0068d040` destruction callback. The supporting loop invokes the constructor in ECX at each stride. `0068d020` clears WORD `+0` and DWORDs `+2/+6/+a`; this covers `[+18,+84c)`. The callback's destruction/unwind behavior remains open.

Before main scalar clearing, the routine enumerates drives through PE imports `GetLogicalDriveStringsA` and `GetDriveTypeA`. A type-5 candidate is formatted into a path ending in `cm0102.exe`; a zero return from `004c0aa0` admits initialization. A nonzero file-check result calls `004c0c10`; other drive types skip the file check. An exhausted list enters the insert-CD UI/retry loop. These two internal file helpers are not fully audited. The buffer capacity is 200, but the owned code only checks a nonzero API return/first byte, and advances a signed8 index by four. Arbitrary returned string lists and termination are not validated here. Host calls can keep the routine in the retry loop.

After the admitted drive check, the routine clears selected scalar fields, assigns a date-like embedded value through opaque helpers, clears BYTE `+855`, and calls `008d26b0(receiver)`. It then performs these steps in order:

| Step | Instruction evidence | Effect and failure path |
| --- | --- | --- |
| First allocation | `008bbc69..008bbc81` | `00945501(global32[00ae2364],8)` retained at DWORD `+86e`; null diagnoses source line 163, then reaches normal receiver return if diagnostic calls return. |
| Second allocation | `008bbcba..008bbcd3` | `00945501(global32[00ae235c],16)` retained at DWORD `+91c`; null diagnoses line 171. The owned body does not free the first allocation. |
| Load choice | `008bbd14..008bbd2c` | Set DWORD `+85e=-1`. Nonzero context calls `008bc020(receiver,context)`; nonzero EAX goes straight to normal receiver return. |
| Fresh fallback | `008bbd32..008bbd6b` | Absent context or zero load result allocates `0xe0`, calls `00839a80(allocation,0)` when nonnull, and stores its result at DWORD `+856`. Null diagnoses line 192. |
| Fresh followup | `008bbdf7..008bbdf9` | Nonnull `+856` result calls `008c6e60(receiver)` before normal return. |

The owned entry does not validate allocation counts or overflow. Selected allocator instructions show a 32-bit product and zero-fill paths, including a `HeapAlloc` import with flag 8. Its complete CRT allocation/retry policy remains a dependency. The main routine has no free call or explicit rollback. Allocation results are retained in receiver fields; destructor ownership and lifetime require separate evidence. Diagnostics also format shared buffers `00ae24d0`, `00ae28bc` and `00ae26c4`. UI/termination behavior of the diagnostic calls is unresolved.

## Instruction-supported partial layout

| Offset(s) | Width / extent | Supported construction fact |
| --- | --- | --- |
| `+0/+4/+8/+c/+10/+14` | DWORD each | Explicit zero stores after drive acceptance. |
| `+18` | 150 × 14-byte rows | Header initialization through the fixed constructor callback. |
| `+84c` | BYTE | Explicit zero. |
| `+84d` | 8 bytes | `0054a110` first writes WORD 0x28, WORD 0x7b4, DWORD 1; later `00417c10` receives this address. Final semantics depend on that call. |
| `+855` | BYTE | Explicit zero before `008d26b0`. |
| `+856` | DWORD | Dependent construction result on fresh path. |
| `+85e` | DWORD | `0xffffffff` after both allocation checks. |
| `+862/+866/+86a` | DWORD each | Explicit zero. |
| `+86e` | DWORD | First allocation result. |
| `+872` | 14 bytes | Embedded zeroed header via `0068d020`. |
| `+880/+884/+888/+88c/+890/+894/+898/+89c/+8a0` | DWORD each | Explicit zero. |
| `+91c` | DWORD | Second allocation result. |
| `+920/+924/+928` | DWORD each | Explicit zero. |
| `+92c` | 14 bytes | Embedded zeroed header via `0068d020`. |
| `+93a/+93e/+942/+946` | DWORD each | Explicit zero; last store ends at `+949`. |

These are partial fields and effects. Unlisted bytes are not guaranteed clear, and opaque callees can write additional fields. Unaligned accesses such as DWORD `+856/+86e/+93a` must retain their instruction widths. No money or transfer-record meaning is assigned to the scalar groups.

## Immediate load boundary

`008bc020` takes the same ECX receiver and one raw32 stack argument, and returns through `RET 4`. Its entry passes the argument plus `transfer.dat`, 0, `0x16` and 4 to `009326e0`; zero argument or missing opened handle has an observed zero-return path. The terminal selected path closes the handle and writes EAX=1; selected error paths close it and write EAX=0. The constructor only tests zero/nonzero.

This dependency can mutate state before returning zero: `008bc116..008bc11e` attempts a four-byte read directly into `receiver+4`; the following failure path returns zero. Later selected sites `008bc7a1..008bc7d8` allocate and construct a dependent object and store DWORD `+856` before terminal completion. The constructor performs no explicit reset or cleanup between zero load return and fresh fallback, which can replace `+856`. This identifies a partial-state and ownership question; it does not prove a runtime leak or characterize all load failure paths. The 5,262-byte callee body, validation, complete effects and cleanup remain outside this assignment.

## Evidence and checks

- [Compact sites](../evidence/transfer-boundary-11-sites.json): 257 independently decoded owned instructions match the private Ghidra listing after documented syntax normalization; 56 selected callee instructions also match. Contains the exact specimen/body hashes, six export hashes verified against the coordinator manifest, PE import resolutions, all 29 owned call sites, explicit receiver write widths and incoming call sites.
- [Contract findings](../evidence/transfer-boundary-11-findings.json): entry, partial layout, effects, caller conditions, ownership limits and unresolved calls.
- [Annotation proposal](../evidence/transfer-boundary-11-annotations.json): candidate name and four bounded comments; no canonical native change or structure/prototype replacement.
- [Extractor](../evidence/transfer-boundary-11-extract.py): read-only PE parser and Capstone 5.0.7 decode, exact owned-span coverage, native comparisons, import lookup and static call/extent/width invariants. Run with the pinned executable, an output JSON path and optional `--native-dir` containing the private exports and manifest.

On 2026-10-18 the extractor passed, including original caller register-definition checks, and repeated generation produced the same JSON. `npm run check` passed with the specified bundled Node v24.19.0; JSON parsing, Python syntax and `git diff --check` also passed. Staged content was reviewed for source scope and private payloads before commit.

This research has no runtime trace, constructor oracle or TypeScript reconstruction. Existing repository checks validate retained unrelated primitive fixtures and checkpoint metadata; they cannot establish constructor success, disk equivalence or complete subsystem behavior. Original bytes and bulk exports remain outside Git.

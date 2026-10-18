# Scouting record replacement and copy-object cleanup — investigation 16

`007b7690` releases two destination pointers, copies a 688-byte record, then conditionally replaces two copied pointers with new storage. Its allocation count and copy count are independent signed dwords. `00813140` cleans the copy object's trailing subobject, second embedded ten-record array, then first array. These are complete local static contracts; helper internals, complete nested ownership and scouting persistence remain open.

Specimen: PE32 `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline: `15eb7357500cf2dfd1838487e2a28e05d4965410`; native checkpoint 15. Addresses are virtual addresses, with byte offsets. Capstone 5.0.7 independently decodes **149 instructions / 541 bytes** and agrees with every instruction in the two read-only native exports, including operand widths after documented spelling normalization. Every local jump target is an instruction start. This is static verification without an execution oracle.

| Entry / bytes / instructions | ABI | Normal return |
| --- | --- | --- |
| `007b7690` / 421 / 118 | ECX=destination D; one four-byte stack argument=source S; `RET 4`; EBX/EBP/ESI/EDI preserved | EAX has no explicitly assigned result or success meaning |
| `00813140` / 120 / 31 | ECX=object O; no stack arguments consumed; `RET`; ESI preserved | EAX unspecified |

The cleanup entry's decompiler `__fastcall` spelling does not establish an EDX argument: the assembly consumes only ECX. Both entries install an FS:[0] exception-registration frame, update frame-local unwind state and restore the prior frame on normal return. Their exception handlers (`0095f5de` and `00961246`) and unwind effects are outside the two bodies. A local normal-return map does not establish all exceptional cleanup paths.

## Record replacement order

The exact ordinary instruction order in `007b7690` is:

1. Read dword D+`0x1ee`. If nonzero, call `009452ca(pointer)`, then clear that dword after the call returns (`007b76b3..007b76c6`).
2. Read dword D+`0x170`. If nonzero, call `0068d1f0` with ECX=`00b74438` and that pointer as its stack argument, then `00944c94(pointer)`, then clear D+`0x170` (`007b76cc..007b76ea`). The first target is a pointer-removal boundary by its call placement; its registry semantics are unresolved. The prior R15 selected wrapper evidence shows `00944c94` forwards to `009452ca`.
3. Read S from the original stack argument and copy `0xac` dwords, exactly **688 bytes**, from S into D with REP MOVSD (`007b76f0..007b7700`). This copies both pointer fields and both count fields before the conditional replacements below.
4. If signed32(read32(D+`0x1f2`)) is positive, compute `u32(45*read32(D+0x1f2))`, pass that byte request to allocation boundary `00944e46`, and store its EAX result at D+`0x1ee` (`007b7702..007b771f`). The two LEAs multiply by five then nine, with 32-bit wrapping. A nonzero allocation result proceeds to the copy-count check.
5. Inside that positive-allocation-count branch only, if signed32(read32(D+`0x1f6`)) is positive, compute `m=u32(45*read32(D+0x1f6))`, reread the pointer at **S+`0x1ee`**, then copy `m>>2` dwords and `m&3` bytes into the allocation result (`007b779b..007b77bf`). Nonpositive copy count leaves the allocation uncopied by these instructions.
6. Independently, if the now-copied D+`0x170` pointer is nonzero, request `0x51a8` (**20,904**) bytes through `00944cf1`. A nonzero result receives exactly `0x146a` dwords (**20,904 bytes**) from a fresh read of **S+`0x170`**. Call `0068d0d0` with ECX=`00b74438`, stack arguments `(new_pointer,4)`, then store the saved new pointer at D+`0x170` after the call returns (`007b77c1..007b7814`). The return of `0068d0d0` is ignored. A zero allocation result skips that copy and helper call, then stores zero at D+`0x170`.

The fixed-buffer helper calls are consistent with a shared tracking structure at `00b74438`, but these bodies establish only the receiver address, pointer traffic and order. They do not establish what tag four means, exclusive ownership, registration success, or lifetime policy. The fixed-size raw copy also does not establish deep copying of any pointers inside that buffer.

| Record field | Width and local role |
| --- | --- |
| `+0x170` | Dword pointer: destination cleanup, initial record copy, conditional fixed-size replacement and helper traffic |
| `+0x1ee` | Dword pointer: destination release, initial record copy, conditional variable-size allocation and copy source |
| `+0x1f2` | Signed dword guard for allocation; positive value multiplied by 45 modulo 2^32 |
| `+0x1f6` | Independent signed dword guard/count for copying; positive value multiplied by 45 modulo 2^32 |

There is no local comparison of `+0x1f6` against `+0x1f2`, source extent check, multiplication-overflow check or pointer validation. If `+0x1f2` is nonpositive, the entire variable allocation/copy branch is skipped and D+`0x1ee` retains the pointer copied from S. This is a conditional pointer alias, not a guarantee of a new allocation for every nonnull source pointer. No structure names such as capacity/length are asserted beyond the observed allocation-count/copy-count roles.

REP movement follows the incoming direction flag; the bodies contain no CLD. The byte ranges described above use the ordinary x86 calling assumption DF=0. Source fields are reread after helper calls; they are not an immutable snapshot of entry state. No equality/overlap guard precedes destination cleanup, so this contract provides **no self-copy or overlapping-record safety guarantee**. R15's opposite-direction ten-record callers supply the destination/source interpretation; they do not guard a null manager alias or examine this helper's result.

## Failure and ownership limits

A zero result from `00944e46` has already been stored at D+`0x1ee` when diagnostics begin (`007b7725..007b7796`). The ordered targets are `00944cff`, `0090d130`, `00944c9f`, `005e8290`, then a direct clear of global `00b67a34`, calls `005cc7d0`, `005a8f60` and `00945934(-1)`. Diagnostics use source anchor `00a701b0`, number `0x127f` and shared buffer `00ae24d0`. There is no local jump to an error return. If the last target unexpectedly returns, execution falls through to the copy-count check; EAX is then whatever that call left, rather than a locally restored allocation pointer. The owned body alone therefore supplies no recoverable allocation-failure return or proof of termination. Earlier destination cleanup and the initial record overwrite are not rolled back.

By contrast, zero from the fixed-size `00944cf1` boundary explicitly produces D+`0x170`=0 and reaches the normal epilogue if no later exception intervenes. No error status is returned. Exceptional allocator/helper behavior remains unresolved. Destination D itself and source S are not directly released. Calls can release or mutate nested/global resources; complete cleanup or allocator compatibility cannot be inferred from the local stores.

## Copy-object cleanup order

`00813140` operates on the same embedded bases constructed by R15's `008041c0`:

| Order / call site | Exact call boundary |
| --- | --- |
| 1 / `0081316b` | `0068d040`, ECX=O+`0x361e`, no stack arguments |
| 2 / `00813188` | `009462bb(O+0x1b0e,0x2b0,10,007ae4f0)` |
| 3 / `008131a3` | `009462bb(O+1,0x2b0,10,007ae4f0)` |

Thus the second embedded array is submitted for cleanup before the first. Each boundary supplies ten elements of stride 688 and cleanup callback `007ae4f0`; R15's selected helper instructions support reverse-stride callback traversal. This investigation does not elevate either helper or that callback into a complete contract. On normal return the outer routine does not directly free O, clear its leading byte, zero either array, clear the metadata tables or write any object field. Its direct writes are exception-frame/local-stack bookkeeping. Callback effects and behavior on repeated cleanup remain unresolved.

R15 selected caller context `008131d3..00813204` calls the ten-record copy-to-manager routine, then this cleanup, releases O separately, and clears its manager dword slot. That caller supports the distinction between object cleanup and object release; it does not demonstrate complete report/editor lifecycle, transactional success or persistence.

## Reproduction and confidence

`scripts/extract_scout_copy_16.py` verifies the pinned PE, manifest SHA-256 `fc92c27bcc9f2f15bedebb4aadbebba7bf0ed5f8801c787e2f0e262c48a7e960`, every manifest-listed file hash and preflight SHA-256 `2be810e149b9d5ebe8de028bf9542aab932afd31514e2ec8d737bef8450374bc`. It independently maps PE virtual addresses to file offsets, checks gapless full-body decoding, compares every native instruction, verifies local branch targets, and emits only selected sites, calls/branches/returns and hashes. No original bytes or bulk native export are retained.

```powershell
python scripts/extract_scout_copy_16.py --binary <private-cm0102.exe> --native-dir <private-exports-16> --preflight <private-annotation-preflight-16.json> --output evidence/scout-copy-16-sites.json
npm run check
git diff --check
```

Findings are in `evidence/scout-copy-16-findings.json`; exact-old-value name-only proposals are in `evidence/scout-copy-16-annotations.json`. Both owned bodies qualify as `contract-supported` local static contracts, with all call targets and exception handlers remaining boundaries. Confidence is high for direct ABI, widths, copies, branches and call order. Complete nested ownership, helper success/termination, exception unwinding, transitive RNG/I/O and full scouting behavior remain unproved. No execution equivalence, TypeScript implementation or game/UI build was added.

Verification passed: pinned PE/native manifest/preflight hashes, all 149 native instructions, all local branch targets, byte-identical repeat extraction (sites SHA-256 `8c5ff48ae267a10379f3cf62d6ce9af4e9a390bc873f1ca2a0d1e04f523ad87f`), JSON parsing, repository checks on Node v24.19.0 and `git diff --check`. The staged scope/privacy review admits only the five task files, compact selected sites/digests and authored research metadata; no binary payload, bulk assembly/pseudocode or original game data is included. Repository checks validate earlier retained fixtures and metadata; they do not execute these two scouting functions.

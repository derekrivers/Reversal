# Investigation 18: error mapping, descriptor seek and stream buffer initialization

The three immediate lower helpers beneath [R17's read/refill path](db-lower-17.md) now have complete **local static contracts**. `0094b2a0` records and maps an error DWORD, `0094c552` forwards a descriptor position operation to `SetFilePointer`, and `0094ec37` chooses a 4,096-byte allocation or a two-byte inline stream buffer. OS behavior, allocation/handle-helper internals and complete database/save compatibility remain boundaries. No execution oracle or reconstruction change is supplied.

All addresses are virtual unless marked file offsets. The specimen is the 7,192,576-byte PE32 x86 image SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Research baseline is `267756ebe6d797b6477efd5f829d45ed6cb54d07`, following checkpoint 17. Native exports came from a read-only, no-reanalysis Ghidra 12.1.4/JDK 21 opening of independently extracted checkpoint 17. Native state and shared registries were not changed.

| Entry | File offset | Contiguous bytes / instructions | Inclusive extent | Direct calls |
| --- | --- | ---: | --- | --- |
| `0094b2a0` | `0054b2a0` | 103 / 26 | `0094b2a0..0094b306` | none |
| `0094c552` | `0054c552` | 154 / 51 | `0094c552..0094c5eb` | `0094fded`, `SetFilePointer`, `GetLastError`, `0094b2a0` |
| `0094ec37` | `0054ec37` | 68 / 19 | `0094ec37..0094ec7a` | `00944e46` |

All 96 instructions / 325 bytes match an independent Capstone 5.0.7 decode of the full original-PE bodies, including operand widths and branch/call targets. All 17 direct jumps and every normal fallthrough remain inside the owned bodies; all instruction starts are structurally reachable. This graph check does not establish runtime path coverage.

## ABI and widths

All three support cdecl: arguments occupy entry stack DWORDs, normal exits use plain `RET`, and observed R17 callers discard their argument slots. EAX exposes the machine result. The seek wrapper saves/restores EBX/ESI/EDI; EBP is untouched. The other two bodies do not touch EBX/EBP/ESI/EDI directly. Preservation through callees depends on their ABI; their complete side effects remain outside this assignment. ECX/EDX and arithmetic flags are scratch except for explicitly described incidental results. No prototype or convention edit is proposed.

Pointer arithmetic and unspecified scalar fields are 32 bits, with wrapping. Descriptor flags are bytes; stream flags are DWORDs. Ordinary descriptions assume valid runtime tables and sufficiently sized, nonaliasing stream storage. There is no local locking, pointer validation, exception handling or rollback guarantee. No owned body contains a direct RNG call.

## `0094b2a0(error_raw32)`: record and map an error

At `0094b2a6`, store the input DWORD to `[00de2f90]` before any lookup. Scan 45 eight-byte rows at `00ad8dc0..00ad8f27` in increasing order: compare the input with each row's first DWORD; on the first exact match, copy its second DWORD to `[00de2f8c]` and return. The loop's address comparison is signed `JL`, but its fixed pointer values stay positive and terminate exactly at `00ad8f28`. The original table is retained privately, with its digest in the sites evidence; its rows are not redistributed.

Only after **all** rows miss, apply these unsigned input ranges:

| Input after lookup miss | Final DWORD `[00de2f8c]` |
| --- | ---: |
| `0x13..0x24` inclusive | `0x0d` |
| `0xbc..0xca` inclusive | `0x08` |
| every other DWORD | `0x16` |

For a miss at or above `0xbc`, the body first writes 8, then overwrites it with `0x16` when above `0xca` (`0094b2f0..0094b2fc`). This transient write matters if observing shared error storage concurrently; no synchronization is supplied. Lookup hits take precedence over all fallback ranges, including any matching zero input.

There is no deliberate success/failure return contract. On a table hit EAX contains the mapped DWORD; on every miss EAX remains the scan-end address `00ad8f28`. ECX retains the raw input, EDX holds the matching zero-based row index or 45. The observed R17 caller and owned seek caller ignore EAX. Error-global values resemble runtime errno/OS-error storage, but no thread-local or public-library API identity is inferred from these fixed globals.

## `0094c552(descriptor_raw32, offset_raw32, method_raw32)`: descriptor seek wrapper

Require `F <unsigned DWORD[00de43e0]`. Resolve a descriptor page through `DWORD[00de42e0 + 4*(signed(F)>>5)]` and entry offset `8*(F&31)`; BYTE entry `+4` must contain `0x01`. Descriptor -1 always fails the unsigned bound. There is no independent table-pointer/lifetime check, and no local validation of offset or method.

If the bound/open-bit check fails, write DWORD `[00de2f90]=0`, `[00de2f8c]=9`, return -1. Otherwise call `0094fded(F)` (`0094c57f`). Its EAX is used as the handle-shaped value. If EAX=-1, write `[00de2f8c]=9` and return -1; that path makes no local write to `[00de2f90]`, although the callee may have changed it.

For any other helper result, call `SetFilePointer(handle, offset_raw32, NULL, method_raw32)` at `0094c5a1`. Original PE import descriptors/thunks bind IAT `009670a0` to `KERNEL32.dll!SetFilePointer` and `009670e8` to `KERNEL32.dll!GetLastError`. The second argument is a raw DWORD consumed by the imported LONG offset parameter; the high-distance pointer is null. There is no local high-word output or 64-bit position implementation.

| API result | Local action |
| --- | --- |
| any result other than `0xffffffff` | accept without consulting last-error |
| `0xffffffff`, `GetLastError()!=0` | call `0094b2a0(error)`, then return -1; no local descriptor flag clear |
| `0xffffffff`, `GetLastError()==0` | accept and return `0xffffffff` |

No `SetLastError(0)` call precedes the API operation. On every accepted result, reload the descriptor page pointer from the saved page-table slot and AND its BYTE entry `+4` with `0xfd` (`0094c5c5..0094c5c7`), clearing exactly the text EOF bit `0x02`; return the API's raw DWORD in EAX. Thus a returned -1 alone cannot distinguish accepted `0xffffffff` from failure. Clearing the bit is a local effect even when the accepted result is -1. There is no local lookahead-cache write, stream-buffer reset, bounds adjustment or seek retry. Actual handle movement, API errors and concurrent descriptor mutation remain external behavior.

R17 calls this as `(F, -1, 1)` after some trailing-CR lookahead cases and ignores the result. The helper therefore attempts a relative position operation and can clear descriptor EOF; it does not guarantee that the lookahead byte was restored. A failed seek can leave R17's returned translated-byte count disconnected from physical handle advancement.

## `0094ec37(stream)`: select and reset a stream buffer

First increment DWORD `[00de3144]` modulo 2^32, before reading the stream argument or calling another helper. There is no `LOCK` prefix; the body neither decrements this counter nor proves what it counts globally. Call `00944e46(0x1000)` at `0094ec42`, then load the stream pointer and store returned EAX to DWORD stream `+8`. The native decompiler labels the callee `_malloc`; its implementation and error/exception policy remain a direct allocation boundary.

| Allocation EAX | Ordered local actions after the initial `+8` store |
| --- | --- |
| nonzero | OR DWORD flags `+0xc` with `0x08`; write DWORD size `+0x18=0x1000` |
| zero | OR DWORD flags `+0xc` with `0x04`; replace DWORD base `+8` with `stream+0x14`; write DWORD size `+0x18=2` |

Then on both paths reload base `+8` into EAX, clear DWORD available count `+4`, and write DWORD cursor `+0` to that base (`0094ec71..0094ec78`). Return EAX is the selected base, despite the native decompiler's `void` signature. In ordinary valid storage the inline fallback supplies a nonnull pointer even when allocation returned null; no -1 failure result is generated. The observed R17 refill caller ignores EAX and consumes the mutated stream fields.

No original flags are cleared, so old `0x04` and `0x08` bits can coexist after reuse. No old buffer is freed, no existing ownership/capacity flag is inspected, and no selected buffer bytes are initialized. The null result is written to `+8` before the fallback overwrites it. No descriptor, OS I/O or stream error-global update occurs directly here; allocation can have transitive effects. Repeated calls, self-aliasing stream/global memory, invalid storage, allocator failure mode and eventual buffer release remain outside the safe-use claim.

## Reproduction and remaining limits

[Sites](../evidence/db-helpers-18-sites.json) retain complete comparison counts, hashes, branch/call targets, table provenance and 24 selected instructions. [Findings](../evidence/db-helpers-18-findings.json) give the compact contracts; [proposals](../evidence/db-helpers-18-annotations.json) contain three name-only suggestions against exact old `FUN_*` names and blank comments. No comments, signatures or structures are proposed.

```text
python scripts/extract_db_helpers_18.py PATH_TO_EXE PATH_TO_EXPORTS_18 PATH_TO_PREFLIGHT_18 OUTPUT.json
```

The extractor requires Capstone 5.0.7. It verifies specimen SHA-256, private manifest SHA-256 `fc4f2070cb0efa89c9473ebe507d0e2d3f01e1f5f66338177be5f34848ee7151`, preflight SHA-256 `8749c47798c3758dc7509d0b3b71b7147f169ee0390066f01ef023baf670bcbb` and all six owned native `.asm`/`.c` hashes. It independently decodes each complete contiguous PE body, compares every native instruction with only spelling normalization, checks every branch/fallthrough and resolves import identities from original PE thunks. Bulk assembly, pseudocode, binary bytes, table rows and native projects remain private.

Two extraction runs produced identical retained sites, SHA-256 `0f3762e582f17802a8b6821eb70931ac13de90e0f4cf32e61607a2122be83ae2`. Node v24.19.0 `scripts/check-research.mjs` and `git diff --check` passed.

These are **contract-supported local static bodies**. Immediate unresolved implementation boundaries are handle helper `0094fded`, allocation helper `00944e46`, and the two imported OS routines. Descriptor initialization/lifetime, stream ownership/cleanup, concurrency, actual OS outcomes and complete file compatibility remain open. Existing numerical research checks validate previously reconstructed primitives, not execution equivalence for these three helpers.

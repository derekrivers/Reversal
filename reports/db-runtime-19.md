# Investigation 19: descriptor handles and allocation forwarding

Three complete bodies now have **local static contracts**: `0094fded` validates a descriptor and reads its stored handle DWORD; native `_malloc` forwards a size and a fixed-global flag to native `__nh_malloc`; the latter rejects oversized inputs or controls calls to an unresolved allocation helper and retry callback. Allocation internals, OS outcomes, descriptor lifetime and complete database/save compatibility remain open. No execution oracle or reconstruction change is supplied.

All addresses are virtual unless marked file offsets. The specimen is the 7,192,576-byte PE32 x86 image SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Research branch baseline is `c78cda13406c25a32747749bc07c8bc7936c7a3a`, following merged checkpoint 18. Native exports came from a read-only, no-reanalysis Ghidra 12.1.4/JDK 21 opening of independently extracted checkpoint 18. Native state and shared registries were not changed.

| Entry / existing native name | File offset | Bytes / instructions | Inclusive extent | Direct calls |
| --- | --- | ---: | --- | --- |
| `0094fded` / `FUN_0094fded` | `0054fded` | 61 / 16 | `0094fded..0094fe29` | none |
| `00944e46` / `_malloc` | `00544e46` | 18 / 6 | `00944e46..00944e57` | `00944e58` |
| `00944e58` / `__nh_malloc` | `00544e58` | 44 / 16 | `00944e58..00944e83` | `00944e84`, `0094895b` |

All 38 instructions / 123 bytes match an independent Capstone 5.0.7 decode of the full original-PE bodies. Every native instruction start and decoded operand matches, with spelling normalization only. This establishes contiguous instruction membership for these three bodies rather than assuming it from min/max bounds. All six direct jumps and every normal fallthrough stay inside the relevant body; all instruction starts are structurally reachable. The graph check does not establish runtime path coverage.

## ABI and local effects

Arguments occupy entry stack DWORDs; normal exits use plain `RET`. Cdecl is supported by R18's seek and stream-buffer caller cleanup, `_malloc` discarding both `__nh_malloc` arguments with two `POP ECX` instructions, and `__nh_malloc` discarding each single callee argument with `POP ECX`. EAX carries the raw DWORD result. None of these bodies directly touches EBX/EBP/ESI/EDI. Preservation through unresolved callees depends on their ABI; ECX/EDX and flags are scratch. No signature or calling-convention edit is proposed.

Descriptions assume valid stack storage, readable runtime tables and ordinary nonaliasing arguments. There is no local lock, exception handler, pointer validation or rollback. Address arithmetic is 32 bits with wrapping. No body contains a direct RNG call. Only descriptor failure performs direct writes outside stack storage; allocator callees may have further effects.

## `0094fded(descriptor_raw32)`: validate and read a handle DWORD

At `0094fdf1`, compare input F against DWORD `[00de43e0]` **unsigned**. F at or above that bound branches straight to failure. Otherwise compute the page index with arithmetic `signed32(F)>>5`, load the page pointer DWORD from `[00de42e0 + 4*index]`, and compute the entry offset `8*(F&31)`.

Test BYTE entry `+4` for bit `0x01` (`0094fe08`). The following `LEA` does not change flags, so `JZ` at `0094fe10` tests that bit. When set, read DWORD entry `+0` into EAX and return (`0094fe12..0094fe14`). The success path performs no direct memory writes and calls no other function. It does not clear EOF, change the descriptor or validate the returned handle value.

Both a failed bound and a clear open bit execute, in order:

1. Read/modify/write DWORD `[00de2f90]` with `AND ...,0`, producing zero (`0094fe15`).
2. Write DWORD `[00de2f8c]=9` (`0094fe1c`).
3. Set EAX to `0xffffffff` and return (`0094fe26..0094fe29`).

These failure writes are unsynchronized. An invalid page pointer can fault before the open-bit decision and therefore need not reach this error path. F=`0xffffffff` always fails the unsigned bound, but the body has no separate signed-negative rejection: other high-bit values would pass an artificially larger bound and then use a negative arithmetic-shift page index. Runtime bounds and table initialization are separate preconditions.

Success may return any stored DWORD, including zero or `0xffffffff`; neither value causes an error write here. Consequently EAX=-1 does not alone establish that this helper rejected the descriptor. In [R18's seek wrapper](db-helpers-18.md), an open entry holding -1 reaches the caller's own EAX=-1 check and error-9 write without this helper clearing `[00de2f90]`. The earlier R18 conclusion that this path made no *local caller* write there remains valid; R19 now distinguishes helper validation failure from the stored-value case. No OS handle query occurs in this body.

## `00944e46(size_raw32)`: native `_malloc` forwarding

Read DWORD `[00de3008]` once and push that value (`00944e46`). The next push reads `[ESP+8]`, which now refers to the original entry size argument. Call `00944e58(size_raw32, flag_snapshot)` at `00944e50`; discard both pushed DWORDs and return its EAX unchanged.

The global's contents are passed verbatim, without conversion to Boolean. This wrapper makes no direct nonstack memory writes, performs no independent validation, and supplies no independent error/exception behavior. A retry callback changing `[00de3008]` does not cause this wrapper to reread it during this invocation. The existing native name `_malloc` and its library-identification comment are preserved; they do not prove the deeper allocator's contract.

## `00944e58(size_raw32, flag_raw32)`: native `__nh_malloc` call/retry controller

The entry compare uses the sign-extended imm8 `-0x20`, interpreted by unsigned `JA`: sizes **above `0xffffffe0`** return zero immediately via `00944e81`. Equality is accepted. Size zero also passes this local check. This body performs no local size rounding or zero-size substitution and makes no direct nonstack memory writes.

For a size at or below that cutoff:

| Step / result | Local next action |
| --- | --- |
| Call `00944e84(size_raw32)` at `00944e63`; EAX nonzero | Return that raw EAX immediately |
| Allocation helper EAX zero, flag DWORD zero | Return zero; no callback |
| Allocation helper EAX zero, flag DWORD nonzero | Call `0094895b(size_raw32)` at `00944e77` |
| Callback EAX zero | Return zero |
| Callback EAX nonzero | Repeat at the size push `00944e5f`, calling `00944e84` again |

The flag comparison at `00944e6d` is against EAX, which is known zero on that path. The flag is reread from the argument slot after each failed allocation call. Any nonzero flag/callback DWORD, including a value with the high bit set, enables its respective branch. `TEST EAX,EAX` precedes each cleanup `POP ECX`, which preserves flags for the following branch.

Assuming callees preserve caller argument storage, each call receives the original size unchanged. The loop does not repeat the initial size cutoff check, has no local retry limit, and may fail to return if callees continue returning allocation zero/callback nonzero. The callback's nonzero result controls retry; it is not returned as an allocation result. No error-global write is made directly, including the immediate oversized path. Allocation, callback dispatch/identity, errors, exceptions, synchronization and storage ownership inside `00944e84`/`0094895b` remain unresolved.

R18's `0094ec37` calls `_malloc(0x1000)` before selecting an allocated or inline stream buffer. The size passes this local cutoff, but that fact supplies no allocation-success guarantee. Its fallback is reached only if this chain returns zero normally; an exception or continuing retry does not reach that local fallback. No heap layout or heap-global meaning is inferred.

## Evidence, reproduction and limits

[Sites](../evidence/db-runtime-19-sites.json) retain full comparison counts, body/native hashes, complete branch/call/return sites and 15 selected instructions. [Findings](../evidence/db-runtime-19-findings.json) record the contracts. The [proposal](../evidence/db-runtime-19-annotations.json) suggests only `FUN_0094fded` → `cm0102_descriptor_to_handle_or_error9`, against the exact old name and absent comment. `_malloc`/`__nh_malloc`, their comments, prototypes and structures are preserved.

```text
python scripts/extract_db_runtime_19.py PATH_TO_EXE PATH_TO_EXPORTS_19 PATH_TO_PREFLIGHT_19 OUTPUT.json
```

The extractor requires Capstone 5.0.7, pins the PE hash above, private manifest SHA-256 `3c5da196118b891f3dcd84f8126355d3c36888c3c7b72ca1f6d89772d8a22935`, preflight SHA-256 `a8b6f47a04ac2dcc2d6fb13537a55b223db5630d50e857ceb014f40f7069cf78`, all six owned `.asm`/`.c` hashes and existing names/comments. It checks complete original/native instruction membership, widths/targets and the local branch/fallthrough graph. Bulk assembly, pseudocode, original bytes and native projects remain private.

Two extraction runs produced byte-identical sites evidence, SHA-256 `a1921be168b5bd31b80f6206dd5d24b7bbc56c7fc8e6a8985a9d3250e94dee07`. `npm run check` passed on Node v24.19.0; `git diff --check` passed. The retained numerical checks validate earlier reconstructed primitives and checkpoint metadata; they do not execute these three bodies.

No runtime execution, allocator/OS trace, connected outcome or full subsystem claim follows from these static contracts. Descriptor initialization/concurrency/lifetime, invalid storage behavior, the two unresolved allocator callees and complete file compatibility remain separate work.

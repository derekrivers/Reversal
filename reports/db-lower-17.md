# Investigation 17: lower copy, descriptor read and stream refill

The three direct dependencies beneath [R16's buffered item reader](db-stream-16.md) now have complete **local static contracts**. `0094ab50` copies bytes in an overlap-aware direction; `0094b3e0` reads a runtime descriptor through the original `ReadFile` import and optionally translates text in place; `0094b307` refills a FILE-like buffer and returns one unsigned byte or -1. Buffer initialization, error mapping and the position helper remain transitive boundaries. This does not establish full database/save compatibility or execution equivalence.

All addresses below are virtual addresses in the 7,192,576-byte PE32 specimen SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline is `edc2a3cafe3695346e706733100eeff59be5b9f4`, checkpoint 16. The three entry file offsets are respectively `0054ab50`, `0054b3e0`, `0054b307`; the extractor derives them from PE sections. Native state and shared registries were not changed.

| Entry | Owned bytes / instructions | Body extent, inclusive | Direct calls |
| --- | ---: | --- | --- |
| `0094ab50` | 664 / 231 | `0094ab50..0094ae84`, 21 instruction ranges | none |
| `0094b3e0` | 502 / 174 | `0094b3e0..0094b5d5`, contiguous | two `ReadFile`, two `GetLastError`, `0094b2a0`, `0094c552` |
| `0094b307` | 217 / 78 | `0094b307..0094b3df`, contiguous | `0094ec37`, `0094b3e0` |

The copy routine's 821-byte enclosing extent includes table/alignment holes. Its 664 owned instruction bytes must not be treated as a contiguous prefix. All 483 instructions / 1,383 owned bytes were decoded from the original executable and compared with the pinned native listing. The evidence includes table targets separately.

## ABI and widths

All three support cdecl: arguments are entry stack DWORDs, all exits use plain RET, and observed R16/internal callers clean up arguments. `0094ab50(destination, source, byte_count_raw32)` and `0094b3e0(descriptor_raw32, destination, requested_bytes_raw32)` use `ESP+4/+8/+0xc`; `0094b307(stream)` uses `ESP+4`. EAX is the return register. EBX/EBP/ESI/EDI are preserved (unused registers need no save); ECX/EDX and arithmetic flags are scratch. No signature or calling-convention edit is proposed. The decompiler incorrectly types the lower reader's third parameter as a pointer; the instructions pass its raw DWORD as `ReadFile`'s byte count.

Unless explicitly byte/word, fields and arithmetic are 32 bits with wrapping. Ordinary buffer and copy descriptions assume valid, sufficiently sized memory, flat DS/ES, DF clear at entry, and no pointer/count overflow. None of these functions checks pointer validity or destination capacity.

## `0094ab50`: overlap-aware byte copy

Let D be destination, S source and N the unsigned DWORD count. At `0094ab62..0094ab6a` compute `E=low32(S+N)`. Copy backward exactly when `D >unsigned S` and `D <unsigned E`; every other case copies forward. For valid nonwrapping ranges this is memmove behavior, including overlapping buffers and identical source/destination. The exact wrapping predicate is retained rather than extending that claim to wrapped address ranges. There are no calls, globals, stream accesses or error return. All normal exits return original D.

The forward path aligns destination by copying 1–3 leading bytes when needed, then transfers DWORDs in increasing address order and 0–3 trailing bytes. Small counts bypass alignment when subtracting four borrows. For eight or more DWORDs it uses REP MOVSD; for fewer, an indexed jump enters an unrolled 0–7-DWORD sequence. The source may be unaligned.

The backward path initializes working pointers to `S+N-4`, `D+N-4` (`0094ace8..0094acec`), aligns from the high end with byte stores, then copies DWORDs in decreasing order and the remaining high-indexed bytes. REP MOVSD blocks explicitly execute STD then CLD (`0094ad03..0094ad06` and three other sites). Short backward blocks use explicit loads/stores. With the normal DF-clear entry assumption all normal returns leave DF clear; there is no promise to preserve an arbitrary incoming direction flag. A fault inside REP can interrupt before CLD.

| Dispatch base | Valid index domain | Purpose |
| --- | --- | --- |
| `0094abb0` | 1..3 | forward alignment bytes |
| `0094ac2c` | 0..7 | forward small DWORD run |
| `0094ac98` | 0..3 | forward byte tail |
| `0094aca8` | -4..-1 | same forward tail after wrapped `N-4` |
| `0094ad38` | 1..3 | backward alignment bytes |
| `0094ade0` | -7..0 | backward small DWORD run after NEG |
| `0094ae30` | 0..3 | backward byte tail / small count |

All 16 indirect jumps use these tables. Every admitted table value resolves to an owned instruction start. The negative-index forward table aliases the four cells at `0094ac98`; these are not instruction bytes even though `0094aca8` itself is an instruction start. N=0 returns D without accessing source or destination. There is no rollback on a memory fault.

## `0094b3e0`: descriptor read and text translation

The descriptor F must satisfy `F <unsigned DWORD[00de43e0]`. Its entry is at `DWORD[00de42e0 + 4*(signed(F)>>5)] + 8*(F&31)`. Entry `+0` is a DWORD OS handle, `+4` a BYTE flag set, and `+5` a BYTE lookahead cache. Flag `0x01` must be set; invalid/out-of-bound entries write DWORD `[00de2f90]=0`, `[00de2f8c]=9`, then return -1 (`0094b5bd..0094b5ce`). There is no locking or table-lifetime validation in this body. Descriptor -1 is invalid under the unsigned check for any possible bound.

After validation, request zero or entry flag `0x02` returns zero before destination access or OS I/O. For a nonzero request with flags intersecting `0x48`, cache `+5` other than `0x0a` is first stored to destination, the requested DWORD is decremented, destination passed to `ReadFile` advances one, and cache becomes `0x0a` (`0094b438..0094b450`). This prefix path does not require text bit `0x80`. It still calls `ReadFile` if the remaining request becomes zero.

Original PE import descriptors/thunks identify IAT `009670e4` as `KERNEL32.dll!ReadFile` and `009670e8` as `KERNEL32.dll!GetLastError`. The main call is `ReadFile(handle, destination_after_prefix, remaining_request, &bytes_read, NULL)` at `0094b464`. Its output count is a stack DWORD, not preinitialized here.

| Main `ReadFile` result | Local action / return |
| --- | --- |
| false, `GetLastError()==5` | DWORD `[00de2f8c]=9`, `[00de2f90]=5`; return -1 |
| false, error `0x6d` | return 0; no local error-global write |
| false, any other error, including zero | call `0094b2a0(error)`, ignore its return, then return -1 |
| true, descriptor bit `0x80` clear | return `low32(prefix_count+bytes_read)` |
| true, descriptor bit `0x80` set | translate in place; return compacted output byte count |

The two error globals have errno-shaped values, but their external API/thread ownership and mapper behavior remain unresolved. A prefix may already have changed destination/cache when the main call fails; 0/-1 then omits that prefix from the reported count. OS-written destination bytes on a failed call are also not rolled back. Zero/short successful reads are accepted; this function does not loop to fill the initial request.

### Text path and one-byte lookahead

On successful text reads, update descriptor BYTE flag `0x04`: set it exactly when the **main OS count** is nonzero and the first byte at original destination is LF; otherwise clear it (`0094b4c0..0094b4cf`). With a cached prefix, this test can inspect the prefix rather than the first byte newly supplied by the OS. Other bits are retained.

Scan from original destination up to the unsigned end pointer `destination + prefix_count + bytes_read`, compacting output to the same buffer:

- Ordinary bytes copy through.
- CR followed by LF inside the read span becomes one LF; an internal CR followed by another byte stays CR.
- `0x1a` stops translation without emitting that byte or later bytes. Set entry flag `0x02` unless flag `0x40` is set (`0094b5a2..0094b5b0`). The initial OS call may already have consumed the rest of the span. There is no seek-back for those discarded bytes.
- CR at the final input position triggers a second `ReadFile(handle, &one_byte, 1, &bytes_read, NULL)` at `0094b535`. The main span end is retained separately. No physical EOF or text result is inferred solely from output length.

For the trailing-CR read, failure with nonzero `GetLastError`, or a zero output count, emits CR and returns the accumulated output; it does not invoke the error mapper or turn the whole call into -1. If the call fails with error zero, control still consults the count and potentially the lookahead byte. Neither stack output is initialized immediately before that call, so malformed API output assumptions must not be added to the local contract.

If lookahead is admitted and flags intersect `0x48`, LF is emitted as LF; a non-LF emits CR and stores that lookahead byte in cache `+5` for the next call. Otherwise, when output is still empty and the byte is LF, emit LF directly. In every other admitted lookahead case call `0094c552(F, -1, 1)` (`0094b582`), ignore its EAX, then emit CR only if lookahead was not LF. Thus a trailing CR plus LF after some earlier output can produce no byte for that CR on this call; the position helper is asked to restore one input byte for a later read. Those are seek-shaped arguments, but actual repositioning and failures inside `0094c552` remain unresolved.

The return is output bytes, not original OS bytes. CRLF contraction, `0x1a`, cached prefixes, lookahead and the unverified position helper prevent equality between return count and physical handle advancement. Pointer-end comparisons are unsigned; wrapped ranges can skip the scan. No local signed-size rejection, terminator store, allocation, open/close or RNG call occurs.

## `0094b307`: refill and consume one byte

This body borrows a stream with DWORD pointer `+0`, available count `+4`, buffer base `+8`, flags `+0xc`, descriptor `+0x10` and refill size `+0x18`. It does not consume an existing count before refilling; callers must establish when refill is appropriate. It dereferences the stream immediately.

| Entry flag condition, low BYTE | Local action |
| --- | --- |
| no `0x83` bit, or `0x40` set | return -1 without local stream writes |
| `0x02` set after the above gates | OR DWORD flags with `0x20`, return -1 |
| otherwise | OR flags with `0x01`, then prepare buffer/read |

If the resulting WORD flags intersect `0x10c`, reset DWORD `+0` to buffer base `+8`. Otherwise call `0094ec37(stream)` at `0094b339`, ignore its return, and rely on its stream effects. There is no separate allocation-failure check. Call `0094b3e0([+10], [+8], [+18])` at `0094b34f` and store EAX to DWORD `+4` before testing it.

- EAX=0: OR DWORD flags with `0x10`, clear DWORD count `+4`, return -1.
- EAX=-1: OR DWORD flags with `0x20`, clear DWORD count `+4`, return -1.
- Every other EAX: retain successful path, including any unusual raw value; no local positive-count/capacity guard.

On that last path, if stream flags have neither `0x80` nor `0x02`, inspect the descriptor table BYTE `+4` through the same index formula. Descriptor -1 selects fixed fallback entry `00ad91f0` instead. If descriptor flags masked with `0x82` equal `0x82`, OR stream DWORD flags with `0x2000` (`0094b399`). This lookup has no independent bounds or open-bit check here.

Next, if DWORD refill size equals `0x200`, stream flag `0x08` is set and flag `0x400` clear, change refill size to `0x1000` (`0094b39f..0094b3b5`). This happens **after** the current read; it does not increase its request or prove buffer capacity. Finally set `+4=low32(read_result-1)`, load one byte through the current DWORD `+0` with MOVZX, advance `+0` by one, and return 0..255. A zero byte is successful; only -1 signals failure. Existing flags are never generally cleared.

## Dependencies, limits and reproduction

The buffered R16 copy boundary now supports overlap for valid nonwrapping ranges. Its direct lower read can translate bytes, cache/prefetch lookahead, stop on text `0x1a`, or return failure after destination mutation. Its single-byte path can initialize/refill the buffer, update EOF/error and stream flags, and alter the next refill size. These findings close the three local bodies; they do not retroactively turn the R16 item reader or the bounded byte-run decoder into validated physical-I/O or truncated-input policies.

Unresolved immediate helpers are `0094ec37` (buffer preparation), `0094b2a0` (error mapping) and `0094c552` (position operation). Their allocation, error-global, handle-position and failure effects are outside ownership. There are no observed locks or exception/fault recovery in the owned bodies. Stream creation, descriptor lifetime/concurrency, valid flags/capacity, actual file contents and host API outcomes remain unvalidated. No execution oracle or reconstruction change is supplied.

[Sites](../evidence/db-lower-17-sites.json) retain complete comparison counts, owned ranges/hashes, direct calls, import bindings, all jump-table target values and selected instructions. [Findings](../evidence/db-lower-17-findings.json) provide the compact contract and remaining boundaries; [proposals](../evidence/db-lower-17-annotations.json) are name-only, with exact old names from preflight/native headers.

```text
python scripts/extract_db_lower_17.py PATH_TO_EXE PATH_TO_EXPORTS_17 PATH_TO_PREFLIGHT_17 OUTPUT.json
```

The extractor requires Capstone 5.0.7. It verifies PE SHA-256, private manifest SHA-256 `096c06e07891855555057cdcc9f33307c6cdee79e7c632be5f593f76d894a2b8`, preflight SHA-256 `0d084f0348af44eeb24a73d8cec0fc866525099b14180bd87bd9c6246beda10f`, and all six owned `.asm`/`.c` file hashes. The exports were made read-only from independently extracted checkpoint 16 using Ghidra 12.1.4/JDK 21 without reanalysis. Every owned instruction matches the independent decode; all 67 direct jumps and 16 indirect jumps resolve within the owned graph, with structurally reachable starts and checked fallthroughs. Structural reachability is not proof that all paths occur at runtime.

Two extraction runs produced identical retained sites, SHA-256 `bff6c444a2391aa4191c72ee64d92552e7b5ba4de977a546fa0fd24a19050b50`. Node v24.19.0 research checks and `git diff --check` passed. Existing numerical checks cover previous primitives, while these three findings remain static-only. Recommend **contract-supported** for these three complete local bodies, with the transitive limits above.

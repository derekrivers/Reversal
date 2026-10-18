# R24-B: date-like pair difference helper

The complete local body at virtual address `0054cc30` is 358 bytes and 111 x86 instructions. It starts at PE file offset `0x14cc30` in the pinned 7,192,576-byte specimen, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The read-only Ghidra 12.1.4/JDK21 export came from an independently restored checkpoint-23 archive, SHA-256 `9cb03ce3740e5529a2f6155aa20b1a61ea4ba321c6d3520e1c91525782703f52`. Its [manifest](../evidence/date-difference-24-sites.json) pins export-manifest SHA-256 `c3770d9a3b8b99d80454413ea5ec85114aa0f3baa9ec0c661567c30d7bf40e70` and exact-old native preflight SHA-256 `1df62ffab8859fa6d1b86e486a26f10f82c82827eb08356caae3ce916694a193`.

The [extractor](../scripts/extract_date_difference_24.py) checks the PE headers and original bytes, the read-only export and preflight, and every instruction address, mnemonic, explicit width and operand. All 111 instructions are structurally reachable. The [site evidence](../evidence/date-difference-24-sites.json) records 14 local branches, two call targets, 10 direct nonframe write sites and the sole `RET 12`. Its result is a complete **static local-body map**. The registration callback and recursive invocation are transitive execution boundaries.

## ABI and local behavior

Entry `ECX` points to an eight-byte date-like value. Its first two WORDs at `+0/+2` act as a signed ordinal and unsigned year for ordering and arithmetic; the DWORD at `+4` is forwarded as the second date argument on recursive reversal. The caller passes an output pointer at entry `ESP+4`, a packed second date's ordinal/year at `ESP+8`, and its second DWORD at `ESP+12`. The callee saves EBX/EBP/ESI/EDI, sets and restores `FS:[0]` for an SEH frame, returns the output pointer in EAX, and cleans all three stack arguments with `RET 12`. These are instruction-derived roles, not recovered source types.

If bit 0 of `00ae249d` is clear, the local body writes ordinal 40 and year 1972 as two WORDs to `00ae2428/+2`, sets that flag bit, writes DWORD 1 to `00ae242c`, calls `0094627a` with `0054cda0`, then continues. The callback's effects and exceptional behavior are not mapped here. If the flag is already set, this initialization and call are skipped; the existing DWORD at `00ae242c` is retained in the result.

The comparison uses **unsigned** year ordering. If the second date's year is greater, or years are equal and its **signed** ordinal is greater, the function calls itself with the two date values swapped and the same output pointer. It then returns that pointer. The local caller does not copy the recursive result a second time. This path is statically mapped, but recursive execution, aliasing and SEH exceptions are outside the validated domain.

On the direct path, it sign extends both ordinal WORDs and subtracts second from receiver. If this is nonnegative, it stores that low WORD and the receiver-minus-second year WORD. If negative, it adds 365 or 366 to the ordinal difference and decrements the year difference. The receiver year controls the leap test: divisible by 4, except century years not divisible by 400. The arithmetic is narrowed to WORDs at `00ae2428/+2`; the resulting DWORD and the existing DWORD at `00ae242c` are copied, in that order, to output `+0/+4`. The exact signed/unsigned mix and even out-of-calendar WORD cases are retained. The helper performs one-year borrow only; it does not sum elapsed days across every intervening year.

The date-like interpretation is supported by year constants, 365/366 borrow and the caller's use of the resulting fields. The precise source-level calendar type and global buffer ownership remain hypotheses. The proposed native name is [DatePairDifference](../evidence/date-difference-24-annotations-proposal.json), confined to this local behavior.

## Original-instruction TypeScript validation

The [TypeScript reconstruction](../reconstruction/date-difference.ts) covers the preinitialized, mapped, disjoint, nonrecursive path only. [Unicorn 2.1.4 oracle generation](../scripts/emulate_date_difference_24.py) executed original x86 **from entry through `RET 12`**, including the SEH frame push/restore, for 95 synthetic cases, 5,100 instruction steps and 86 distinct starts. Inputs span equal years, signed ordinal edges, nonborrow and borrow, leap and nonleap years including an even year not divisible by four, century and 400-year rules, and a high year WORD. The [retained oracle](../evidence/date-difference-24-oracle.json), SHA-256 `a62a75ec46f27ec20de69032e4189e787690917f2fc90a88280ad4609abbb0b9`, records the trace, **merged ordered read/write events**, output/global DWORDs, registers and stack result. The [checker](../reconstruction/check-date-difference.ts) compares all these external effects and validates the fixture provenance and domain. In particular, the original body writes the low ordinal WORD before it rereads receiver year; the TypeScript preserves that order.

The oracle excludes flag-clear initialization, `0094627a`, recursive calls, invalid/unmapped pointers, aliases, concurrent mutation and abnormal SEH transfer. Its 95 cases validate this path, not every calendar input or the whole function. Direct static branches outside the cases remain in the site map.

Normal and optimized Python regenerated both site and oracle JSON byte-identically. A changed PE byte, changed native text, and resealed native text with its manifest hash updated were rejected in both modes; the latter reaches the independent PE/native operand comparison. A separately resealed DWORD-to-WORD native width mutation is rejected by the exact width comparison in both modes. The TypeScript checker rejects a changed result, a changed merged event order and a changed oracle. The [negative receipt](../evidence/date-difference-24-negative.json) records these checks. Public files contain synthetic values and site metadata; the executable, native exports and project remain private.

Reproduce with Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24:

```text
python scripts/extract_date_difference_24.py EXE --exports EXPORTS_24 --preflight PREFLIGHT_24 --output sites.json
python scripts/emulate_date_difference_24.py EXE --exports EXPORTS_24 --preflight PREFLIGHT_24 --output oracle.json
node reconstruction/check-date-difference.ts evidence/date-difference-24-oracle.json
python scripts/check_date_difference_24_negative.py EXE --exports EXPORTS_24 --preflight PREFLIGHT_24 --node NODE24 --scratch PRIVATE_DIR --output negative.json
```

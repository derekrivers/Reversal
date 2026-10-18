# R26-B — `_strncpy` runtime body

The complete local body at virtual address `009466d0` is mapped and a bounded headless TypeScript reconstruction matches **6,912 original-entry-to-return synthetic executions**, comprising **580,732 x86 steps**, all **109 instruction starts** and all **130 local CFG edges**. These are runtime copy fixtures over a constructed case matrix, not independent game states or gameplay coverage. R25-C's mode-zero call targets this body, but that caller and its locale selection do not execute here.

## Provenance and evidence

The PE32 specimen is `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The body is 254 contiguous bytes, VA `009466d0..009467cd`, end exclusive `009467ce`, file offset `005466d0`; body SHA-256 is `0318574df8288c6fc0e543c779d4c1098344731f9acf2a7c790c2176ab7bdf4c`.

The private native export manifest SHA-256 is `e86692ed3575e204e9e22c5c6d15bba0f5a299d1bc30ce64111b25f0e66cad75`, tied to checkpoint 25 archive `670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a`. Exact-old preflight SHA-256 is `b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd`. The extractor verifies the PE hash/size, all ten manifest export hashes/sizes, preflight and manifest provenance, existing name/comment, every instruction's address, mnemonic and complete operands (including memory width), and all local branch destinations/fallthroughs. It uses Capstone 5.0.7 and explicit exceptions, with no integrity `assert` statements.

The existing `_strncpy` library name and its Visual Studio 1998 Debug/Release library comment are preserved. No native annotation change is proposed. No canonical native database or shared registry was edited.

| Authored artifact | Purpose |
| --- | --- |
| `evidence/strncpy-runtime-26-sites.json` | Compact instruction/CFG/access census and provenance; no instruction bytes |
| `evidence/strncpy-runtime-26-oracle.json.gz` | Compressed synthetic inputs, operand-sized events, original outputs, register/stack results and aggregate native coverage |
| `evidence/strncpy-runtime-26-negative.json` | Normal/-O-safe integrity and model mutation receipt |
| `evidence/strncpy-runtime-26-privacy.json` | Generated input-byte privacy verification and public file inventory |
| `scripts/extract_strncpy_runtime_26.py` | Exact PE/native verification and static evidence extraction |
| `scripts/emulate_strncpy_runtime_26.py` | Original-entry Unicorn 2.1.4 execution; no patched instructions or intercepted callees |
| `scripts/check_strncpy_runtime_26_negative.py` | Eleven rejection checks plus positive checker |
| `reconstruction/strncpy-runtime-26.ts` | Bounded runtime model with exact ordered memory effects |
| `reconstruction/check-strncpy-runtime-26.ts` | Node 24 retained oracle comparison and eight admission checks |

Oracle gzip SHA-256 is `fbee331c5b29691dda02c91ab5492d31cb20b4f254ee8d7a1febde457ca29169`. It contains numerical synthetic fixtures and address coverage; it contains no executable code or original game memory.

## Complete local contract

The ABI is 32-bit `__cdecl`: destination pointer at entry `ESP+4`, source pointer at `ESP+8`, unsigned 32-bit count at `ESP+0xc`. Returns at `00946729`, `00946758` and `009467cd` use plain `RET`; the caller removes the twelve argument bytes. EAX returns the original destination pointer, ESP advances by four over the return address, EBX/EBP/ESI/EDI are preserved, and ECX finishes at zero. EDX is volatile: paths that never enter the word loop retain incoming EDX; word paths retain the last source dword, possibly masked after a NUL. Flags are modified and are excluded from the reconstruction's output contract. There are no calls, globals, RNG accesses or locale state reads.

For valid, stable, disjoint memory, exactly `count` destination bytes are written when count is nonzero. Source bytes before the first NUL are copied. The first NUL and all remaining bytes within count become zero. If no NUL occurs within count, no terminator is added. Count zero performs no source read and no destination write, although it still reads stack arguments, saves/restores EDI and reads the return address. The static count contract is unsigned 32-bit; the TypeScript admission bound is 0 through 65.

| Region / sites | Control and observable effects |
| --- | --- |
| `009466d0..009466f2` | Load count; save EDI; zero count branches to the short return. Positive count also saves ESI/EBX, then loads source and destination. Source alignment selects leading bytes or dwords. |
| `009466f4..00946713` | Copy single bytes until source is aligned, count is exhausted, or a NUL appears. Each byte is read, source advances, byte is written and destination advances. The remaining-count test precedes the NUL test. On alignment, the remaining count is split into word count and low two remainder bits. |
| `00946715..00946729` | Byte remainder loop reads and writes one byte at a time. On NUL it decrements the remaining byte count before padding. On exhaustion it returns through the common restore sequence. |
| `0094672a..00946758` | A NUL in the unaligned source prefix triggers byte zero stores until destination alignment or count exhaustion, then word padding and a byte remainder. The byte padding path restores EBX/ESI before reloading the destination return value. |
| `00946759..00946791` | Each aligned source dword is read **twice**: first at `00946766` for `((~word) ^ (word + 0x7efefeff)) & 0x81010100`, then at `0094676f` for copying/lane tests. Source advances by four after the second read. A clear detector or a detector hit with all four lanes nonzero stores the full dword and continues. |
| `00946793..009467b5` | A NUL in lane 3 stores the unchanged dword. A NUL in lanes 2/1 stores `word & 0xffff` / `word & 0xff`; lane 0 stores zero. Thus bytes after the first NUL in that destination word become zero in the same dword store. EAX is cleared and the word count decreases. |
| `009467b7..009467cd` | Write remaining zero dwords, then `remaining & 3` zero bytes. Restore saved registers and return the original destination. |

Dword source reads require source alignment; dword destination stores can be unaligned. Only the special prefix-NUL padding path first aligns the destination. Word reads may touch up to three source bytes after the first NUL; the model preserves this access behavior. In these fixtures, 1,352 executions read beyond the NUL and the largest excess is three bytes. No observed source operand extends beyond the count interval. Source/destination memory is ordinary stable memory; repeated reads must not be treated as one access when considering volatile or concurrently changed storage.

## Original instruction oracle and admitted matrix

The fixture is the Cartesian product of four source alignments, four destination alignments, 24 counts and 18 patterns: `4 × 4 × 24 × 18 = 6,912`. Source and destination have separate 96-byte mapped synthetic buffers. The fixed addresses are `00200f00 + source_alignment` and `00210f00 + destination_alignment`; the valid synthetic stack starts at entry ESP `10000800`.

Counts are `0..17`, `31`, `32`, `33`, `63`, `64`, `65`. Fourteen patterns place NUL at offsets `0,1,2,3,4,7,15,16,17,31,32,63,64,65` in otherwise nonzero generated bytes. A fifteenth pattern has no NUL. Three additional patterns fill source with `0x80`, `0xff` or `1`, exercising word detector carry/false-hit behavior. NUL positions before, equal to and beyond count test padding/truncation; byte and dword transitions, all four NUL lanes, all sixteen alignment pairs, zero count, and nonterminated copies are covered. GPR seeds vary deterministically per row; they are not an exhaustive Cartesian product of register bit patterns. Native EFLAGS starts at `0x202` and is not compared.

The code hook admits only the original 109 instruction starts. Every trace begins at `009466d0` and ends at one of the three native returns. Every consecutive native edge must belong to the statically verified CFG; aggregate coverage equals the complete local instruction and edge inventories. Return counts are 4,184 at `00946729`, 2,098 at `00946758` and 630 at `009467cd`. There are 288 zero-count cases.

The comparison includes all eight general registers (EAX/ECX/EDX/ESP/EBX/EBP/ESI/EDI), the popped return PC, all 96 destination bytes, and a 36-byte stack window from entry `ESP-16` through `ESP+19`. Each source/stack read and destination/stack write is compared in order, with its relative address, operand width and value. There are no destination reads or source writes. The stack comparison includes count/source/destination/return-address reads, EDI spill at `ESP-4`, ESI at `ESP-8`, EBX at `ESP-12`, corresponding restores, unchanged arguments and sentinel bytes. The two epilogue load/restore orders are preserved. The oracle also verifies unchanged source bytes, replays all destination/stack writes, and independently checks ordinary copy/pad output. No expected output is generated by the TypeScript model.

TypeScript admits integral unsigned register/pointer values, count 0..65, valid stack snapshots with matching arguments, nonwrapping address extents, and disjoint source/destination/stack address ranges. It rejects shared overlapping source/destination views, invalid counts, inconsistent stack input, unmapped reads and writes. An aligned source containing only a single readable NUL is insufficient when a native dword read would be required: the model rejects it rather than reducing that read to one byte.

The oracle executes a finite matrix on valid synthetic mappings. It does not validate overlapping/aliasing source, destination or stack; invalid pointers, access violations, OS/SEH behavior, memory-mapped I/O, concurrent mutation, all possible count or byte patterns, caller behavior, locale initialization, path-library behavior, or gameplay semantics. In particular, native count zero does not dereference the source or destination, but the TypeScript API still enforces its synthetic admission constraints. No C undefined behavior or pointer fault behavior is supplied by the model.

## Verification and reproduction

Normal Python 3.13.7 and `python -O` extractors, emulator and negative tests pass. Sites, gzip oracle and negative receipt are byte-identical between normal and optimized runs. Capstone is 5.0.7; Unicorn is 2.1.4. Node v24.19.0 passes the task checker and the baseline `npm run check`. The coordinator can add the task checker to the central suite during integration.

Five integrity changes are rejected: a specimen byte, native source-read width, existing native name, existing native comment, and retained oracle byte. Six model changes are rejected: destination output, volatile register, stack byte, return PC, removal of a source read, and destination store width. Eight TypeScript admission checks reject negative/overbound count, overlapping views, overlapping address ranges, address wrap, short stack, noninteger register and an insufficient readable source word.

Run from the checkout; outputs for regeneration must be new paths:

```powershell
python scripts/extract_strncpy_runtime_26.py ../Reversal/downloads/cm0102.exe --exports ../private-native-verify/exports-26 --preflight ../private-native-verify/annotation-preflight-26.json --output results/strncpy-sites.json
python scripts/emulate_strncpy_runtime_26.py ../Reversal/downloads/cm0102.exe --exports ../private-native-verify/exports-26 --preflight ../private-native-verify/annotation-preflight-26.json --output results/strncpy-oracle.json.gz
python scripts/check_strncpy_runtime_26_negative.py ../Reversal/downloads/cm0102.exe --exports ../private-native-verify/exports-26 --preflight ../private-native-verify/annotation-preflight-26.json --node <Node24-executable> --output results/strncpy-negative.json
node reconstruction/check-strncpy-runtime-26.ts
npm run check
```

Repeat the three Python commands with `-O` and distinct output paths. A task-specific `.gitattributes` binary override protects the gzip oracle from the repository's evidence text conversion; the staged blob hash is verified against the pinned fixture hash. The executable, native export files, full decompilation, mutation copies and native database remain outside Git. Committed artifacts contain authored code/findings, digests, compact address/operand evidence and verified generated synthetic numerical fixtures only.

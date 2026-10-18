# R26-C — league row comparator and shared rule table

`006834f0` is a call-free comparator over two borrowed rows. It first compares signed WORD `+0x19`, then uses up to four shared rule bytes to choose signed row metrics. Its return is the second metric minus the first, so a negative result places the row with the larger metric first under the conventional sort contract. Field meanings and final standings remain unresolved.

The complete 178-byte local body and the external five-entry switch table are verified against the pinned original PE. A headless TypeScript reconstruction matches **840 original-entry-to-return executions, 40,128 x86 instruction steps and 17,891 ordered memory events**, covering all 67 instructions and every local branch/switch edge. The fixtures are synthetic stable records, shared state and stack; the sort caller does not execute.

## Provenance and complete CFG

All addresses are virtual unless labelled file offset. Baseline: checkpoint 25, main `1db4da1ef3b123879eea1fc2148c145850865f9e`. Read-only `cm0102.exe`: SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`.

| Evidence | Pinned value |
| --- | --- |
| Native checkpoint archive | `670587a05d1f75ae729c32a93e3ba5739f3d513a3c27126ddd4d9185b8620b6a` |
| Private export manifest | `e86692ed3575e204e9e22c5c6d15bba0f5a299d1bc30ce64111b25f0e66cad75` |
| Exact-old annotation preflight | `b06dff40898efb2ba18f02c7cfe49d272377bc9854920eb1ab1332c4093331fd` |
| Body `006834f0..006835a1`, file offset `002834f0`, 178 bytes | `6d08215550e4a70622f50d9cf87e401edb59c20037c272a815697a5a722ada33` |
| Table `006835a4..006835b7`, file offset `002835a4`, 20 bytes | `db1835fa55fd6b84aa49555e828ac096edf165e009215802a8cfc5abf01d8c7e` |
| Retained deterministic gzip oracle, 164,929 bytes | `61d70223745ee7f928dcb6aa16fecfc74d16050cdab16309dd4d53118790f61f` |
| Decompressed JSON, 1,845,201 bytes | `515149d388520acfab141cf9c229edf8bd6676a6d30def46c6d3809d2cdb1775` |

The [extractor](../scripts/extract_league_comparator_26.py) verifies the entire specimen, every private export digest, preflight and every native/PE instruction operand. Only whitespace, hexadecimal formatting, branch aliases, scale-one spelling and Ghidra's implicit DWORD on the absolute accumulator load are normalized. The [compact sites](../evidence/league-comparator-26-sites.json) include instruction starts, read widths, branch destinations and body/table digests; bulk assembly and pseudocode remain private.

The indirect jump at `00683549` reads DWORD `[006835a4 + EAX*4]`. The exact selected table bytes are `503568006a356800863568009235680078356800`, little endian:

| Rule byte | Table slot | Destination | Metric, compared as second minus first |
| --- | --- | --- | --- |
| 1 | `006835a4` | `00683550` | `signed16(row+0x15) - signed16(row+0x17)` |
| 2 | `006835a8` | `0068356a` | `signed16(row+0x15)` |
| 3 | `006835ac` | `00683586` | `signed8(row+0x12)` |
| 4 | `006835b0` | `00683592` | No comparison; advance to the next byte |
| 5 | `006835b4` | `00683578` | `signed16(row+0x31)` |

The table is outside Ghidra's 178-byte body. All five destinations are existing instructions inside that body, and all reachable control flow stays inside it until plain `RET` at `00683527` or `006835a1`. No Ghidra body expansion is needed. There are no calls, RNG operations, heap effects or explicit data writes; four stack saves are the only writes.

## ABI, read order and return

The entry takes two row addresses at entry `[ESP+4]` and `[ESP+8]`, with no required incoming ECX/EDX value. It preserves EBX, EBP, ESI and EDI. Both returns consume only the return address: caller cleanup, cdecl-style two-pointer comparator. The TypeScript reconstruction also models the observed EAX/ECX/EDX outputs and all stack save/load events; EFLAGS are outside its comparison contract.

1. Save EBX/EBP/ESI, read argument 1 into ESI, then save EDI. Read DWORD `[left+0]`. If it is zero, return zero without reading argument 2 or its row.
2. Read argument 2 into EDX and DWORD `[right+0]`. If that key is zero, return zero. These are row contents tested for zero, not checks that the argument addresses are valid.
3. Read WORD `[left+0x19]`, then WORD `[right+0x19]`. Unequal raw WORDs are sign-extended and returned as `right-left` through `00683521..00683527`. These unaligned field offsets retain their actual 16-bit widths.
4. Only if both keys are nonzero and the primary fields tie, read DWORD `[00b679fc]` once. Let that borrowed shared address be `S`. Begin at byte `[S+0xc5]`.
5. A zero rule byte returns zero immediately. A nonzero byte is sign-extended, decremented and tested unsigned against 4. Values 1..5 read the corresponding original table entry; all other nonzero values, including `0x80..0xff`, skip comparison and advance.
6. The selected metric is compared. The first difference returns `right-left`. For rule 1 the exact row-read order is **left WORD +0x17, left WORD +0x15, right WORD +0x17, right WORD +0x15**. Rules 2, 3 and 5 read the left metric then the right metric. Equal metrics advance to the next byte.
7. Increment the rule pointer. The arithmetic based on `EBX=-0xc5-S` produces the current byte index; a signed comparison continues while it is less than four. Thus only `S+0xc5..S+0xc8` may be inspected. Four equal/ignored rules return zero, with no further fallback on key identity.

The return is an integer difference rather than a normalized -1/0/+1. Primary, rule 2 and rule 5 differences are within ±65,535; rule 3 within ±255; rule 1 within ±131,070. All fit signed 32-bit arithmetic. The oracle reaches both ±131,070 boundaries. The public [TypeScript module](../reconstruction/league-comparator-26.ts) exposes memory reads/writes explicitly, preserving the short-circuit order as well as signed interpretation.

## Stable-state ordering and caller limits

For a stable shared rule list and rows with nonzero keys, this is descending lexicographic order on the primary field followed by selected metrics up to the first zero rule or four-byte limit. Unknown rules and rule 4 add no metric. Repeated rules add no new distinction. The bounded numeric differences cannot overflow, supporting sign antisymmetry and transitivity over that stable domain. This is an inference from the complete arithmetic/control contract, not a claim that the real caller always supplies that domain.

Zero-key rows undermine equality transitivity. The oracle includes A with key 1 and primary 1, B with key 0, and C with key 2 and primary 2. Original execution returns `compare(A,B)=0`, `compare(B,C)=0`, but `compare(A,C)=1`. Therefore the relation fails strict weak ordering if such a B is mixed with otherwise distinguishable rows. No key-zero precondition is established for every caller.

The body writes no input/shared memory, so two identical row pointers are admissible in the tested domain and return zero. Eight same-row alias cases execute. Arbitrarily overlapping row/config regions are not tested; stack/input aliasing is excluded because the prologue writes its save slots. Valid mapped pointers and stable storage are required. There is no shared-pointer null guard, no row-length validation and no synchronization. A changed shared pointer or changed rule/row bytes across comparisons can invalidate a sort's ordering assumptions; the single shared-pointer load is only a per-call snapshot of that address.

The existing [R10-C caller contract](league-boundary-10.md) remains context: `00682b30` constructs 59-byte scratch rows, passes this callback to sort-like `00945333` at `00682d27`, then calls it directly on adjacent scratch rows at `00682dd2` to decide whether to decrement a bucket counter. It writes byte +4 of matching borrowed input rows and frees scratch. The earlier caller `006827d0` sets `00b679fc` to its receiver at `0068281e`. Another caller later overwrites byte +4. This establishes a shared competition-related comparator dependency and output lifetime limits; it does not establish field names, final ranking rules, tie handling of the CRT implementation or final standings. No connected sort or caller lifecycle is execution-validated here.

## Execution evidence and reproduction

The [emulator](../scripts/emulate_league_comparator_26.py) loads only the pinned original 178-byte body and 20-byte table into Unicorn. It executes from entry through an original RET without stubs or substituted instructions. Synthetic pages for rows, shared rules and the shared-pointer slot are read-only; the stack is writable. Every executed address must be a verified instruction start. Every data/stack read, width, value and order is captured, including indirect table reads, argument loads, save-slot reads and return-address reads. Four stack-save writes are captured and replayed against the complete final stack window. The comparator's actual integer registers and ESP are retained.

The 840-case schedule contains four key guards, the three transitivity witness pairs, 25 primary boundary pairs, all 256 rule-byte values, 400 meaningful-rule boundary pairs across all four positions, eight equal lists, eight identical-pointer aliases, eight meaningful priority cases and 128 deterministic synthetic combinations. Row base alignment varies across all four residues. WORD domains include -32,768, -1, 0, 1 and 32,767; BYTE domains include -128, -1, 0, 1 and 127. The oracle covers 79 in-body instruction edges, including every conditional outcome and all five indirect destinations. It does not exhaust every possible row byte combination.

The retained oracle uses gzip level 9 with `mtime=0`, with an exact binary override in `.gitattributes` so Git preserves its bytes. The [retained checker](../reconstruction/check-league-comparator-26.ts) pins both the compressed and decompressed digests and the oracle provenance and compares all eight tracked integer registers, return address, final stack bytes and the full ordered memory-event sequence with the TypeScript implementation. The [negative checks](../scripts/check_league_comparator_26_negative.py) reject seven independent mutations: original instruction byte, external table byte, native field width, exact-old name, oracle metadata, return result and read order. Their [receipt](../evidence/league-comparator-26-negative.json) records the rejection gates.

Python 3.13.7 / Capstone 5.0.7 / Unicorn 2.1.4 ran both normal and `-O` extraction, emulation and negative checks; the resulting three artifact pairs were byte-identical. Node 24.19.0 ran the task checker and the inherited `npm run check`, both passing. The task checker is separate from the shared check runner; coordinator integration is required for CI to invoke it automatically. Validation scope and hashes are recorded in [the receipt](../evidence/league-comparator-26-validation.json).

From the checkout root, with the pinned specimen and private exports available:

```text
python scripts/extract_league_comparator_26.py PATH_TO_EXE --exports PRIVATE_EXPORTS_26 --preflight PRIVATE_PREFLIGHT_26 --output results/league-comparator-26-sites.json
python scripts/emulate_league_comparator_26.py PATH_TO_EXE --exports PRIVATE_EXPORTS_26 --preflight PRIVATE_PREFLIGHT_26 --output results/league-comparator-26-oracle.json.gz
node reconstruction/check-league-comparator-26.ts results/league-comparator-26-oracle.json.gz
python scripts/check_league_comparator_26_negative.py PATH_TO_EXE --exports PRIVATE_EXPORTS_26 --preflight PRIVATE_PREFLIGHT_26 --node PATH_TO_NODE24 --output results/league-comparator-26-negative.json
npm run check
```

Use new `.json.gz` emulator output paths; it writes deterministic gzip and refuses to overwrite evidence. Repeat Python commands with `-O` to verify optimized-mode integrity. The checked-in fixtures contain synthetic records, stack and resulting instruction-address traces, plus the selected 20-byte dispatch table in compact static evidence. They contain no original game records, executable body bytes, bulk decompilation, PE or native project files.

## Native proposal

The [name-only proposal](../evidence/league-comparator-26-annotations.json) supplies exact-old `FUN_006834f0` → `cm0102_compare_league_rows_by_shared_rules_candidate`, with 178 expected body addresses and the hash-pinned preflight above. Confidence is high for this bounded local mechanism; business field names remain unknown. No prototype, comment, body expansion or structural annotation is proposed. Canonical Ghidra, shared registries, queue and checkpoint state remain coordinator-owned.

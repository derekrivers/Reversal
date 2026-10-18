# Investigation 15: four delegated database field readers

The four descriptor-1 helpers from [R14](db-wrapper-family-14.md) read ordered fields into caller records, widening selected input bytes into WORDs. Their destination strides are `0x245`, `0x44`, `0x46` and `0x6b`; their per-record requested transfer sizes are respectively 577, 65, 67 and 104 bytes. These are local static contracts, with opaque record identities and unresolved stream-helper effects.

Every address below is a **virtual address** in the 7,192,576-byte PE32 specimen SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Work started at merged checkpoint-14 baseline `a4fa4bc`. Entry file offsets here equal VA minus `00400000`; the extractor maps actual PE sections. The canonical native project and shared coverage/checkpoint files were not edited.

| Entry / last instruction | Body bytes / instructions | Destination stride | Requested bytes / calls per complete record | Observed R14 caller site |
| --- | --- | --- | --- | --- |
| `0054dc90` / `0054e5cc` | 2,365 / 805 | 581 (`0x245`) | 577 / 133 | `0054dc79` in `0054db50` |
| `0054e9a0` / `0054efce` | 1,583 / 583 | 68 (`0x44`) | 65 / 36 | `0054e98b` in `0054e880` |
| `0054f150` / `0054fbab` | 2,652 / 972 | 70 (`0x46`) | 67 / 62 | `0054f13b` in `0054f030` |
| `0054ffd0` / `005501cd` | 510 / 193 | 107 (`0x6b`) | 104 / 11 | `0054ffbb` in `0054feb0` |

## Shared ABI, selection and returns

The four entry stack arguments are `(stream, mode_raw32, destination, count_raw32)` at entry `ESP+4/+8/+0xc/+0x10`. These are the arguments marshalled by R14's descriptor-1 branches; the helper receives a count directly, and does not inspect a descriptor. Plain RET and caller cleanup support cdecl. Each preserves EBX, EBP, ESI and EDI. `0054dc90` reserves one extra DWORD via PUSH ECX for its local record counter; that local is overwritten and the final POP ECX does not promise preservation of entry ECX.

Each field uses `(field_destination, field_width, 1, stream)`. The **full DWORD** mode chooses `00945bfe` when zero and `00932c30` for every nonzero value. Most mode tests use EBX; the larger reader reloads the original mode from its stack argument during its inner array loops. Both alternatives have the same field widths, order and destination addresses. [R09](database-boundary-09.md) establishes read direction at this boundary. The nonzero mode selects the custom stream abstraction; its complete decoding, error and stream-advancement contract remains open.

Every call pair rejoins at `ADD ESP,0x10; CMP EAX,1; JC failure`. The exact predicate is **unsigned EAX below 1**, hence only raw DWORD zero fails; a value greater than one also passes locally. Do not replace this with an exact item-count equality. The common failure epilogues are `0054e5c5`, `0054efc8`, `0054fba5` and `005501c7`; each returns exact DWORD zero. The complete success epilogues return exact DWORD one at `0054e5bd`, `0054efc1`, `0054fb9e` and `005501c0`.

The initial `TEST count,count; JBE success` skips precisely zero, since TEST clears CF. The record loop uses an unsigned carry comparison against the original count. No signed-positive bound, destination-capacity check or multiplication-overflow check is present. For ordinary nonaliasing caller storage, record `i` starts at `destination + i*stride`, with native 32-bit address arithmetic. A zero count succeeds without reading a stream or dereferencing the destination.

A helper zero return stops immediately: no later field or record is attempted. Previously completed fields and records stay modified, and a failed direct field read can already have partially changed its destination. Scratch-byte conversions occur only after that scratch read passes its check, so a failed scratch read skips its corresponding WORD store. There is no rollback or stream rewind. Exact bytes transferred and stream position on a failure depend on the unresolved helper bodies.

## Exact field order

All destination offsets below are hexadecimal and relative to the current destination record. Widths and repetition counts are decimal. A repeated range means **separate width-byte, count-one helper calls**, in increasing offset order, rather than one array-sized read. Sequence numbers count dynamic calls per record. `scratch → WORD` means a one-byte read into a reused caller stack slot followed by a two-byte destination store after success. No semantic field or string names are assigned.

### `0054dc90`

| Sequence | Destination offset(s) | Read width each | Repetitions / conversion |
| --- | --- | ---: | --- |
| 1 | `+00` | 4 | 1 |
| 2 | `+04` | 51 | 1 |
| 3 | `+38` | 26 | 1 |
| 4–6 | `+53,+57,+5b` | 4 | 3 |
| 7 | `+5f` | 1 | 1 |
| 8 | `+60` | 4 | 1 |
| 9 | `+64` | 1 | 1 |
| 10–11 | `+65,+69` | 4 | 2 |
| 12 | `+6d` | 1 | 1 |
| 13 | `+6e` | 4 | 1 |
| 14 | `+72` | 1 | 1 |
| 15–17 | `+73,+77,+7b` | 4 | 3 |
| 18 | `+7f` | 1 | 1 |
| 19 | scratch → WORD `+80` | 1 | zero maps to 1, multiply by 500, retain low 16 bits |
| 20 | `+82` | 1 | 1 |
| 21–36 | `+83..+bf`, step 4 | 4 | 16 |
| 37–39 | `+c3..+cb`, step 4 | 4 | 3 |
| 40–41 | `+cf,+d3` | 4 | 2 |
| 42–91 | `+d7..+19b`, step 4 | 4 | 50 |
| 92–96 | `+19f..+1af`, step 4 | 4 | 5 |
| 97–103 | `+1b3..+1cb`, step 4 | 4 | 7 |
| 104–106 | `+1cf..+1d7`, step 4 | 4 | 3 |
| 107 | `+1db` | 4 | 1 |
| 108 | `+1df` | 1 | 1 |
| 109–128 | `+1e0..+22c`, step 4 | 4 | 20 |
| 129–132 | `+230..+23c`, step 4 | 4 | 4 |
| 133 | `+240` | 4 | 1 |

The seven actual inner loops have bounds 3, 50, 5, 7, 3, 20 and 4 at `0054e35f`, `0054e3fc`, `0054e433`, `0054e46a`, `0054e4a1`, `0054e53e` and `0054e571`; they advance their destination by four. The `+83..+bf` sequence is unrolled. Entry arithmetic at `0054dcb7..0054dccc` and its zero-mode alternative forms `i*581`; the final iteration comparison is at `0054e5ae`.

The conversion at `0054dfe0..0054e00c` zero-extends the scratch byte to AX, stores WORD `+80`, substitutes one if zero, and executes **16-bit** `IMUL AX,AX,0x1f4` before storing AX. Thus the final value is `((b == 0 ? 1 : b) * 500) & 0xffff`, with no saturation. Examples calculated from these instructions: 0 and 1 produce 500, 131 produces 65,500, 132 produces 464, and 255 produces 61,964. The scratch read overwrites only the low byte of the entry stream-argument slot; ESI already holds the stream pointer. R14's descriptor-2 wrapper instead repairs zero WORDs after a complete block read; that separate branch does not perform this multiplication.

Offsets `+37`, `+52` and `+244` are untouched by the local successful record path. In particular, the 51- and 26-byte transfers do not include `+37` and `+52`; there is no local terminator write. The record is not cleared.

### `0054e9a0`

| Sequence | Destination offset(s) | Read width each | Repetitions / conversion |
| --- | --- | ---: | --- |
| 1 | `+00` | 4 | 1 |
| 2–3 | `+04,+06` | 2 | 2 |
| 4–6 | scratch → WORDs `+08,+0a,+0c` | 1 | 3; each byte zero-extended |
| 7–27 | `+0e..+22`, step 1 | 1 | 21 |
| 28–35 | `+23..+3f`, step 4 | 4 | 8 |
| 36 | `+43` | 1 | 1 |

WORD stores are at `0054ea86`, `0054eabb` and `0054eaf0`, after MOVZX at `0054ea7b`, `0054eab0` and `0054eae5`. Scratch reads reuse the low byte of the entry mode-argument slot; EBX already holds the full original mode. Zero stays zero, with no scaling. Entry arithmetic forms `i*68`, and `0054efb6` controls the unsigned outer loop. Every byte of the 68-byte destination record is written on success.

### `0054f150`

| Sequence | Destination offset(s) | Read width each | Repetitions / conversion |
| --- | --- | ---: | --- |
| 1 | `+00` | 4 | 1 |
| 2 | `+04` | 1 | 1 |
| 3–4 | `+05,+07` | 2 | 2 |
| 5–7 | scratch → WORDs `+09,+0b,+0d` | 1 | 3; each byte zero-extended |
| 8–62 | `+0f..+45`, step 1 | 1 | 55 |

WORD stores are at `0054f262`, `0054f297` and `0054f2cc`, after MOVZX at `0054f257`, `0054f28c` and `0054f2c1`. These also reuse the low byte of the entry mode-argument slot after saving the full mode in EBX. Zero stays zero. Entry arithmetic forms `i*70`; the final unsigned loop comparison is `0054fb93`. Every byte of the 70-byte destination record is written on success. The WORDs at odd offsets are unaligned stores, not inferred aligned fields.

### `0054ffd0`

| Sequence | Destination offset(s) | Read width each | Repetitions / conversion |
| --- | --- | ---: | --- |
| 1 | `+00` | 4 | 1 |
| 2 | `+04` | 51 | 1 |
| 3 | `+38` | 26 | 1 |
| 4 | `+53` | 4 | 1 |
| 5–6 | `+57,+58` | 1 | 2 |
| 7–10 | `+59,+5d,+61,+65` | 4 | 4 |
| 11 | scratch → WORD `+69` | 1 | zero-extended |

ESI begins at record `+38`; each completed record adds `0x6b` to it at `005501b2`. MOVZX at `005501a3` and the WORD store `[ESI+0x31]` at `005501a9` establish destination `+69`, not `+31`. Scratch reads reuse the low byte of the entry destination-argument slot, after ESI has captured its derived address. Zero stays zero. `005501b5` controls the unsigned outer loop. Offsets `+37` and `+52` are untouched; there is no local clearing or terminator write.

## Ownership and limits

The local bodies allocate or free no heap storage, open or close no streams, call no RNG, and access no explicit global state. Their only direct callees are the two read helpers. They borrow stream and destination; direct destination writes, scratch writes and the documented WORD conversions are immediate effects. Allocation owner, destination capacity/lifetime, stream lifetime, helper-global effects and any possible transitive RNG or allocation effects remain unresolved.

The requested-byte totals sum item sizes in field order. They do not establish physical file offsets, compressed bytes consumed, complete disk compatibility, semantic record identities, a whole database/save schema, or executable runtime reachability. Each native export reports one incoming wrapper call; this inventory does not exclude indirect or unrecognized references. The field positions are destination offsets supported by owned instructions, not original source declarations.

## Evidence and reproduction

[Sites](../evidence/db-field-readers-15-sites.json) retain every transfer group's call/check addresses, requested stream offset, widths, loop repeats, destination offsets, holes, selected entry/conversion/loop/exit instructions, span hashes, native export hashes and discovered incoming refs. [Findings](../evidence/db-field-readers-15-findings.json) summarize the contracts and unresolved effects. The optional [name-only proposals](../evidence/db-field-readers-15-annotations.json) identify record strides and conversions without semantic record names.

The [extractor](../evidence/db-field-readers-15-extract.py) uses Capstone **5.0.7** to independently decode all **2,553 instructions / 7,110 bytes**, then compares each address and normalized mnemonic/operands against checkpoint-14 Ghidra assembly. All match. It checks every owned `.asm`, `.c` and `.refs` against private manifest SHA-256 `65503dc3cf33eff2a9a40c1cdc456f5798bc8e04d1d9bbad6132c06b9677ca58`. Decompiler output was secondary context; assembly fixes the unsigned failure check, memory widths and multiply truncation. No original bytes, complete instruction listing, game records or bulk decompiled source is retained publicly.

```text
python evidence/db-field-readers-15-extract.py PATH_TO_PINNED_EXE PATH_TO_PRIVATE_EXPORTS_15 OUTPUT.json
```

Two runs produced byte-identical retained sites, SHA-256 `c6ead338daa9e2900fc32b60b72f4270a4e66f899cab164b0b8f9cea4811cf54`. Annotation old values agree with private preflight SHA-256 `c20393d151da0afff24f0ff7f806f91857d90f454cbff5a52d7bc0463517d1f1` and native decompiler headers; the coordinator must recheck exact old names before any application. No comments, prototypes, conventions or structures are proposed.

The `npm run check` entrypoint (`scripts/check-research.mjs`) passed when run directly with Node v24.19.0. It checks existing numerical fixtures and metadata; these four readers have static evidence only. The staged diff passed whitespace and privacy checks, with only the five assigned authored report/evidence/script files present.

Recommend **contract-supported** for all four complete local bodies. The stream helpers remain dependency boundaries. This is static instruction coverage; no connected game behavior, runtime oracle or execution-equivalence claim is added.

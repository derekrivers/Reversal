# Investigation 10: league record and weighted-amount boundaries

The three exact `league.cpp` entries expose a record-byte writer, a finance-related weighted distribution boundary and an arithmetic total helper. Their instruction contracts are recoverable without claiming a complete fixture, standings or game-result algorithm. This is static research: no new behavioral implementation, oracle or game execution is included.

Every address is a **virtual address** unless labelled file offset. The read-only specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; the branch starts at main `944954fd19b73a133f4505afc5b28a486479b45e`. The source-path anchor at `009f15f4` is `E:\dev\CM3\cm3 00-01\cm3\code\comp\league.cpp`. Its references corroborate source ownership, not original function names or business meaning.

| Entry | Inferred inclusive body bytes | Entry file offset | Native instructions | ABI / boundary |
| --- | --- | --- | ---: | --- |
| `00682b30` | `00682b30..00682e09` | `00282b30` | 215 | ECX receiver, one table pointer argument, `RET 4`; writes input row byte +4 |
| `00682e10` | `00682e10..00682f61` | `00282e10` | 115 | ECX receiver, no stack arguments, plain `RET`; dispatch or weighted finance helper calls |
| `00682f70` | `00682f70..00683006` | `00282f70` | 47 | ECX receiver, one DWORD increment argument, `RET 4`; returns DWORD sum in EAX |

The first and third entries have thiscall-style evidence. The second also consumes ECX and reads no EDX input. Ghidra calls it fastcall; with no stack arguments this does not establish an additional argument. No native prototype replacement is proposed. No semantic return is established for the first two functions.

## `00682b30`: peer aggregates and an input byte

The receiver's **signed 16-bit count at +0x3e** is loaded at `00682b3c` before a calloc-like allocation `00945501(count,0x3b)` at `00682b45`. The helper's zero-fill branches were inspected locally. The returned scratch allocation is checked for null. Failure emits a source-path diagnostic with constant 381, clears DWORD `00b67a34` and returns; there is no explicit termination call. There is no positive-count validation before allocation.

On the successful path, the stack argument is a borrowed table with **59-byte rows**. Each input row's raw DWORD key at +0 is copied into the corresponding zeroed scratch row. Distinct input rows qualify as peers only if their **WORD +0x19 values are equal** (`00682c1b..00682c24`). For each qualifying peer, the input row's **pointer at +5** selects a table of 14-byte entries, searched up to count-1 entries for a matching DWORD key. These unaligned fields must retain their assembly widths; semantic record names remain unresolved.

A matched nested entry contributes four bytes at +4/+5/+6/+7 into scratch bytes +0x11/+0x12/+0x13/+0x14, and three words at +8/+0xa/+0xc into scratch words +0x15/+0x17/+0x19. The writes at `00682c89`, `00682c9b`, `00682cad`, `00682cbf`, `00682ccc`, `00682cda` and `00682ce8` establish 8-bit or 16-bit wrapping accumulation. They do not establish goals, points or wins field names.

The scratch table is passed to sort-like helper `00945333` with signed count, stride `0x3b` and comparator `006834f0` at `00682d27`. The comparator is a dependency: its inspected body uses the **shared pointer at `00b679fc`**, so treating this as a pure receiver-local sorting contract would omit state. After sorting, each scratch key is matched to the first input row with the same DWORD key. Its byte +4 receives the low byte of a bucket counter at `00682d94`. The counter starts at count and decrements by one only when the adjacent scratch comparator returns nonzero (`00682dd2..00682dde`). Full comparator ordering/configuration and meaningful ranking conventions remain outside this contract.

Only scratch is freed (`00682df5`); the input table and nested entries are borrowed, and this body does not reorder the input table or write receiver fields. The two native incoming calls are `00682877` in `006827d0` and `006471b0` in `006471a0`. The former sets `00b679fc` to the receiver at `0068281e` and can fall back to receiver +0xb1 for the table. The latter explicitly passes receiver +0xb1 and **later overwrites byte +4 with sequential values at `00647213`**, after another sort. The output's lifetime therefore depends on the caller; it cannot be described here as a final standing.

## `00682e10`: selector, registry dispatch or weighted credits

The **byte selector at receiver +0xe1** is read at `00682e1b`. Value 2 returns immediately. Value 3 selects a registry path: `00adadfc` must be nonzero; the DWORD reached through receiver +4 indexes that registry, and the selected object's vtable slot +0x6c is called at `00682eb2` with ECX set to that object and the original receiver pushed. Its concrete target and transitive effects remain unresolved. A null registry emits diagnostic 479, clears `00b67a34` and returns.

Every other selector takes the arithmetic path. With count n from signed WORD +0x3e, it builds `1+2+...+n`, then **sign-extends only AX** at `00682ed6`. The signed DWORD numerator at receiver +0x28 is divided by that signed 16-bit divisor at `00682edf`. This division executes **before** the positive-count guard at `00682ee8`: nonpositive counts leave a zero divisor and reach a division fault. Larger positive counts can also change the divisor through 16-bit truncation/sign interpretation. Real admissible count bounds are unknown; this is not a safe generic distribution API.

For a stable count n, each row index i multiplies `(n-i)` by the quotient with a 32-bit result. The receiver's pointer at +0xb1 selects 59-byte rows; row +0 supplies a record pointer to `005a0590`, using the object loaded from `00ae2a38` as ECX. The amount was already pushed and remains on the stack when that resolver returns with `RET 4`; the resolved EAX becomes ECX for `005999a0`, which consumes the remaining amount argument at `00682f1f`.

The bounded `005999a0` dependency adds that signed amount to target DWORDs +0x148 and +0xa8 and to its 64-bit pair at +0/+4. `005a0590` is anchored to `finance.CPP` and resolves through additional state; its full normalization and ownership remain open. This supports a **finance-related weighted distribution** interpretation. Economic units, allocation lifetime and the complete finance transaction are not established. Signed amounts greater than 1000 also trigger `0048e3e0` at `00682f48`, supplied with the record, sign-extended 64-bit amount, byte-sized index+1 and other raw arguments. Its complete notification/business effect is a dependency.

This body writes no receiver latch or direct receiver field. Repeated application is not prevented locally. The only native incoming call is `00689ba4` in `00689ad0`, immediately guarded by a zero test of receiver DWORD +0xe6. Earlier caller paths test table/flags and row counters, but the whole lifecycle and protection against duplicate credits are not recovered.

## `00682f70`: a weighted total producer

For a positive signed WORD count at receiver +0x3e, the sole DWORD increment argument is added as `x,2x,...,nx` using 32-bit additions (`00682ff3` / `00682ff5`). The returned EAX is therefore `x*n*(n+1)/2 modulo 2^32`, stated as a description of the static loop. No multiplication-based implementation or numerical oracle is introduced. Negative count returns zero. Exactly zero emits diagnostic 532 and clears `00b67a34`, then rechecks the count; if it remains zero, the return is zero. This diagnostic path does not terminate.

It writes no receiver/table field and allocates no memory. Forty-one native direct incoming calls were independently checked against the original E8 instructions and the atlas's 41 containing caller functions. Two bounded caller examples connect this total to the other owned function: at `00574b23`, increment 250000 is passed; `00574b28` stores EAX at receiver +0x28 and `00574b2b` writes selector byte 1. At `00405643`, increment 50000 is passed and `00405651` stores EAX at +0x28. These connect a producer and consumer of that raw total; they do not establish a complete competition lifecycle, currency or fixture algorithm.

## Evidence, uncertainty and reproduction

- [Findings](../evidence/league-boundary-10-findings.json) record widths, state effects, callers/dependencies and separate confidence levels.
- [Compact sites](../evidence/league-boundary-10-sites.json) contain selected decoded instructions, function-span digests, native export digests and exact incoming call sites. All 215/115/47 instructions match the coordinator's read-only Ghidra exports after documented textual normalization. No bulk listing, pseudocode or original record data is tracked.
- [Extractor](../evidence/league-boundary-10-extract.py) checks the pinned SHA, maps PE addresses, regenerates selected sites with `capstone==5.0.7`, and optionally compares private native exports via `--native-dir`. It never executes the specimen.
- [Annotation proposal](../evidence/league-boundary-10-annotations.json) supplies three candidate names and four comments, confined to the owned bodies. No structures or prototypes are replaced. The canonical project, atlas and checkpoints are coordinator-owned and unchanged by this work.

```text
python evidence/league-boundary-10-extract.py PATH_TO_PINNED_EXE results/league-boundary-10-sites.json --native-dir PATH_TO_PRIVATE_EXPORTS
```

The retained checks were run using Node 24.19.0. They validate the repository's existing numerical fixtures and metadata; they do not validate this league behavior. Ordered runtime state, external dispatch targets, full comparator/finance effects, input domains and final competition outcomes remain open.

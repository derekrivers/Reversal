# Investigation 16: database stream read helpers

`00945bfe` is a buffered, fread-shaped item reader. `00932c30` adds an indexed logical bound and selects byte-run decoding only when its stream's DWORD `+0x19` equals 4; every other internal mode delegates whole items to `00945bfe`. The R14/R15 caller's nonzero mode merely selects the custom stream object. These are complete **local static contracts**, with unresolved lower I/O/copy/refill dependencies and no full file-format or runtime equivalence claim.

All addresses are virtual addresses in the 7,192,576-byte PE32 specimen SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The branch baseline is `15eb7357500cf2dfd1838487e2a28e05d4965410`, checkpoint 15. The extractor maps PE sections; the two entry file offsets happen to be `00545bfe` and `00532c30`. Canonical Ghidra state and shared registries were not changed.

| Entry | Body bytes / instructions | Last instruction | Direct calls |
| --- | ---: | --- | --- |
| `00945bfe` | 232 / 92 | `00945ce4` | `0094ab50`, `0094b3e0`, `0094b307` |
| `00932c30` | 468 / 169 | `00932e03` | `00945bfe`, at three sites |

## Shared ABI and caller relationship

Both take `(destination, item_size_raw32, item_count_raw32, stream)` at entry `ESP+4/+8/+0xc/+0x10`, return EAX, preserve EBX/EBP/ESI/EDI and use plain RET with caller argument cleanup, supporting cdecl. ECX/EDX and flags are scratch. `00945bfe` uses a frame and one local DWORD; `00932c30` uses saved registers and overwrites the low byte of its already-captured stream argument slot as token scratch (`00932d08`, `00932d3f`). No prototype change is proposed.

[R14](db-wrapper-family-14.md) selects `00945bfe` for caller mode zero and `00932c30` for every nonzero full DWORD. Its block wrappers require exact returned item-count equality. [R15](db-field-readers-15.md) makes width-by-one field calls and fails only when the raw helper return is zero. The helpers here receive neither descriptor nor the caller mode argument. Record meaning, stream construction, initialization and reachability remain outside this assignment.

All arithmetic below is native 32-bit arithmetic unless specified. The simplified byte counts assume valid, disjoint stream/destination storage, nonnegative counters, positive item size and no arithmetic/address overflow; the exact signedness and wrapping cases are stated separately.

## `00945bfe`: buffered item reader

Let `T = low32(item_size * item_count)` and `R = T`. A zero product returns zero before dereferencing stream or destination (`00945c11..00945c1d`), including a product that wraps to zero. There is no overflow rejection. Otherwise EBX tracks destination and ESI stream; the following local fields are used:

| Stream offset | Access width | Observed use |
| --- | ---: | --- |
| `+0x00` | DWORD read/add | cached byte pointer |
| `+0x04` | DWORD read/subtract | cached available-byte count |
| `+0x0c` | WORD read; DWORD OR | mask `0x10c` enables cached state; OR `0x10`/`0x20` records lower-read zero/-1 |
| `+0x10` | DWORD read | first argument of lower read `0094b3e0` |
| `+0x18` | DWORD read | block quantum, also reloaded after successful single-byte refill |

Initial quantum `Q` is `[stream+0x18]` when the WORD flag mask intersects `0x10c`, otherwise 4096. Each loop does one of the following:

1. If the flag mask intersects and cached availability is nonzero, set `K = min_unsigned(R, availability)` and call `0094ab50(destination, cached_pointer, K)` at `00945c5c`. Its return is ignored. Locally subtract K from remaining and availability and add K to both cached and destination pointers. These updates are DWORD operations; no signed-positive availability check exists. This call has a copy-shaped boundary; its complete body, overlap behavior and fault effects are unresolved here.
2. Otherwise, if `R >=unsigned Q`, request `N = R - (R % Q)` bytes from `0094b3e0([stream+0x10], destination, N)` at `00945c8e`. If Q is zero, N is R and no division is performed. A zero result ORs DWORD flags with `0x10`; -1 ORs them with `0x20`; both stop. Any other returned DWORD is subtracted from R and added to destination before looping. There is no local check that the result is positive or at most N. Short positive results continue reading. Physical stream advancement and lower-helper writes are dependency effects.
3. If `R <unsigned Q`, call `0094b307(stream)` at `00945ca7`. Result -1 stops without a local flag OR; any other result stores AL as exactly one destination byte (`00945cb2`), advances destination by one, decrements R, and reloads Q from `[stream+0x18]`. Any refill, cursor or flag mutations inside that dependency remain unresolved.

When R reaches zero, EAX is the **original item count**, even if the multiplication wrapped to a smaller nonzero T. A stopped transfer returns unsigned `low32(T-R) / item_size` at `00945ce1`, counting only whole items. The nonzero-product path necessarily has nonzero item size, so this local division is not a size-zero trap. Destination can contain bytes of an incomplete final item. There is no rollback, rewind, destination clearing or terminator store. Flags are not cleared on entry or success. Cached stream advancement is explicit; physical file position cannot be equated to bytes returned because dependencies can buffer, transform or prefetch data.

## `00932c30`: indexed bound, internal mode and stream writes

Null stream returns zero at `00932c42`; any nonzero DWORD `[stream+4]` returns zero at `00932c50`, before destination access. For other inputs, define S as item size, `B = low32(S * item_count)`, C as DWORD `+8`, I as DWORD `+0xc`, and L as the unaligned DWORD at `stream + low32(I*0x10c) + 0x29`. The index has no local range check.

The exact clamp is **signed**: if `C >signed low32(L-B)`, set `B = low32(L-C)` and return zero if `B <=signed 0` (`00932c74..00932c88`). Otherwise B is unchanged. For ordinary nonnegative, nonoverflowing inputs this caps the requested byte count to the remaining bound. The raw signed/wrapping algorithm must not be replaced by an unqualified unsigned minimum. Next the function stores `low32(C+B)` into `+8` **before** testing internal mode or performing I/O (`00932c94`).

| Stream offset | Width | Access and local meaning |
| --- | ---: | --- |
| `+0x00` | DWORD | read underlying `00945bfe` stream pointer |
| `+0x04` | DWORD | read nonzero rejection gate |
| `+0x08` | DWORD | read/write logical byte position |
| `+0x0c` | DWORD | read indexed-bound selector |
| `+0x10` | DWORD | read/write repeat bytes already emitted |
| `+0x14` | DWORD | read/write repeat length |
| `+0x18` | BYTE | read/write repeated byte |
| `+0x19` | unaligned DWORD | read internal mode; exact value 4 selects decoder |
| `+I*0x10c+0x29` | unaligned DWORD | read selected logical bound |
| `+0x41705` | BYTE array | encoded refill destination; indexed byte reads |
| `+0xa3185` | unaligned DWORD | read/write encoded cursor |
| `+0xa318d` | unaligned DWORD | read/write encoded refill item count |

### Internal mode other than 4

Compute `J = signed_trunc(B / S)` with CDQ/IDIV at `00932ddc..00932ddf`. Replace `+8` with `low32(C + low32(S*J))`, then call `00945bfe(destination, S, J, [stream])` at `00932df7` and return its EAX unchanged. Thus only whole items are requested; a fractional bound remainder is excluded from logical advancement and I/O. The position is **not corrected for a short read**: it records requested whole-item bytes even when the underlying helper returns fewer items or zero. A zero S can fault on IDIV after the position store; unlike `00945bfe`, this function has no general zero-product fast return. Invalid signed inputs can also fault on signed division overflow or reach the lower helper as large raw counts.

### Internal mode 4: byte-run decoding

For positive signed B, emit exactly B bytes if execution completes. An existing repeat with nonzero length and signed cursor less than length first emits byte `+18`, incrementing DWORD cursor `+10` per destination byte (`00932cc6..00932cd3`). A partially consumed repeat is retained across calls. Once exhausted, zero both repeat counters and read the next token.

An encoded-byte fetch uses `buffer[cursor]` and increments encoded cursor when `cursor <signed fill_count`. Otherwise either refill site calls `00945bfe(stream+0x41705, 1, 200000, [stream])` (`00932d25`, `00932d99`), stores EAX as fill count, takes `buffer[0]` and sets encoded cursor to one. Both refill sites use the same request. The 200000 bytes are a requested refill size; this body does not establish allocation capacity or an original disk chunk boundary.

| Token value | Decoder action |
| --- | --- |
| `0x00..0x80` inclusive | emit token itself as one literal byte |
| `0x81..0xff` | set repeat length to `token-0x80` (1..127), fetch next encoded byte into `+18`, then emit through the repeat loop |

The split uses unsigned JA at `00932d45`: `0x80` is a literal. Repeat cursor and encoded cursor comparisons are signed. A repeat value can span a refill boundary; pending decoded repeats can serve later calls without consuming new encoded input. Destination writes are individual bytes; there is no output terminator or clearing.

Neither refill site checks for zero/short/error results before reading `buffer[0]`. A zero refill can therefore use stale or uninitialized buffer contents and continue emitting bytes. There is no local decoder EOF/error return and no rollback of `+8`. Existing cache content, initialization and lower-helper behavior determine malformed/truncated input effects; this is not a validated truncated-input policy.

On decoder completion EAX is **signed** `B / S`, regardless of refill success. Positive B need not be divisible by S: the decoder can write a partial final item, count only whole items, and retain `+8 = C+B`. For nonpositive B that survives the earlier clamp, it skips destination decoding and still executes IDIV. Zero S can fault. For a valid width-by-one R15 field request, a completed decoder call returns either one or the bound-clamped zero; this local return does not authenticate encoded input.

## Ownership, dependencies and remaining uncertainty

Both functions borrow destination and stream; neither has a direct allocator/free, open/close, RNG or explicit global access. Direct effects are destination byte stores, the listed stream-field writes, local argument-slot scratch writes, and the calls listed above. Lower helpers may add effects. `0094ab50` has a copy-shaped three-argument boundary; `0094b3e0` accepts `(opaque stream+10 value, destination, requested bytes)` and returns a byte-result consumed as described; `0094b307` accepts the stream and supplies a byte or -1. These complete lower bodies, physical file positioning, text translation, locking, error propagation and buffering ownership are still open. No OS import or standard-library identity is assigned from these call shapes alone.

Custom position `+8`, encoded buffer cursor and physical stream position are three distinct quantities. Decoder prefetch can consume encoded input well beyond the immediate output request, while a pending repeat can emit output without further input. Neither local body establishes full database/save compatibility, record identities, stream lifetime/capacity, a valid file corpus or a connected game execution oracle.

## Evidence and reproduction

[Sites](../evidence/db-stream-16-sites.json) retain body hashes, every call boundary, return sites, compact selected instructions and complete native comparison counts. [Findings](../evidence/db-stream-16-findings.json) retain the path/width contract and open dependencies; the optional [name-only proposal](../evidence/db-stream-16-annotations.json) changes no signature or structure.

The [extractor](../scripts/extract_db_stream_16.py) uses Capstone **5.0.7**, decodes all **261 instructions / 700 bytes**, compares every normalized address/mnemonic/operand against hash-pinned Ghidra assembly, and verifies all **40** local jump targets are owned instruction starts. Both `.asm` and `.c` exports match private manifest SHA-256 `fc92c27bcc9f2f15bedebb4aadbebba7bf0ed5f8801c787e2f0e262c48a7e960`; old names and headers match preflight SHA-256 `2be810e149b9d5ebe8de028bf9542aab932afd31514e2ec8d737bef8450374bc`. Decompiler output was secondary context. No bulk listing, original instruction bytes or private paths are retained.

```text
python scripts/extract_db_stream_16.py PATH_TO_PINNED_EXE PATH_TO_EXPORTS_16 PATH_TO_PREFLIGHT_16 OUTPUT.json
```

Two extraction runs produced byte-identical retained sites, SHA-256 `bcda9007b5caed038e781efd69fa441fa91ccf233e9fd586a097de44f9a22fca`. The Node v24.19.0 research check and `git diff --check` passed. Existing numerical checks cover earlier primitives; these two helpers have static instruction evidence only. Recommend **contract-supported** for both complete local bodies, with transitive I/O effects explicitly unresolved.

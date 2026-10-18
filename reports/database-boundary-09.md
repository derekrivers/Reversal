# Investigation 09: two database record loading boundaries

The exact entries `0054d5e0` and `0054d740` are fixed-size **read** wrappers. They transfer records into destinations supplied by their caller and return whether the helper reported the requested record count. The recovered sizes are 198 (`0xc6`) and 290 (`0x122`) bytes. Record names and fields remain unknown; this does not establish a complete database or saved-game format.

All addresses below are **virtual addresses** in the pinned 7,192,576-byte PE32 specimen with SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The corresponding entry file offsets are `0014d5e0` and `0014d740`. Original bytes were read locally and never changed or added to Git. The canonical native database was not modified.

## Exact contract

| Entry | Inferred inclusive body | Record bytes | Required descriptor DWORD at +0x3f | Single atlas caller site | Destination pointer holder used there |
| --- | --- | ---: | ---: | --- | --- |
| `0054d5e0` | `0054d5e0–0054d6d0` | 198 | 1 | `00528540:0052b44e` | `00ae23a4` |
| `0054d740` | `0054d740–0054d832` | 290 | 2 | `00528540:0052c070` | `00ae23a8` |

Both use four stack arguments: `(stream, mode_raw32, destination, descriptor)`. The caller pushes four DWORDs then removes `0x10` bytes; each wrapper uses plain `RET`, with no ECX receiver. This supports cdecl. Each reserves `0x200` local stack bytes, preserves ESI and leaves EBX/EBP/EDI unwritten. No prototype or signedness replacement is proposed.

The first instruction loads the fourth argument from entry `ESP+0x10`. A DWORD load from descriptor `+0x37` supplies the count (`0054d5eb` / `0054d74b`); a separate DWORD load from `+0x3f` supplies the equality guard (`0054d5ee` / `0054d74e`). These fields are unaligned DWORDs, not bytes or words. The required values 1 and 2 are established; naming this field a version or record type would exceed the evidence.

The complete DWORD mode argument is tested. Zero selects `00945bfe`; any nonzero value selects `00932c30`. Both receive `(destination, record_bytes, original_count, stream)` and the wrapper compares returned EAX with its saved original count. `SETE` plus a cleared register produces a DWORD return of exactly 0 or 1. There is no per-record loop, destination clearing, size/count range check or rollback in these wrapper bodies. In particular, success is an item-count equality; it does not validate record contents. A zero count can satisfy that equality without reading any record.

## Why the operation is a load

`00945bfe` has fread-like behavior: it computes `size * count`, copies buffered data into the supplied destination (`00945c5c`) or stores a byte there (`00945cb2`), and divides completed bytes by size at `00945ce1` on an incomplete transfer. Its other complete path returns count. This establishes read direction without relying on an imported symbol name.

`00932c30` likewise writes destination bytes (`00932cc6`). Its internal mode-4 branch contains byte-run decoding, while the other branch delegates to `00945bfe` at `00932df7`. The wrapper's nonzero mode selects this custom stream abstraction; it does not prove that every such stream is compressed. The helper body was inspected only to resolve read direction and the four argument positions. Its full decoder/stream contract is outside this report.

Both functions have the same nine direct callees in the retained atlas: `005a8f60`, `005cc7d0`, `005e8290`, `0090d130`, `00932c30`, `00944c9f`, `00944cff`, `00945934`, `00945bfe`. The last two read helpers occupy alternative normal paths; the remaining seven calls occur on the descriptor mismatch path. These two functions have no unresolved indirect call sites in that inventory.

## State and ownership

The caller loads pre-existing destination pointers from `00ae23a4` and `00ae23a8` and passes them as the third argument. The wrappers borrow destination, stream and descriptor pointers. They allocate and free no destination, open and close no normal-path stream, and write no descriptor fields. Allocation owner, destination lifetime, semantic record types and the full caller lifecycle remain unresolved. Reads mutate destination and stream through the selected helper; a false result does not undo a partial read.

At descriptor mismatch, the wrappers reference the `Db_files.cpp` path at `009b8dc0` (`0054d605` / `0054d767`). They prepare an error message using diagnostic constants 300 / 355, the format string at `009870e8`, and shared buffer `00ae24d0`, then call `005e8290` with the `Error` title at `009870e0`. They clear DWORD `00b67a34`, call `005cc7d0`, call the currently single-RET body `005a8f60`, and pass -1 to `00945934`. The latter enters termination machinery whose route at `009459e7` calls the PE import `KERNEL32.dll!ExitProcess` through `00967164`. This is a fatal diagnostic path, not a normal false-return branch. Detailed UI/cleanup ownership and original source line declarations are not claimed.

The retained atlas identifies one containing caller, `00528540` (`Database.cpp` anchor). At `0052b44e` and `0052c070`, the caller pushes the descriptor in ESI, the respective global destination, the raw mode and the stream, then checks EAX. The local caller excerpts support the ABI and destination handoff only. A single inferred caller is not proof that indirect or unrecognized references cannot exist. No behavioral contract is assigned here to adjacent database functions.

No RNG restoration is established: neither wrapper explicitly accesses a known RNG state or calls the RNG. They copy opaque record blocks, whose contents have not been interpreted. This also cannot exclude RNG persistence elsewhere in the program or in an unexamined record.

## Evidence and proposed annotation

- [Compact decoded sites and function-span digests](../evidence/database-boundary-09-sites.json) retain address-specific instructions, source/error string anchors and bounded caller/helper excerpts. They contain no raw code or game records.
- [Machine-readable findings](../evidence/database-boundary-09-findings.json) record the ABI, ownership, direct dependencies, evidence limits and uncertainty.
- [Annotation proposal](../evidence/database-boundary-09-annotations.json) proposes only the working names `cm0102_read_db_c6_records_checked` and `cm0102_read_db_122_records_checked` plus comments within their exact bodies. It makes no native edits and proposes no broader helper rename or structure/prototype replacement.
- [Static extractor](../evidence/database-boundary-09-extract.py) checks the specimen hash, maps virtual addresses through PE sections and regenerates the compact sites using `capstone==5.0.7`. It never executes the game. The original bytes and full local disassembly stay under ignored private paths.

Read-only native Ghidra exports supplied by the coordinator independently corroborate both exact bodies: all 69 instructions at `0054d5e0` and all 69 at `0054d740` match the pinned-byte decode after mnemonic/number/whitespace normalization. The checked sites include DWORD descriptor reads at `0054d5eb` / `0054d74b`, full DWORD mode branches at `0054d668` / `0054d7ca`, size pushes at `0054d683` / `0054d7e5`, read calls at `0054d689`, `0054d6b8`, `0054d7eb`, `0054d81a`, and zeroed-register equality results at `0054d693..0054d698` / `0054d7f5..0054d7fa`. Native incoming references also confirm the call from `0052c070` to `0054d740`. The supplied directory lacked a `0054d5e0` refs file at review time; the atlas and original-byte caller excerpt remain the basis for its `0052b44e` edge. No contract or annotation correction was required. Export digests and comparison counts are in the findings; bulk exports remain private.

To reproduce, install `capstone==5.0.7` into a local Python environment, then run:

```text
python evidence/database-boundary-09-extract.py PATH_TO_PINNED_EXE results/database-boundary-09-sites.json
```

Compare the generated JSON with the retained sites. `npm run check` verifies the repository's existing numerical fixtures and metadata; it does not runtime-test these reads or the full loader. This investigation uses static instruction evidence only, with no emulation, live file I/O or reconstructed loading implementation.

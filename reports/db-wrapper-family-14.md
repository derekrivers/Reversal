# Investigation 14: sixteen database read and dispatch wrappers

All sixteen assigned `Db_files.cpp` entries have direct fixed-size **read** paths. Twelve are simple checked reads; four also dispatch descriptor value 1 to separate field-read helpers. One of those four, `0054db50`, additionally repairs zero WORDs after a complete direct read. Treating the whole group as identical block-copy wrappers would miss these paths.

The contracts below concern complete **local wrapper bodies**. They establish no semantic record names, complete database/save schema, or full behavior of the delegated field readers. R09's `0054d5e0`/`0054d740` are reference context only.

All addresses are virtual addresses in the 7,192,576-byte PE32 specimen SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Work started from merged baseline `3d81fa3c056c7d28c3c2a6d99e93d96464f43834`. Entry file offsets are entry VA minus `00400000` for these spans; the extractor maps PE sections rather than assuming that subtraction generally.

## Verified family matrix

`G` means the opaque DWORD loaded from descriptor `+0x3f`; it is not assigned a version/type meaning. Every direct path passes `(destination, record_bytes, original_count, stream)`. The **full DWORD mode** selects `00945bfe` when zero and `00932c30` for every nonzero value, in every row. All direct transfers are into caller memory.

`EQ` means EAX is exactly 0 or 1 from helper-return equality with the saved original count. `FWD` means the wrapper passes the separate helper's EAX through unchanged, without checking total count itself. Every unlisted `G` value takes the shared fatal path. Diagnostic numbers below are literal constants, not claims about authenticated original source lines.

| Entry | Body bytes / instructions | Direct record bytes | Accepted G and normal paths | Return | Diagnostic constant |
| --- | --- | --- | --- | --- | --- |
| `0054d8a0` | 241 / 71 | 56 (`0x38`) | 1 or 2: direct read | EQ | 519 (`0x207`) |
| `0054da00` | 235 / 69 | 78 (`0x4e`) | 1: direct read | EQ | 573 (`0x23d`) |
| `0054db50` | 314 / 92 | 581 (`0x245`) | 1: `0054dc90`; 2: direct read, then WORD repair on full count | FWD / EQ | 645 (`0x285`) |
| `0054e630` | 237 / 69 | 110 (`0x6e`) | 2: direct read | EQ | 826 (`0x33a`) |
| `0054e780` | 241 / 69 | 157 (`0x9d`) | 1: direct read | EQ | 910 (`0x38e`) |
| `0054e880` | 283 / 83 | 68 (`0x44`) | 1: `0054e9a0`; 2: direct read | FWD / EQ | 1007 (`0x3ef`) |
| `0054f030` | 283 / 83 | 70 (`0x46`) | 1: `0054f150`; 2: direct read | FWD / EQ | 1146 (`0x47a`) |
| `0054fc10` | 235 / 69 | 52 (`0x34`) | 1: direct read | EQ | 1337 (`0x539`) |
| `0054fd60` | 235 / 69 | 17 (`0x11`) | 1: direct read | EQ | 1394 (`0x572`) |
| `0054feb0` | 283 / 83 | 107 (`0x6b`) | 1: `0054ffd0`; 2: direct read | FWD / EQ | 1449 (`0x5a9`) |
| `00550230` | 235 / 69 | 26 (`0x1a`) | 1: direct read | EQ | 1541 (`0x605`) |
| `00550380` | 237 / 69 | 101 (`0x65`) | 2: direct read | EQ | 1592 (`0x638`) |
| `005504d0` | 235 / 69 | 58 (`0x3a`) | 1: direct read | EQ | 1677 (`0x68d`) |
| `005505c0` | 235 / 69 | 43 (`0x2b`) | 1: direct read | EQ | 1738 (`0x6ca`) |
| `00550710` | 235 / 69 | 58 (`0x3a`) | 1: direct read | EQ | 1801 (`0x709`) |
| `00550860` | 235 / 69 | 60 (`0x3c`) | 1: direct read | EQ | 1850 (`0x73a`) |

The duplicated width `0x3a` does not establish identical record identities. The direct widths in the four dispatch rows apply **only to G=2**. Their G=1 branches contain no total on-disk record-size literal.

## ABI, widths and normal return

Each wrapper reads its fourth entry stack argument at `ESP+0x10` as a descriptor pointer, saves its DWORD `+0x37` in ESI as the requested count, and reads DWORD `+0x3f` as the guard. Both descriptor reads are unaligned 32-bit reads. The other arguments are `(stream, mode_raw32, destination)` at entry `ESP+4/+8/+0xc`. Each wrapper reserves `0x200` local bytes and preserves ESI; `0054db50` also saves/restores EDI. EBX and EBP remain untouched, as does EDI in the other fifteen. Plain RET and stack argument handling support cdecl; no prototype replacement is proposed.

The plain wrappers implement exact guard equality using DEC/JZ or SUB/JZ. `0054d8a0` instead uses signed `TEST/JLE` followed by `CMP 2/JG` at `0054d8b1..0054d8b8`; the accepted raw DWORD set is exactly {1,2}. Its normal paths precede its diagnostic block. The other simple wrappers place diagnostics before their normal paths. This layout difference is included in the full-body comparison.

The two normal read calls in each body push four arguments, including the exact literal width in the matrix, then discard `0x10` argument bytes. The common helpers' read direction is supported by [R09's bounded body inspection](database-boundary-09.md) and freshly decoded dependency sites: `00932cc6` and `00945cb2` store into destination memory; `00932df7` delegates to the fread-like helper; the copy call at `00945c5c` and division at `00945ce1` are further boundary context. These wrappers call no direct write helper. Nonzero mode selecting the custom stream abstraction does not establish that every such stream is compressed.

Direct paths compare helper EAX against the original count. Zeroed-register SETE sequences yield exact 0/1 in fifteen wrappers; `0054db50` uses explicit zero/one exits around its post-read loop. A count of zero can succeed without transferring records. No wrapper validates destination capacity, record contents, pointer nullness or the count range. A short read returns zero without rollback of destination or stream effects.

## Four dispatches and the WORD repair

At G=1, the four dispatch wrappers marshal `(stream, mode_raw32, destination, original_count)` to their respective helpers, replacing the descriptor argument with the count. Calls are at `0054dc79`, `0054e98b`, `0054f13b` and `0054ffbb`. EAX is forwarded through each epilogue; there is no wrapper-level count comparison on this path.

Immediate helper entry boundaries show mode-dependent reads of a first 4-byte field with item count 1. Their observed exit boundaries set EAX to one or zero. Those excerpts support a field-read boundary, but do not recover complete conversion behavior, full destination writes, total disk record widths or every return path. The helpers' 2,365/1,583/2,652/510-byte bodies are not assigned complete contracts here. The public evidence therefore records FWD for the local wrapper path instead of generalizing the direct block-read EQ rule.

`0054db50` is the only owned wrapper with explicit normal-path destination writes. On G=2, a short count returns zero at `0054dc2b..0054dc34` before repair. A full count reaches `0054dc35`: `TEST ESI,ESI; JBE` skips only zero, because TEST clears CF. For a nonzero raw count, EAX starts at destination `+0x80`; each iteration tests a WORD and replaces zero with one at `0054dc3f..0054dc45`, then advances by `0x245` and decrements ESI. Every nonzero WORD is preserved. The loop iterates exactly the original DWORD count; it does not impose a signed positive count bound. It returns one afterward. This local normalization is not performed by the wrapper's delegated G=1 branch; additional helper effects remain unresolved.

## Error path and ownership

Every rejected guard constructs the shared diagnostic using source-path address `009b8dc0`, format `009870e8`, buffer `00ae24d0`, title `009870e0` and the matrix's distinct constant. The ordered diagnostic calls are `00944cff`, `0090d130`, `00944c9f`, `005e8290`; then the wrapper clears DWORD `00b67a34`, calls `005cc7d0`, calls `005a8f60`, and passes -1 to `00945934`. [R09](database-boundary-09.md) resolves that machinery to `KERNEL32!ExitProcess` through `00967164`; `009459e7` is re-decoded here. Thus a bad guard is a termination path, distinct from a short-read zero result. Full diagnostic/cleanup ownership remains outside the local contract.

All sixteen borrow stream, destination and descriptor. No wrapper allocates or frees the destination, opens/closes a normal-path stream, or writes the descriptor. Direct helper calls mutate destination and stream; G=1 dispatch adds unresolved transitive effects. Caller allocation ownership, destination lifetime/capacity and semantic record identities remain open. Native incoming references are retained as discovered direct-call sites, without claiming runtime reachability or excluding indirect/unrecognized callers. No RNG persistence is established by these opaque reads.

## Evidence, coverage and reproduction

[Sites](../evidence/db-wrapper-family-14-sites.json) contain compact instruction selections, per-span hashes, every body's decoded instruction count, native file hashes and incoming reference sites. [Findings](../evidence/db-wrapper-family-14-findings.json) retain the per-function matrix and limits. The [name-only annotation proposal](../evidence/db-wrapper-family-14-annotations.json) gives sixteen exact old/new names and confidence; native state is unchanged. Old names were checked against private preflight SHA-256 `728f0dbb5ccd7860c03a35203f30b7bb377048879c2b95601b1744fd78e7fc3d` and native decompiler headers. Recheck before application.

The [extractor](../evidence/db-wrapper-family-14-extract.py) independently decodes **all 1,171 instructions** across all sixteen spans and compares each address and normalized mnemonic/operands with Ghidra's assembly. It hashes every owned `.asm`, `.c` and `.refs` export against manifest SHA-256 `233ec2078dc3eacf0d1b83a3d093028caf57c634329bacce4af4ea2efb5c7f86`. All match. Decompiler output was read as secondary interpretation; assembly establishes widths and branch predicates. No complete listing, original instruction bytes, game records or bulk decompilation is retained publicly.

Recommend **contract-supported** for each of the sixteen owned entries under the ledger's definition of a complete local body contract. The four delegated helpers remain dependency boundaries; their larger bodies are not additional complete contracts. The stream helpers likewise remain bounded context. This supports local static coverage, with no execution-equivalence claim.

With Python and `capstone==5.0.7`, reproduce using:

```text
python evidence/db-wrapper-family-14-extract.py PATH_TO_PINNED_EXE PATH_TO_PRIVATE_EXPORTS_14 OUTPUT.json
```

Two extraction runs compared byte-identically with the retained sites: SHA-256 `02c8b5426cfc6b8f8e32a13cb5b78eecb2c50d5b1dd72e1826cd6eae18a0f35b`. `npm run check` passed on Node v24.19.0; it checks existing numerical fixtures and repository metadata, not these wrappers at runtime. This work adds static contracts and proposed names; it adds no reconstructed game/UI behavior or runtime oracle.

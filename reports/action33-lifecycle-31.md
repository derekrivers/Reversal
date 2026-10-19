# R31-B: original participant fixture kernels and lifecycle boundaries

The original `008968f0` lookup now returns a nonnull roster/staff pointer in 80 labelled synthetic cases, using its actual `008982b0`, `00600a50`, `005409b0` and `0053b900` callees. That returned pointer is consumed by a separate original-entry placement call, which stores it at slot `+0x69` and copies its attribute pointer to `+0x6d`. This advances R30-D's caller-supplied pointer prefix to a reproducible original lookup result.

It does not create an initialized match. Slot placement stops before an unproduced side-byte read. The normal status lookup reaches process-static initialization and an exit-list dependency while `00b63d28` remains zero. The lookup-object constructor independently stops before its first Windows drive query. No OS, allocator, file, callback registration or return value is stubbed.

The specimen is the 7,192,576-byte PE32 x86 image SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; addresses are virtual unless labelled PE file offsets. The branch baseline is merged `36b44d8701b6abe332bc5a112198a570a8946536`. R30-D state provenance at `d5a425f` is prior research context, not a branch dependency or additional execution claim.

## What ran

The [extractor and fixture harness](../scripts/extract_action33_lifecycle_31.py) executes original instructions in Unicorn 2.1.4. The [oracle](../evidence/action33-lifecycle-31-oracle.bin) is canonical gzip-compressed JSON, with a `.bin` suffix so the repository's existing binary attributes preserve its bytes. It retains synthetic scalars, original code addresses, register observations, call frames and complete region digests; it contains no original memory pages or instruction bytes.

| Original entry | Cases | Observed result or stop |
| --- | ---: | --- |
| `008968f0` | 80 | Nonnull staff pointer returned through `RET 0x0c` |
| `008968f0` | 80 | Null attribute pointer causes tactics ID invalidation and zero return |
| `006e0d00` | 80 | Actual returned staff pointer reaches original `006eaea0`; stop before `006eaf77` |
| `0062ed70` | 80 | Actual nonnull staff pointer reaches `0062c680`, date initialization and exit registration; stop before `00946214` |
| `0062ed70` | 80 | Actual zero lookup result preserves the stop before `0062ed99 -> 00944cff` |
| `0062a680` | 8 | Stop before `0062a6b1`, the first Windows import call |

There are **29,800 original instruction steps** across these entries. The lookup stage checks EAX, return EIP/ESP and all four nonvolatile integer registers. Each stage records every ordered data/stack access and complete before/after hashes for fifteen synthetic regions. All nonstack bytes are compared with independent expected effects: only the selected tactics-cell invalidation, named slot stores, process date/flag stores and SEH-chain update are admitted. Stack snapshots and ordered-access hashes are observed evidence; there is no independent full CPU-stack reconstruction or TypeScript equivalence claim.

The fixture builder invokes separate function entries. Between lookup and placement it preserves data memory and passes the actual returned pointer, while preparing the next entry's synthetic CPU argument frame. Each case uses a fresh machine; process initialization is not carried across cases. It has not executed enclosing caller `006dbb80`, database loading, complete slot construction or resolver entry. The source records remain explicitly synthetic.

## Reproducible normal record selection

The schedule spans club IDs 0..3, roster indices 0..19 and nonnull/null attribute modes. It supplies these bounded inputs before the original lookup entry:

| Synthetic storage | Supplied value and purpose |
| --- | --- |
| Tactics object `00200000`, DWORD `+0x601` | Table base `00210000` |
| Club candidate `00220000`, DWORD `+0` | Club ID 0..3 |
| Club DWORD `+0xcf` | Zero, selecting the admitted guard route |
| Globals `00ae2350`, `00ae235c`, `00ae2364` | 1, 8 and 64 |
| Staff-array global `00ae23bc` | Synthetic base `00230000` |
| Selected tactics cell | `base + 0x91*club_id + 2 + 4*index`, containing `(11*club_id+index)%32` |
| Selected staff record | `00230000 + 0x6e*staff_id`, with its first DWORD equal to `staff_id` |
| Staff DWORD `+0x61` | Synthetic attribute record `00240000 + 0x46*staff_id`, or zero for the invalidation cases |

At `0089695c`, the original lookup passes `(club,0)` to `008982b0`. Its original `008982c8` call passes `(club,1,1,0,0)` to `00600a50`. With club `+0xcf=0`, that body reaches `00600be6 -> 005409b0`; the original predicate compares club ID against `00ae235c - 00ae2350`, so all four IDs return zero. `00600a50` returns zero and `008983e0` selects the club's first DWORD as the tactics row number. None of these results is injected.

`00896972..00896989` apply the `0x91` row stride and DWORD roster index. `00896996..008969a4` turn the selected staff ID into `00ae23bc + 0x6e*ID`. A null attribute pointer invalidates the tactics cell to `-1` at `008969b1` and returns zero. On the nonnull path, `008969cb -> 0053b900` compares the club ID against `00ae235c - 2*00ae2350`; the supplied IDs are below that threshold, so the original code reaches `00896a14` and returns the staff pointer. All 160 lookup entries execute to their actual return instruction.

These guards close one bounded input producer. They do not prove that a loaded tactics table, club ID, staff ID, global count or attribute record has these values in a game. Original database allocation, ID relocation, tactics ownership and the staff-array lifetime remain required inputs, as identified in R30-D.

## Placement stops before consuming an unproduced field

For the 80 nonnull results, the separate `006e0d00` entry uses ECX=`00260000`, the original returned staff pointer as argument 2, and a distinct raw forwarded argument `0x89abcd80 | club_id`. Manager `+0x18` contains `club_id`, so outgoing argument 3 is `0x89abcd00 | club_id`, while argument 5 retains `0x89abcd80 | club_id`. Their low bytes differ in every case; the call-frame comparison preserves this R30-D review fix.

The wrapper computes `slot_base + 0x1be*index`, calls `006eaea0` at `006e0dde`, and the original prefix writes:

- `006eaec5`: context pointer at slot `+0x19e`.
- `006eaecb`: the actual returned staff pointer at slot `+0x69`.
- `006eaeda`: staff `+0x61` at slot `+0x6d`.
- `006eaf64`: attribute byte `+0x45` at slot `+0x17`, after the original staff-ID/count comparisons.

The index and slot `+0x2e` byte stores are also checked. At the next instruction, `006eaf77`, the body would read slot `+0x27`. This field has not been produced by the admitted lookup/placement prefix. The harness stops **before reading it** instead of selecting a side from its synthetic initial bytes. The next data task is to establish that field's original pre-placement initializer and the context `+0x4792` club-pointer owner subsequently used before `006eafa0 -> 004cf5f0`. This is not a completed slot constructor.

## Normal status enters process-static initialization

The status probe passes the actual returned staff record to original entry `0062ed70`. Its ID is 0..31, below the supplied count 64, so it reaches `0062edfc -> 0062c680` with ECX loaded from the still-zero lookup global. No nonnull lookup object is fabricated.

With the original loader-zero flag at `00b63d10`, refresh initialization runs before any lookup-object dereference. The observed sequence is:

1. `0062c6c2` sets flag bit 0 in `00b63d10`.
2. `0062c6c8 -> 0054a110`, ECX=`00b63d08`, writes WORD 40, WORD 1972 and DWORD 1 at offsets 0, 2 and 4, then returns normally.
3. `0062c6cd` pushes callback address `0062ce20`; `0062c6d2 -> 0094627a -> 0094620d` executes the original registration wrappers.
4. `0094620e` pushes the exit-list base from `00de4638`, still zero; execution stops before `00946214 -> 0094bef1`.

The exit-list base and end globals (`00de4638` and `00de4634`), the static flag and `00b63d28` lie in the PE's zero-filled virtual tail. The harness has not run CRT startup, allocated an exit list or registered the callback. The exact next dependency is `0094bef1` with argument 0 and the original registration frames still pending. This is a CRT exit-list dependency; no zero-object fault has been observed. Later refresh stages and a normal status return remain unexecuted.

For the 80 null-attribute lookup results, the original status entry instead selects its null-record diagnostic path and stops before `0062ed99`, with outgoing `(009e7f28,0,0,SP-0x100,SP-0x200)`. There are no diagnostic calls before that stop and no date/exit-list initialization on those cases. The original diagnostic source is never dereferenced or published by this experiment.

## The global constructor still needs Windows and file state

Eight independent `0062a680` entries use supplied 44-byte receiver storage and either a zero argument or a nonzero synthetic load argument. They run the actual prologue and stop before `0062a6b1`, with `(200,local_buffer)` prepared for import slot `009670f8`. The PE import directory independently resolves that slot to `KERNEL32.dll!GetLogicalDriveStringsA`; `00967100` resolves to `GetDriveTypeA` for later constructor code.

The original on-disk IAT page is mapped for the prologue's reads, but unresolved imports are never called. This is not an initialized Windows module. No receiver member is initialized before the stop, and the global remains zero. The incoming nonzero load argument has not been dereferenced or certified as a file object. The setup functions `00828110`/`0082a9c0`, their allocation calls and their earlier game-state dependencies are not executed here. Their static constructor/global-store links remain R30-D findings.

After this OS boundary, constructor `0062a680` still has drive/file probing and original load/new-state callees `0062ab00`/`0062cf70`. Those paths, plus CRT and owner lifetimes, must be admitted before a nonnull `00b63d28` can support a normal participant-effect fixture. A nonnull roster pointer alone does not provide that object.

## Integrity, privacy and reproduction

The extractor pins four private export manifests: R30-D state/staff SHA-256 `b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a` and `c6457fcd1b68d524d2d4ce623d144e77a3e5ae23c9a4699e157b9ec2181f7b35`, and fresh checkpoint-29 lifecycle/support SHA-256 `27093fe32f6bcf31c94cb78c108eb78b025713c14215cc3602daeb2db57aad68` and `92d0708d6eada4983366d522314881e04c293b0bfaab4c467eb08f71992d7741`. The fresh exports came from the disposable annotated checkpoint-29 project, opened read-only without reanalysis. Archive and per-file hashes are retained. The status context export from investigation 25 is separately pinned.

Capstone 5.0.7 compares **729 instructions in thirteen selected ranges** against native addresses, mnemonics and operands. Whole-body comparisons here are evidence checks, not new semantic-registry entries or execution coverage of unvisited diagnostics. Integrity gates remain active under optimized Python.

```text
python -B scripts/extract_action33_lifecycle_31.py PRIVATE_PE PRIVATE_STATE_EXPORTS PRIVATE_STAFF_EXPORTS PRIVATE_LIFECYCLE_EXPORTS PRIVATE_SUPPORT_EXPORTS PRIVATE_EXPORTS_25 evidence/action33-lifecycle-31-oracle.bin
python -B scripts/verify_action33_lifecycle_31.py PRIVATE_PE PRIVATE_STATE_EXPORTS PRIVATE_STAFF_EXPORTS PRIVATE_LIFECYCLE_EXPORTS PRIVATE_SUPPORT_EXPORTS PRIVATE_EXPORTS_25 evidence/action33-lifecycle-31-oracle.bin evidence/action33-lifecycle-31-validation.json
node scripts/check-action33-lifecycle-31.mjs
npm run check
```

The [verifier](../scripts/verify_action33_lifecycle_31.py) reproduces the compressed evidence byte-for-byte under normal Python and `-O`, tests specimen/manifest and independently resealed native operands, and rejects executed wrong-pointer and wrong-slot-store mutations. Privacy scans cover both the compressed container and bounded expanded JSON, including raw/hex/base64 original-code and diagnostic-source samples; injected raw/hex fragments and excessive expansion are rejected. Complete regeneration constrains every retained field. [Validation](../evidence/action33-lifecycle-31-validation.json) records the receipt.

The [retained checker](../scripts/check-action33-lifecycle-31.mjs) checks hashes, schemas, schedules, alias propagation, call-frame provenance, frontiers and counts without private inputs. It also rejects changed returned-pointer and swapped placement-argument mutations independently of hash checks. Normal and optimized validation receipts are byte-identical; the standalone checker and `npm run check` pass under Node 24.19.0. Coordinator adoption registers this checker in the shared runner and records the independent review in the queue. All state remains synthetic, with no live match, full lifecycle, normal effect return, score or shot-result claim.

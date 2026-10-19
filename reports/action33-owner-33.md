# R33-B: fixture ownership at the slot-placement boundary

The DWORD read at `006eaf8f` is a borrowed fixture pointer stored by `006b7f20`, the existing candidate prepare-match function. Its first stack argument supplies the pointer; this function neither allocates nor copies the fixture. Four exported caller sites pass an existing match-day record plus four bytes. A fifth caller, `0084be20`, passes a fixture in its own stack frame and computes that fixture's two club pointers from the database array.

Selected original producer instructions on synthetic storage now supply the three missing pointer fields. The subsequent original placement entry advances from R32-B's pre-`006eaf8f` stop to **pre-`006eafa0 -> 004cf5f0`**, with actual outgoing arguments `(returned_staff, produced_home_club)` and ECX zero from the uninitialized `00ae1050` global. This is a composition of two **interior producer windows** and separate original initializer, lookup and placement entries. Execution of `0084be20` from its entry, a completed prepare-match call, a full slot constructor, a live lifecycle and a normal participant effect remain unclaimed.

The specimen is the 7,192,576-byte PE32 x86 image with SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All addresses below are virtual. Baseline is main `afbdea6fb05957f11fbfa83dbe852cc85f656cf9` after PR #120. Earlier findings remain in [R30-D](action33-state-30.md), [R31-B](action33-lifecycle-31.md) and [R32-B](action33-slot-32.md).

## Enclosing function, callers and aliases

The focused native export identifies `006b7f20..006b979f` as the existing Ghidra function `cm0102_prepare_match_candidate`. The name remains provisional. The original prologue saves EBP before aligning ESP; consequently `[EBP+8]` at `006b7f41` is the first entry argument, despite subsequent alignment and local allocation. `006b7f45` saves incoming ECX in EBX; `006b7f4e` stores EDX as a **four-byte** member at `[EBX+0x4792]`. The normal success tail uses AL=1 and `RET 0x10` at `006b979d`, consistent with four DWORD arguments and an ECX receiver. The tail is static evidence; the executed prefix does not return.

| Exported call site | Actual first argument and receiver | Evidence and scope |
| --- | --- | --- |
| `006b4af2` in `006b4360` | EBX=`ESI+4`; ECX=`[ESI+0x57]` | `006b4a3c` forms EBX; `006b4ae8..006b4af2` pass it. The record comes from the manager's `+0x19` list plus the current offset at `006b49d2..006b49d9`. Static. |
| `006b53ba` in `006b5260` | EBP=`ESI+4`; ECX=EAX | ESI is the caller's incoming stack argument at `006b527e`; the local allocation/constructor path provides EAX and stores it to record `+0x57`. `006b53b2..006b53ba` pass the borrowed fixture. Static. |
| `006b5ca7` in `006b5a70` | EDI=`ESI+4`; ECX=`[ESI+0x57]` | `006b5b2e..006b5b44` compute a `0x69`-stride record from manager `+0x19`; `006b5c92..006b5ca7` pass it. Static. |
| `006b6b71` in `006b6970` | ECX temporary=`EDI+4`; receiver then becomes EAX | `006b69bf` obtains EDI from another returned object's `+0xe2`; `006b6b6a..006b6b71` pass the fixture. Upstream lookup and allocation remain unexecuted. Static. |
| `0084c3e8` in `0084be20` | LEA of current frame base `+0x40`; receiver ESI | Two PUSHes precede LEA `[ESP+0x48]`, so the pointer is the caller's earlier ESP plus `0x40`. The original CALL and callee entry through `006b7f4e` are executed here from an interior caller window. |

In the record-plus-four callers, fixture `+0x1c/+0x20` alias record `+0x20/+0x24`. A caller may use its fixture independently of the simulation object stored at record `+0x57`; the pointer at match `+0x4792` is therefore not evidence of ownership transfer. Selected callers have different lifetime obligations and must not be treated as one universal allocation path.

The prepare-match prefix itself reloads `[receiver+0x4792]` at `006b7f86`, reads fixture `+0x1c` at `006b7f8c`, and then reads **word** club `+0x80`. It separately reads fixture `+0x20` at `006b7fa3`. Both fixture members are DWORD pointers; the later word reads do not narrow the pointers. These reads are statically compared with native operands, beyond the executed binding stop at `006b7f54`.

## Club pointer producers and lifetime

In `0084be20`, let F be ESP at `0084c266`, before the two PUSHes in the producer window. The fixture starts at `F+0x40`. The incoming selected club IDs are DWORDs at `[EDI-4]` and `[EDI]`, loaded at `0084c266` and `0084c26f`. Their earlier selection, ordering, dates, eligibility and RNG are outside the admitted window. `0084c269` loads the backing array pointer from `00ae23b4`.

Original LEA/shift/add instructions form `base + ID*0x245` for each club. `0084c294` stores the first pointer at `[F+0x5c]`, exactly fixture `+0x1c`. After two PUSHes, `0084c2ad` stores the second pointer at `[ESP+0x68]`, exactly `F+0x60` and fixture `+0x20`. Both are four-byte stores. Confusing the changed ESP would assign the second field to the wrong offset. These are address calculations in the 32-bit machine domain; the selected window has no independent ID bound or allocation validation.

The fixture storage belongs to `0084be20`'s stack frame. On the success path, `0084c478..0084c485` call match cleanup and release the match pointer, then `0084c488..0084c493` pass the still-live stack fixture to a later helper. The enclosing return restores the frame at `0084c4e3..0084c4fb`. These are static lifetime leads: cleanup/release callees and alternate return paths are not executed, and release semantics are not re-established here. The fixture pointer cannot be retained beyond its enclosing frame, reused local record or backing database allocation without further evidence.

The separate database lifetime export supplies selected static support. `00528b61..00528b87` derive an allocation size of `0x245 * incoming_count`, call `00944e46`, and publish EAX at `00ae23b4`. `00529df3..00529dfc` provide another allocation/replacement store; its incoming size is not inferred here. In teardown, ESI is zeroed at `00528086`; `005281e0..005281f8` test the club-array base, pass it to `009452ca`, and clear the base and count. Any club pointer into released or replaced storage is outside the admitted lifetime. Full loaders, real club IDs and save relocation remain dependencies.

## Executed synthetic scope and next boundary

The [extractor](../scripts/extract_action33_owner_33.py) runs 80 cases, spanning the prior four club labels and 20 roster indices. It supplies the synthetic database base `002a0000`, club IDs `club` and `7+index`, and admitted frame/register inputs for the two interior windows. It never writes fixture `+0x1c/+0x20` or match `+0x4792` as fixture setup. Those fields are written by the original instructions above.

The first window executes `0084c266..pre-0084c2b1`, producing both club pointers. The second executes `0084c3dd -> 006b7f20..pre-006b7f54`, including the real CALL and the original argument store. The omitted caller work includes date/selection/eligibility paths, registration, the allocation at `0084c343 -> 00944cf1` and the complete match constructor. The synthetic receiver storage in ESI is explicitly supplied. No return from the suspended prepare-match frame is fabricated. Its SEH link is retained as an observed prologue effect.

The same machine then runs original `006eada0` on the selected slot and original `008968f0` with its admitted callees. Its actual returned staff pointer feeds a separately prepared `006e0d00` entry, preserving R32-B's distinct five placement arguments. The original-initialized slot `+0x27` remains zero even when this call's manager side byte is nonzero. Consequently the executed placement reads the **home** field at `006eaf95`; the away field is produced and checked but its placement consumer branch is not executed.

The original read chain is slot `+0x19e` -> match storage -> `+0x4792` -> the caller's preserved stack fixture -> `+0x1c` -> calculated club pointer. The harness verifies exact read addresses and widths, the original returned staff/attribute aliases, the outgoing `(staff,home_club)` stack words, and the complete fixture bytes remaining unchanged. The next call at `006eafa0` is not executed. `00ae1050` lies in the PE zero-filled virtual tail and remains zero; its constructor, contract rows, `004cf5f0` execution and later placement/status calls are required next dependencies. The existing global `00b63d28`/OS/CRT lifecycle boundaries from R31-B/R32-B remain open.

Every stage checks complete nonstack regions against independently authored admitted writes. The club producer additionally checks its entire stack region against independently authored writes, including the changed-ESP field store and neighbouring bytes. Other stages retain full stack hashes and ordered access digests but do not independently reconstruct every stack byte or prove full CPU/flag equivalence. Initializer and lookup return/nonvolatile integer ABI checks are executed. No TypeScript equivalence or full caller continuity is claimed.

The five stages execute **25,520 original instructions**: 23 producer, 23 caller/binding, 67 initializer, 135 lookup and 71 placement instructions per case. Capstone 5.0.7 compares **1,035 instructions in 34 selected ranges** with native operands. Static ranges and unvisited branches are not execution coverage.

## Reproduction, integrity and privacy

The new focused read-only checkpoint-29 export manifest SHA-256 is `42425fa15eeb2da209497e396b81bacc99e77a2c608500cdd9febd7ee9091f79`, from archive `f787a4dd87cb0efc9d7b270f8be0656e49d0f5f64738f1d19aab759540936bdd`. The existing database lifetime manifest is `83d24d0790139ab37f7e3c82e12dfff9844456a8273e8d5ee10d1036359c7daf`, from checkpoint-28 archive `ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a`. The extractor preserves inherited R31-B/R32-B manifest and per-file pins. It verifies every file in each selected manifest and every operand in each selected code range. No canonical native state is written.

```text
python -B scripts/extract_action33_owner_33.py PRIVATE_PE PRIVATE_STATE PRIVATE_STAFF PRIVATE_LIFECYCLE PRIVATE_SUPPORT PRIVATE_EXPORTS_25 PRIVATE_SLOT PRIVATE_R33_FOCUSED PRIVATE_DATABASE evidence/action33-owner-33-oracle.bin
python -B scripts/verify_action33_owner_33.py PRIVATE_PE PRIVATE_STATE PRIVATE_STAFF PRIVATE_LIFECYCLE PRIVATE_SUPPORT PRIVATE_EXPORTS_25 PRIVATE_SLOT PRIVATE_R33_FOCUSED PRIVATE_DATABASE evidence/action33-owner-33-oracle.bin evidence/action33-owner-33-validation.json
node scripts/check-action33-owner-33.mjs
npm run check
```

The [verifier](../scripts/verify_action33_owner_33.py) requires byte-identical regeneration in normal and optimized Python. It rejects specimen/manifest changes, a resealed owner-store width, executed wrong owner/club destinations and an away-club read on the home branch. Privacy gates scan both the compressed container and bounded expanded JSON for raw, hex and base64 code/source samples, including injected raw/hex negatives and an excessive expansion negative. Authored task files receive the same sample scan. The [oracle](../evidence/action33-owner-33-oracle.bin) retains synthetic observations, addresses and hashes; original code, listings, source strings and pages remain private. The [receipt](../evidence/action33-owner-33-validation.json) records ten rejected probes.

The [retained checker](../scripts/check-action33-owner-33.mjs) checks exact case/stage schemas, pinned artifacts, pointer arithmetic, stack aliases, widths, caller arguments, stop/call classification and aggregate counts without private inputs. Independent semantic mutations swap a produced club pointer and change the outgoing contract-club argument. Normal and `-O` receipts match; the standalone checker and full repository check pass under Node 24.19.0. The coordinator owns any shared-runner adoption, frontier/registry update, independent review and merge.

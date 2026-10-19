# Investigation 27-A: two cursor advance helpers

This unit maps and executes the complete local bodies at virtual addresses `0068d1b0` and `0068d1d0` in the pinned CM01/02 3.9.68 PE32 (SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`). Their PE **file offsets** are `0x28d1b0` and `0x28d1d0`; each is 19 bytes. Native assembly and pseudocode come from a read-only export of freshly restored checkpoint 26 (archive SHA-256 `4acf11ca1ab79b275436c6365813904d87634436de1723ce24a2274f83a087c4`). The private export manifest and exact-old annotation preflight are pinned by the [site evidence](../evidence/iterator-helpers-27-sites.json). All game bytes and bulk exports stay private.

Capstone 5.0.7 matches every byte of each contiguous original PE body to all nine native instruction starts, mnemonics and operands. Each eight-edge local CFG reaches every instruction, including both return sites. Neither body calls anything or installs exception handling. The [extractor](../scripts/extract_iterator_helpers_27.py) checks PE type, virtual-to-file mapping, complete decode, native hashes, exact-old function identity, instruction membership and CFG. Its numerical outputs are static body evidence; the execution claim below is separate.

## Local contract and ABI

ECX is the receiver pointer. The cursor is a DWORD at unaligned receiver offset `+0xa`. Neither body reads a stack argument, pushes a register nor adjusts the stack beyond `RET` popping its return address. EBX, ESI, EDI, EBP and ECX are unchanged. EAX returns the node's DWORD payload at offset zero, or zero for a null cursor. EDX ends as the next cursor, or zero on the null path. `TEST EDX,EDX` sets flags; the null arm's `XOR EAX,EAX` sets them again. EFLAGS are outside the TypeScript comparison.

| Body | Ordered external effects on nonnull cursor | Null cursor |
| --- | --- | --- |
| `0068d1b0` | Read `receiver+0xa` DWORD; read `node+0` DWORD; read `node+6` DWORD; write that link DWORD to `receiver+0xa`; return original payload. | Read only `receiver+0xa`; return zero without writing. |
| `0068d1d0` | Read `receiver+0xa` DWORD; read `node+0` DWORD; read `node+0xa` DWORD; write that link DWORD to `receiver+0xa`; return original payload. | Read only `receiver+0xa`; return zero without writing. |

A nonnull node with payload zero is still consumed and advances the cursor. A null **next link** is written, and the current payload is returned. The bodies perform no pointer validity or collection-count check. The unaligned link reads are 32-bit loads, not byte fields. In R26-A, `0062be00` copies a collection field at `+2` to cursor `+0xa`, then calls `0068d1b0` on every normal path as it searches keyed records. This resolves that callee's local cursor operation but does not establish a complete merge execution: allocation, insertion, linked-list consistency and later caller behavior remain separate.

## Original-entry validation

The [Unicorn oracle](../evidence/iterator-helpers-27-oracle.json.gz) executes each original body from entry through its real `RET` against synthetic disjoint receiver, node and stack regions. It contains 400 cases per entry: 16 null cursors and 384 nonnull cursors spanning 16 deterministic byte patterns, six payloads (including zero and signed bounds) and four next links (including null and an unmapped value that is only copied). The 800 cases execute 5,536 x86 instruction steps, all 18 starts and all 16 CFG edges. No original game data is in these regions or in the fixture.

The [TypeScript reconstruction](../reconstruction/iterator-helpers-27.ts) and [checker](../reconstruction/check-iterator-helpers-27.ts) compare EAX/ECX/EDX, ordered external DWORD read/write events, complete post-state SHA-256 of both external regions, `RET` EIP/ESP, and preserved EBX/ESI/EDI/EBP. The event order matters: the payload is read before the next link, and the cursor write follows both reads. The checker reconstructs every synthetic input rather than trusting fixture memory, checks the fixture's digest and schedule, and compares observed instruction traces to the static CFG. It also rejects unsupported entry addresses and a write on the null path.

The [negative receipt](../evidence/iterator-helpers-27-negative.json) confirms byte-identical normal and `python -O` static/oracle regeneration; changed PE, native export, manifest and preflight rejection; independently resealed wrong PE and native link operands reaching the instruction comparator; and TypeScript oracle/result/effect mutations. Integrity gates use explicit exceptions, not optimization-sensitive `assert`. The task checker passes Node 24.19.0 and the shared repository check passes separately. [Name proposals](../evidence/iterator-helpers-27-annotations-proposal.json) retain exact-old evidence and change names only.

This validation admits stable, mapped, disjoint synthetic objects and ordinary returns. Aliasing, invalid pointers/faults, concurrent mutation, real collection invariants, EFLAGS, and a connected `0062be00` loop are outside the claim. No full player lifecycle, match result or game UI is recovered here.

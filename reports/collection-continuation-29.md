# R29-C — collection continuation bodies

This unit maps four **complete local bodies** in the pinned CM01/02 PE32 x86 specimen, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All addresses below are virtual unless identified as PE file offsets. The read-only native exports derive from checkpoint-28 archive SHA-256 `ab4bf204a86776c1a2e34caa6db9eb330665078446c5a7738e0d403fb415fb2a`; selected export manifest SHA-256 is `ced03a8f3d9da3cc61fcb9d63e0be55cb1cc39776615c038e0320836a526c0da`, and exact-old preflight SHA-256 is `cee6d3c36808bd69afb14796fa22314a8900909e3b59e08544e5bdfe58063a0c`.

| Entry | PE file offset | Body bytes | Body SHA-256 | Instructions / local edges | Scope |
| --- | --- | ---: | --- | ---: | --- |
| `0068d080` | `0028d080` | 77 | `83ebc8411630aace93c34c04e5228f0e6a69230a414d3c8916c2fae563683c80` | 28 / 30 | Static local body |
| `0068d280` | `0028d280` | 96 | `9ad487f2155b6dfa106152e9014016f8d591486b47b34b71c7fa2326ded608a3` | 35 / 38 | Static local body |
| `0068d2e0` | `0028d2e0` | 13 | `7c262d0ca2ac80f5d4796010d4f7f47a8dabba2108156c8fae2de52a268ee3d5` | 7 / 6 | Static body and bounded execution |
| `0068d2f0` | `0028d2f0` | 128 | `646e712450194e53ddf5c6f2af169c320a552c7cecc10b979d5cce59f0dcf7ac` | 47 / 51 | Static local body |

The [extractor](../scripts/extract_collection_continuation_29.py) pins the specimen, export files, manifest and preflight. Capstone 5.0.7 decodes every PE byte of each span and matches every address, mnemonic and operand in the independent native instruction export. It checks each local branch destination and fallthrough, instruction reachability, returns and the seven direct calls. The [site evidence](../evidence/collection-continuation-29-sites.json) records compact hashes, calls, operands and CFG summaries without storing executable bytes or bulk pseudocode. `0068d010`, `0068d0d0` and `00944c94` are context and call boundaries, not new contracts here.

## Shared 14-byte collection shape

The bodies address a receiver with a WORD count at `+0`, DWORD head at `+2`, DWORD tail at `+6` and DWORD current cursor at `+0xa`. Nodes have a payload pointer DWORD at `+0`, a copy length WORD at `+4`, a next link DWORD at `+6` and a previous link DWORD at `+0xa`. These are observed field uses, not a claim that the object always satisfies list invariants. Unaligned WORD/DWORD accesses are intentional in the instructions. None of these bodies checks pointer validity, list consistency, aliasing or concurrency.

### `0068d080`: clear linked nodes and reset header

ECX holds the receiver. It saves ESI and, on the nonempty path, EBX/EDI; it takes no stack arguments and returns with ordinary `RET`. It reads head `+2` and skips the loop if zero. For each nonzero head it rereads `+2`, reads that node's next pointer at `+6` **before** invoking `0068d010(node)` and `00944c94(node)` in that order, and then stores the saved next pointer into receiver `+2`. After the last node, it writes zero as WORD `+0`, then DWORDs `+2`, `+6`, `+0xa`, in that order. The inner null-node branch follows a prior nonzero head test and is unreachable under stable header memory. EAX has no reliable local result value across the calls. The two callees' payload cleanup, release, exception and heap effects are external boundaries; the local body does not prove that every allocation is safely freed.

### `0068d280`: unlink one node, then release it

ECX is the receiver; entry `[ESP+4]` is the DWORD node pointer. After saving ESI, its first read of that argument is `[ESP+8]`. `RET 4` removes the caller's node argument; EAX is explicitly set to `1` on normal return. ESI is saved/restored, with EDX and ECX used as scratch. A null or unmapped node is not an admitted normal input: it is dereferenced before the late `TEST ESI,ESI` release guard.

It first compares node with head. If equal it sets head to node.next; otherwise it writes node.next to `node.prev+6`. It then compares node with tail. If equal it sets tail to node.prev; otherwise it writes node.prev to `node.next+0xa`. It reads current `+0xa`, decrements the receiver count as a **WORD** modulo 65,536, and, only if current equals the removed node, sets current to `current.next`. It then calls `0068d010(node)` and `00944c94(node)` in that order. This sequence does not guard underflow, stale links, or a node outside the list. The direct link/count/cursor effects are local; the release callees remain transitive boundaries.

### `0068d2e0`: current payload getter

ECX holds the receiver, with no stack arguments and ordinary `RET`. It reads DWORD receiver `+0xa`; if zero it returns EAX=0, otherwise it reads DWORD `[cursor+0]` into EAX. The null route never dereferences cursor. It preserves all general registers except EAX, advances ESP by four via `RET`, and has no explicit data write or call. Its two return paths are included in the original-entry validation below.

### `0068d2f0`: reset destination, then append a source prefix

ECX is the destination receiver and entry `[ESP+4]` is the DWORD source receiver. The body saves ESI/EDI and conditionally EBX, returns with `RET 4`, and has no stable documented EAX result across callees. It first performs the same destination node loop as `0068d080`: capture next before calling `0068d010` and `00944c94`, advance destination head, and zero destination WORD `+0` and DWORDs `+2`, `+6`, `+0xa` in that order. Thus a source aliasing the destination may already have been cleared before any source read.

It then reads source head `+2` and writes it to source current `+0xa`. For each current node, it reads payload `[node+0]`, reads next `[node+6]`, tests the payload and **writes source current to next before** deciding whether to append. A zero payload stops immediately after that cursor advance; source head/count/tail are not reset and source nodes are not released here. A nonzero payload causes a WORD read at the current node `+4`; `MOV DX` replaces only the low 16 bits of the previously loaded payload pointer in EDX. It pushes that full EDX value as the second argument, pushes the payload pointer as the first, sets ECX to destination and calls `0068d0d0`. That callee uses the low 16 bits for its copy length, so the upper EDX bits are not a normalized length. After the call it reloads source current and repeats. An empty source sets current to zero and appends nothing. Allocation, copied payload, failure/exception and release behavior are transitive; this local contract does not validate a safe complete copy or lifecycle.

## Original-entry validation and limits

The [getter oracle](../evidence/collection-continuation-29-oracle.json) executes the original 13-byte body from its entry for 1,024 synthetic mapped cases: null cursor, cursor equal to receiver, and two separate-cursor schedules, including unaligned receiver addresses. The [TypeScript reconstruction](../reconstruction/collection-head-29.ts) and [checker](../reconstruction/check-collection-head-29.ts) compare EAX, every other general register, return EIP/ESP, ordered data and stack reads, both complete 4 KiB page digests, all seven instruction starts and six local edges. This totals 5,120 original instruction steps. The caller must supply mapped receiver/cursor/return memory; the TypeScript port explicitly rejects invalid numeric address ranges. Flags are not part of this ABI comparison.

Normal and optimized Python reproduce byte-identical site/oracle/[negative](../evidence/collection-continuation-29-negative.json)/[privacy](../evidence/collection-continuation-29-privacy.json) evidence. Ten Python mutations reject changed PE/native/manifest/preflight, independently resealed operand/call/return changes and a resealed exact-old name. Node 24.19.0 passes the getter check; four negative modes reject changed EAX, reordered reads, changed full memory and changed preserved EBX. The privacy checker independently regenerates the synthetic schedule and whole-page digests, requires canonical compact JSON and rejects embedded raw-page changes. [Validation metadata](../evidence/collection-continuation-29-validation.json) records the retained hashes. `npm run check` passes under Node 24 and includes the getter checker; the repository check does not rerun the private-input oracle.

The [four exact-old name proposals](../evidence/collection-continuation-29-annotations-proposal.json) are name-only and require coordinator review/application. No shared atlas, checkpoint or canonical native project was changed. The three calling bodies remain static contracts; only the getter has a bounded original-entry TypeScript behavior claim. No connected collection lifecycle, allocator success, heap safety or game outcome is established.

Reproduce with the pinned private inputs:

```text
python scripts/extract_collection_continuation_29.py downloads/cm0102.exe --exports PRIVATE_EXPORTS_29 --preflight PRIVATE_PREFLIGHT_29 --output evidence/collection-continuation-29-sites.json
python scripts/emulate_collection_head_29.py downloads/cm0102.exe PRIVATE_EXPORTS_29 PRIVATE_PREFLIGHT_29 evidence/collection-continuation-29-oracle.json
python scripts/check_collection_continuation_29_negative.py downloads/cm0102.exe --exports PRIVATE_EXPORTS_29 --preflight PRIVATE_PREFLIGHT_29 --output evidence/collection-continuation-29-negative.json
python scripts/check_collection_head_29_privacy.py evidence/collection-continuation-29-sites.json evidence/collection-continuation-29-oracle.json evidence/collection-continuation-29-privacy.json
node reconstruction/check-collection-head-29.ts
npm run check
```

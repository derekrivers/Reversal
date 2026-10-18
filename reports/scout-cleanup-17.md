# Scouting cleanup dependencies — investigation 17

`0068d040` walks a dword head at receiver+2, cleans/releases each node and publishes its saved successor. `009462bb` calls a supplied ECX-receiver callback in reverse stride order. `007ae4f0` conditionally releases two pointers in a 688-byte scouting record. These are three complete local static contracts; node internals, release/tracking helpers, finalization and exception handlers remain boundaries. No execution oracle or lifetime-safety claim is made.

The pinned PE32 specimen is `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline is `edc2a3cafe3695346e706733100eeff59be5b9f4`, native checkpoint 16. Addresses below are virtual addresses; field offsets and sizes are bytes. Independent Capstone 5.0.7 decoding agrees with all **92 instructions / 279 bytes** in the read-only Ghidra 12.1.4/JDK21 exports, including operand widths after documented spelling normalization. Every local branch lands on an instruction start.

| Entry / bytes / instructions | Input and stack cleanup | Normal return and preserved registers |
| --- | --- | --- |
| `0068d040` / 51 / 24 | ECX=receiver H; no consumed stack arguments; `RET` | EAX has no general result meaning; ESI/EBX/EDI preserved, EBP untouched |
| `009462bb` / 104 / 34 | Four dword stack arguments `(B,S,C,F)`; `RET 0x10`; no incoming ECX/EDX value consumed | EAX unspecified; EBP/EBX/ESI/EDI preserved |
| `007ae4f0` / 124 / 34 | ECX=record R; no consumed stack arguments; `RET` | EAX has no general result meaning; ESI/EDI preserved, EBX/EBP untouched |

The ECX cleanup entries consume no observed EDX argument, regardless of decompiler `__fastcall` spelling. Stack/register guarantees assume called routines honor their observed ABI. No body tests a callee return for success, validates a receiver or exposes a recoverable error result.

## Head traversal and node release

At `0068d043`, `0068d040` reads dword H+2 and returns without calls or H-field writes if it is zero. Otherwise each iteration performs this exact sequence:

1. Reread N=read32(H+2), copy N to EDI, and save next=read32(N+6) in EBX (`0068d04c..0068d051`). Both fields are unaligned dword accesses.
2. If N is nonzero, call `0068d010` with ECX=N, then call `00944c94(N)` with caller stack cleanup (`0068d054..0068d065`). The known wrapper forwards to release boundary `009452ca`; this body does not establish its allocator contract or node-subobject effects.
3. Test the **saved** next value, store it at H+2, and repeat if nonzero (`0068d068..0068d06d`). MOV preserves the TEST flags.

Thus normal traversal follows successors saved before either call, and a finite well-formed chain finishes with H+2=0. During both calls H+2 still contains its pre-call value unless a callee changes it; any such change is overwritten by the saved successor afterward. No local instruction releases H itself, decrements a count, clears other H fields or zeros node memory. The inner N check occurs **after** the N+6 dereference, so it does not protect against a head becoming null between the initial check and the iteration load. There is no cycle, duplicate-node, extent, pointer or concurrent/reentrant mutation check. Cyclic or aliased chains therefore have no guaranteed safe termination or release behavior.

`0068d040` installs no local exception frame. If either helper faults, throws or does not return, the post-call H+2 publication is not established. Node cleanup and deallocation are sequential boundaries; no rollback, retry or total nested-resource coverage is proven.

## Reverse stride callback helper

`009462bb` reads stride S from `[EBP+0xc]`, computes the low 32 bits of S*C with IMUL, and adds them to its stack copy of B (`009462e2..009462eb`). It then repeatedly decrements its stack copy of C. If the result has its sign bit set, it exits the loop; otherwise it subtracts S from the stack copy of B, puts that pointer in ECX and calls F indirectly through `[EBP+0x14]` (`009462f2..00946300`). It pushes no callback arguments and ignores the callback's return value. For ordinary C in `0..0x7fffffff`, returning ABI-conforming callbacks receive:

`B + S*(C-1), B + S*(C-2), ..., B`, with all pointer arithmetic modulo 2^32.

The exact guard is **DEC followed by JS**, not an overflow-aware signed comparison. Consequently initial count `0x80000000` wraps to `0x7fffffff` on the first decrement and, if all calls return and leave the helper frame intact, performs **2^31 callbacks**. Other initial negative signed counts perform no callbacks; zero also performs none. Overflow flags from IMUL/ADD/SUB are ignored. Zero stride repeatedly supplies the same receiver. Negative stride is just its 32-bit bit pattern in the same arithmetic. B and F are not null-checked, and no multiplication, address, extent or stride/count validation occurs. Before its first count test even a zero/negative count has already changed the stack copy of B by the wrapped product; that arithmetic alone does not access an element.

The helper installs FS:[0] exception registration with handler `0094bf5c` and descriptor `009713d0`, initializes frame-local `[EBP-0x1c]` to zero and sets unwind state `[EBP-4]` to zero before traversal. After the loop it sets the former to one, unwind state to -1, calls **`00946323` even on an empty traversal**, then restores FS:[0] and returns (`00946302..00946320`). The final helper and exception-handler bodies are outside this assignment. Therefore the local normal path establishes callback order, not complete exceptional destruction or a proof that the final helper has no additional effects. With arbitrary callbacks, aliasing or mutation of helper arguments/frame can invalidate the nominal sequence.

This body is generic callback/cleanup machinery. It neither directly writes an element field nor directly releases an array allocation. R15's manager cleanup releases the array cookie separately after this call returns. No compiler-source identity is asserted.

## Record callback and connected outer order

`007ae4f0` installs FS:[0] exception registration with handler `0095f362`, saves R and sets its frame-local unwind state to six. It then:

| Order / sites | Local behavior |
| --- | --- |
| 1 / `007ae50e..007ae529` | Read dword R+`0x1ee`; if nonzero call `009452ca(pointer)`, then clear that field after return |
| 2 / `007ae533..007ae551` | Read dword R+`0x170` **after** the first branch; if nonzero save P in EDI, call `0068d1f0(P)` with ECX=`00b74438`, call `00944c94(P)`, then clear R+`0x170` after return |
| 3 / `007ae55b..007ae56b` | Restore FS:[0] and preserved registers, discard the local frame, return |

The second helper's return is ignored; there is no branch that suppresses the following release when that return indicates anything. Both pointer clears occur only after the respective release call returns. If both fields alias the same allocation, the local code makes two release calls when both branches remain nonzero; it has no cross-field alias guard. Pointer R+`0x170` is reread after the first release, so callee mutation can change whether or what the second branch cleans. The saved P is reused for its release even if `0068d1f0` mutates the record field. Tracking semantics at `00b74438`, allocator compatibility, exceptions and nested-buffer ownership remain unresolved.

On normal completion both pointer fields are zero if callees do not subsequently mutate a field already tested or cleared: initially zero fields are left as read, and taken branches explicitly clear them. This conditional observation supports repeated skipping of already-zero fields; it does not prove safe repeated cleanup under all aliases, callbacks or exceptions. No instruction clears the rest of the record, its count fields or its 688-byte storage, and R itself is not passed for release. These are the same two pointer fields cleaned before R16's record replacement; this callback performs no replacement copy or allocation.

R16's `00813140` supplies the connected ordinary call order: `0068d040(O+0x361e)`, then `009462bb(O+0x1b0e,688,10,007ae4f0)`, then `009462bb(O+1,688,10,007ae4f0)`. Thus the trailing node container is cleaned first. The second array's record receivers run from **O+`0x333e` down to O+`0x1b0e`**, then the first from **O+`0x1831` down to O+1**, in steps of 688. This order assumes successful returning helpers and intact arrays; no complete scouting workflow or object lifetime safety follows. The outer object is released separately in an observed R15 caller.

## Evidence, proposals and reproduction

`evidence/scout-cleanup-17-sites.json` retains only body hashes/offsets, selected sites and complete call/branch/return inventories. `evidence/scout-cleanup-17-findings.json` records the authored contracts and limitations. The optional name-only proposals in `evidence/scout-cleanup-17-annotations.json` give exact old `FUN_*` names from the pinned preflight; they request no prototype, convention, comment or structure edits. The coordinator alone may apply them after review and exact-old recheck.

The extractor verifies the executable hash, private manifest SHA-256 `096c06e07891855555057cdcc9f33307c6cdee79e7c632be5f593f76d894a2b8`, every manifest-listed export hash, and preflight SHA-256 `0d084f0348af44eeb24a73d8cec0fc866525099b14180bd87bd9c6246beda10f`. It maps PE virtual addresses to raw file offsets, decodes all bytes without gaps, compares every native instruction and checks all local branch targets. Private inputs are read-only; no original bytes, bulk assembly/decompilation, native project or game data is committed.

```powershell
python scripts/extract_scout_cleanup_17.py --binary <private-cm0102.exe> --native-dir <private-exports-17> --preflight <private-annotation-preflight-17.json> --output evidence/scout-cleanup-17-sites.json
npm run check
git diff --check
```

Confidence is high for local ABI, widths, direct writes, branches and ordinary call order. All three bodies qualify as contract-supported local static contracts with explicit transitive and exceptional boundaries. No direct RNG or I/O call/state access is identified in these bodies; transitive effects remain open. Checks of retained repository fixtures do not execute these cleanup functions. No reconstruction behavior, shared coverage ledger, canonical native annotation, game or UI build is changed.

Verification passed: pinned specimen/manifest/preflight hashes, every manifest-listed export hash, all 92 native instructions and local branch targets, byte-identical repeat extraction (sites SHA-256 `a43072d23f6b5edcfe14cba4ca43a813830dc312d25335d171ab4d5009e3b822`), JSON parsing, `npm run check` with Node v24.19.0, and `git diff --check`. The public change contains only the five owned task files and compact authored evidence; no private input or bulk export is included.

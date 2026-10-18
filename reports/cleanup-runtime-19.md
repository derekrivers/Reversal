# Investigation 19 — cleanup runtime boundaries

`009452ca` refines the R18 payload-release boundary to a null-guarded dispatch on a global runtime mode. Mode 3 selects a 20-byte table entry and calls a larger release helper; mode 2 locates a page descriptor and updates local bookkeeping; lookup failure and other modes call the imported `HeapFree`. The wrapper never tests release success. `0094633b` creates its own exception frame and subtracts the current stride before each callback. Its exception fragments remain outside this assigned native body.

The pinned PE32 x86 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline is checkpoint-18 commit `0ab803b3adb19eb9ecdb70d4a31d759127376b78`. All addresses are virtual addresses unless explicitly labelled as file offsets; field offsets and sizes are bytes. Independent Capstone 5.0.7 decoding matches every one of **142 instructions / 385 included bytes** in the read-only Ghidra 12.1.4/JDK21 exports. Every branch targets an included instruction start. This is static analysis without an execution oracle.

| Entry | Included bytes / instructions | Local ABI and normal return |
| --- | --- | --- |
| `0094633b` | 81 / 30 | Four dword stack arguments B, S, C, F; own EBP frame; `RET 0x10` |
| `009452ca` | 105 / 45 | Pointer P at entry ESP+4; caller cleanup; plain RET |
| `00948b90` | 43 / 14 | P at entry ESP+4; EAX=table entry or zero; caller cleanup |
| `009498eb` | 87 / 34 | P, out-region, out-page at entry ESP+4/+8/+12; EAX=descriptor address or zero; caller cleanup |
| `00949942` | 69 / 19 | Region R, page B, descriptor M at entry ESP+4/+8/+12; caller cleanup |

No incoming EDX argument is consumed. Normal nonvolatile-register restoration assumes callbacks/callees return with the expected stack and frame discipline. The first body saves EBP/EBX/ESI/EDI; the second saves EBP/ESI; the fourth saves ESI. Other nonvolatile registers are untouched locally. Return values must be assessed per path; the release dispatcher has no unified success meaning.

## Reverse callback traversal and exception boundary

`0094633b` contains two native ranges: `0094633b..00946376` and `00946384..00946398`. Their combined size is 81 bytes, although the enclosing span is 94 bytes. The 13 bytes at `00946377..00946383` are explicitly excluded from owned instruction coverage. The scope metadata at `009713e0` contains dwords `ffffffff,00946377,00946381`, connecting those addresses to the exception machinery. Neither those fragments nor handler `0094bf5c` and its further dependencies are complete contracts here.

The function saves the old FS:[0] chain head, registers its own frame with handler `0094bf5c` and table `009713e0`, saves registers/current ESP, and sets dword EBP-4 to zero. Each iteration decrements the dword count at EBP+`0x10` and exits when the result has SF=1. Otherwise it subtracts stride S at EBP+`0xc` from base B at EBP+8, stores the new base back to that stack slot, passes it in ECX to the indirect callback at EBP+`0x14`, and repeats. No stack arguments are pushed for the callback.

If every callback returns normally and preserves this function's active argument copies B, S, C and F, ordinary nonnegative signed input C gives C callbacks visiting `B-S, B-2S, …, B-CS`, with 32-bit wrapping address arithmetic. Under that same preservation assumption, input `0x80000000` wraps on the first DEC to `0x7fffffff` and gives **2^31 callbacks**. Zero and inputs `0x80000001..0xffffffff` stop before any callback. The count guard uses DEC/JS without checking overflow.

These totals and the fixed-stride sequence are conditional because every iteration reloads count, base, stride and callback from the active frame. Callback writes to these slots can change the next receiver, callback target or termination. For example, with C=3, S=0 and B pointing to the active count slot, a callback that writes zero through ECX makes the next decrement negative, ending after one visit. This is an instruction-derived alias example, not an execution fixture. There is no frame-alias, extent, stride or callback-pointer validation; callback mutation of other frame data can also affect normal restoration and exception handling.

On ordinary loop exit it sets EBP-4 to `ffffffff`, restores FS:[0] from EBP-`0x10`, restores nonvolatile registers, leaves its frame and removes all four arguments with `RET 0x10`. EAX is the saved old exception-chain value if no callback runs, otherwise callback-supplied; ECX holds the old chain value at exit. Neither has an established result meaning. An installed exception frame alone establishes no complete exceptional cleanup or rollback contract.

R18 `00946323` remains an inherited-frame guard/forwarder. When its guard is zero it passes its enclosing frame's current four values to this target, which then creates its own frame. R17's observed ordinary exit sets that guard to one and skips the forwarding call. No additional exceptional reachability or complete source/compiler identity is claimed.

## Release dispatch

`009452ca` loads P into saved ESI and immediately returns for P=0. This path reads neither the mode nor heap global, calls nothing, never dereferences P and leaves EAX unchanged. For nonzero P it reads mode dword `00de4404` once:

1. Mode 3 calls `00948b90(P)`. A nonzero result R selects **`00948bbb(R,P)`**, then returns. Assembly supplies both arguments; the decompiler's one-argument rendering is incomplete. A zero lookup falls through to the imported call.
2. Mode 2 calls `009498eb(P,&local_R,&stack_argument_P)`. A nonzero returned descriptor M selects `00949942(local_R,rewritten_stack_argument_P,M)`, then returns. The successful lookup overwrites this routine's own incoming argument copy with the page base. A failed lookup falls through.
3. Other modes and failed lookups call `HeapFree(read32(00de4400),0,original_P)` through IAT `0096715c`. PE import metadata independently identifies that slot as `KERNEL32.dll!HeapFree`; the imported implementation is outside coverage.

The one/two/three-argument local helper calls are balanced by POP/POP/ADD ESP respectively. The imported path has three pushes and no local argument adjustment, requiring 12-byte callee cleanup for its ordinary return. The wrapper saves ESI and restores its EBP frame. It checks no release result, retries nothing, and has no local exception registration. No direct payload clear or global mutation occurs in the wrapper itself. A selected helper that faults or does not return prevents subsequent normal completion; there is no later fallback after a selected release call. Callee effects and global synchronization remain open.

## Mode 3 window lookup

`00948b90` reads count dword `00de43f4` and table pointer dword `00de43f8`. It forms end=`start+20*count` modulo 2^32 and iterates while unsigned cursor<end, advancing by 20 bytes. It returns the first cursor satisfying **unsigned32(P-read32(cursor+0xc)) < `0x100000`**, or zero on exhaustion. It makes no calls and performs no memory writes. The predicate establishes membership in an arithmetic 1 MiB window, without allocation identity, alignment or liveness guarantees. Wrapped or corrupt bounds can skip entries or cause excessive traversal/access faults. The larger selected release helper `00948bbb` remains a boundary.

## Mode 2 lookup and bookkeeping

`009498eb` begins with candidate R=`00ad6d58`, including that sentinel as a candidate. It seeks the first node satisfying unsigned **P>read32(R+`0x10`) and P<read32(R+`0x14`)**. Otherwise it follows dword R+0 and returns zero when that link returns to the sentinel. Invalid links may fault; cycles excluding the sentinel may never finish.

After selecting the first interval, it requires P's low four bits to be zero and its page offset `(P & 0xfff)` to be at least `0x100`. Failure returns zero without trying later overlapping intervals. Success first stores R through the second argument, then loads the third argument's pointer and stores B=`P & 0xfffff000` there. The instruction `AND CX,0xf000` changes only the low 16 bits of a copy of P, preserving its high 16 bits and producing exactly this page base. It returns descriptor address:

`M = B + 8 + SAR32(P - B - 0x100, 4)`.

For admitted offsets, the shift operand is `0..0xef0`. No descriptor byte is read here. Rejected paths write no outputs; output aliasing or a fault between the successful stores can change or partially publish the outputs. Neither output-pointer validity nor descriptor liveness is checked.

`00949942(R,B,M)` uses this exact order:

1. Compute row=`R+0x18+8*SAR32(B-read32(R+0x10),12)`, with 32-bit address arithmetic.
2. Zero-extend byte M and add it to the **dword** at row modulo 2^32.
3. Clear **byte** M, compare the current dword row to `0xf0`, and write **dword** row+4=`0xf1`. MOV preserves the comparison flags used by the following branch.
4. If the compared row equals `0xf0`, increment **dword** `00de3010`. If that new value equals `0x20`, call `00949829(0x10)` and discard the argument.

There is no duplicate-release or zero-descriptor guard. An already-zero descriptor still causes the row+4 write, and a row already equal to `0xf0` can increment the global again. There is no bounds/negative-index/alias check, local lock, atomic prefix or local exception frame. If M aliases the row, clearing M can affect the value compared in step 3. Larger helper `00949829` and global invariants remain open. EAX normally retains the row address; the triggered call can replace it. Neither path supplies a validated release-success result.

R18/R17 node/query cleanup now reaches a null-guarded dispatcher, but the earlier byte-content lookup can still select a payload aliasing the separately released query. Allocator compatibility, disjoint ownership, complete object lifetimes, repeated-release safety and thread/reentrancy safety remain unproved. No direct RNG or file I/O call is identified; transitive effects remain open.

## Evidence and reproduction

The extractor verifies the pinned PE, manifest SHA-256 `3c5da196118b891f3dcd84f8126355d3c36888c3c7b72ca1f6d89772d8a22935`, every manifest-listed size/hash, checkpoint archive identity and preflight SHA-256 `a8b6f47a04ac2dcc2d6fb13537a55b223db5630d50e857ceb014f40f7069cf78`. It maps each virtual range to raw file offsets, independently decodes all included bytes without gaps, compares every instruction and checks branch destinations. Normalization handles numeric/whitespace/jump spelling, plus-negative displacement, scale one and the accumulator MOV's implicit dword width; other operand widths remain explicit. The old names are checked exactly. Missing preflight comment fields remain JSON null; no old-comment claim or comment change is needed.

`evidence/cleanup-runtime-19-sites.json` retains ranges/hashes, selected sites and complete call/branch/return inventories. `evidence/cleanup-runtime-19-findings.json` records bounded contracts and limits. `evidence/cleanup-runtime-19-annotations.json` proposes five exact-old name changes only, for coordinator review. No original code bytes, bulk assembly/decompilation, native project, shared atlas or checkpoint changes are included.

```powershell
python scripts/extract_cleanup_runtime_19.py --binary <private-cm0102.exe> --native-dir <private-exports-19> --preflight <private-annotation-preflight-19.json> --output evidence/cleanup-runtime-19-sites.json
npm run check
git diff --check
```

Confidence is high for the included local instructions, ABI/stack discipline, arithmetic, direct effects and call order. Execution behavior, callback/exception/large-helper contracts and imported behavior remain unvalidated. Repository checks validate retained fixtures and metadata rather than executing these five routines.

Verification passed: every pinned input/export hash, all 142 native instruction comparisons and branch destinations, exact-old-name preflight, byte-identical repeat extraction (sites SHA-256 `88a2f74cce58f6f3442148c3bf403cfe8dd5ceeb17a7adc33dba03ca06173ca3`), parsing all three JSON files, `npm run check` on Node v24.19.0 and `git diff --check`. The public change contains only the five owned report/evidence/extractor files.

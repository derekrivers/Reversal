# Cleanup helper dependencies — investigation 18

`0068d010` forwards a node's first dword to `00944c94`. `0068d1f0` finds the first node whose stored-length byte comparison succeeds, unlinks it, updates a word count and cursor-like pointer, then calls payload/node cleanup boundaries. `00946323` conditionally forwards four values from its enclosing EBP frame. These are complete local static bodies; the two short helpers establish forwarding mechanics, not complete object-lifetime contracts.

The pinned PE32 x86 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline is `267756ebe6d797b6477efd5f829d45ed6cb54d07`, native checkpoint 17. All addresses below are virtual addresses; field offsets and sizes are bytes. Independent Capstone 5.0.7 decoding matches all **72 instructions / 172 bytes** in the read-only Ghidra 12.1.4/JDK21 exports, including every branch/call target and operand width after documented spelling normalization. All local branches land on instruction starts. No execution oracle is asserted.

| Entry / bytes / instructions | Local inputs and return | Preserved registers on normal return |
| --- | --- | --- |
| `0068d010` / 10 / 5 | ECX=N, no stack argument consumed, plain RET; EAX comes from the callee without a declared result meaning | EBX/EBP/ESI/EDI untouched locally; assumes callee ABI |
| `0068d1f0` / 138 / 59 | ECX=container H, dword query pointer Q at entry ESP+4; RET4; EAX=0 on traversal exhaustion, 1 after matched-node cleanup returns | EBX/EBP/ESI/EDI saved/restored |
| `00946323` / 24 / 8 | Inherited EBP frame; no own stack arguments read/consumed; plain RET; EAX unchanged on skip, otherwise supplied by callee | No direct nonvolatile-register changes; assumes callee ABI |

No owned body consumes an incoming EDX argument. None installs a local exception frame, validates a receiver or tests a callee result for failure. Decompiler convention/type spellings are insufficient to supply a standalone prototype for the inherited-frame helper.

## Node payload forwarding

`0068d010` reads dword `[ECX]`, pushes that value, calls `00944c94`, pops the argument into ECX and returns. It never passes the node address itself unless the node's first dword happens to contain it. It does not clear that field, check either pointer for null or write node memory. The final POP leaves ECX holding the pushed payload value on an ordinary return.

Immediate boundary context from the pinned PE confirms `00944c94` pushes its own stack argument, calls `009452ca`, pops the temporary argument and returns. That already reviewed forwarding wrapper supplies no independent allocator, null-safety or nested-resource guarantee. Consequently the sequence in R17 `0068d040` forwards a node payload through `0068d010`, then separately passes the node to `00944c94`; a two-call sequence alone does not establish that both releases are compatible or disjoint. An interrupted first call prevents the second call and the outer head publication from being established.

## First byte match, unlink and cleanup

`0068d1f0` uses this partial layout. Names denote local roles established by reads/writes, not original source declarations.

| Base | Offset | Width | Observed role |
| --- | --- | --- | --- |
| H | 0 | 16 bits | Count-like field decremented on a match |
| H | 2 / 6 / 10 | 32 bits each | Head / tail / cursor-like pointer |
| Node N | 0 | 32 bits | Payload comparison pointer, later forwarded for cleanup |
| N | 4 | 16 bits | Signed length expanded into ECX |
| N | 6 / 10 | 32 bits each | Successor / predecessor |

The function saves the initial H+2 head in EDX, starts N there and returns 0 immediately if it is null. For each nonzero N it reloads Q into EDI, loads the payload pointer into ESI, sign-extends word N+4 into ECX, executes `XOR EBP,EBP`, then `REPE CMPSB`. `JE` accepts the resulting zero flag; a mismatch advances N through N+6 and repeats. There are no calls or object-field writes on an unsuccessful search.

The comparison has several material boundaries:

- For length zero, CMPSB performs no comparison accesses and leaves the zero flag set by XOR, so the node matches immediately even if Q is null. The Q value and node payload pointer are still loaded.
- For nonnegative length with DF=0, comparison proceeds forward for that many bytes unless an earlier mismatch stops it. There is no NUL check, query-length check or test of following bytes. A shorter node payload can match a prefix of Q.
- A negative signed word becomes an ECX count from `0xffff8000` through `0xffffffff`. REPE uses the resulting unsigned 32-bit count; if accessible equal bytes continue, this can mean billions of comparisons. There is no negative-length guard.
- No CLD occurs in this body. The incoming direction flag controls whether ESI/EDI advance or retreat, using DS:ESI and ES:EDI. Forward byte matching therefore requires the ordinary DF=0 entry condition.

The first accepted node is removed in this precise order, before either cleanup call:

1. If N equals the initially saved head, write N.next to H+2; otherwise write N.next to N.prev+6 (`0068d21f..0068d231`).
2. If N equals the current H+6 tail, write N.prev to H+6; otherwise write N.prev to N.next+10 (`0068d234..0068d247`).
3. Decrement **word** H modulo 2^16, without an underflow guard (`0068d24d`).
4. If N equals H+10, replace H+10 with the successor read through that current pointer (`0068d250..0068d257`).
5. With ECX=N call `0068d010`, then call `00944c94(N)` with caller stack cleanup; return EAX=1 (`0068d25e..0068d277`). The inner N-null test is redundant on a normal accepted search path and does not validate links.

On a valid single-node list the head/tail become null and a cursor equal to N advances to N.next. No instruction clears N's link/payload fields, resets other H fields, checks link consistency or detects cycles. Count, node-length and pointer fields have different widths; dword fields at offsets 2/6/10 can be unaligned.

All structural writes occur before payload/node cleanup. A fault, exception or nonreturning cleanup call can leave the node detached and the word already decremented, with no local rollback or error return. The ordinary result 1 records the completed matched path, not proven deallocation success. Arbitrary malformed links, aliased fields, callbacks, concurrent mutation or reentrancy can invalidate the nominal sequence.

R17 `007ae4f0` calls this helper with ECX=`00b74438` and query P from record+`0x170`, ignores the 0/1 result, then separately calls `00944c94(P)`. This refines the earlier tracking boundary to byte-content search/unlink. It does **not** prove allocation-identity lookup: a matching node payload can have the same bytes as P, and it can also alias P. Since a matched payload is forwarded for cleanup before the caller forwards P, disjoint ownership or freedom from repeated-release hazards remains unproved. The global container's complete initialization, ownership and other users are outside this assignment.

## Guarded enclosing-frame forwarding

`00946323` reads dword EBP-`0x1c`. A nonzero value branches straight to RET, with no pushes, calls or object writes and with EAX unchanged. For zero it pushes four dwords from the enclosing frame in order EBP+`0x14`, +`0x10`, +`0xc`, +8, then calls `0094633b` and returns. Thus the callee receives values in argument order **(+8,+0xc,+0x10,+0x14)**. These are not the helper's own entry-stack arguments. It neither creates an EBP frame nor validates the inherited pointer.

The body performs no caller stack adjustment after the call. Immediate pinned-PE boundary context at `00946396` is `RET 0x10`, establishing removal of the four forwarded dwords on that normal callee return. The larger `0094633b` body and its exception handler are not assigned contracts here. The helper does not interpret EAX, set the guard or supply its own recoverable failure handling.

In the already mapped R17 `009462bb`, EBP-`0x1c` starts at zero, and the traversal mutates stack copies of base and count. On every ordinary traversal exit it sets the flag to one **before** calling `00946323`; therefore that observed call skips `0094633b`, including empty traversals. Any invocation while the flag is zero would forward the current base/count/stride/callback frame values, not necessarily original inputs. Actual exceptional reachability, handler behavior and completeness of remaining cleanup remain boundaries. A frame-dependent forwarding stub is insufficient evidence for a complete exceptional lifetime contract or compiler-source identity.

## Evidence and reproduction

`evidence/cleanup-helpers-18-sites.json` retains body hashes/offsets, selected sites and complete call/branch/return inventories. `evidence/cleanup-helpers-18-findings.json` records the contracts and limits. Optional name-only proposals in `evidence/cleanup-helpers-18-annotations.json` specify the exact old `FUN_*` names from the pinned preflight; no prototype, convention, comment or structure changes are requested. The coordinator alone may apply reviewed names after exact-old recheck.

The extractor verifies specimen SHA-256, private manifest SHA-256 `fc4f2070cb0efa89c9473ebe507d0e2d3f01e1f5f66338177be5f34848ee7151`, all manifest-listed file sizes/hashes, and preflight SHA-256 `8749c47798c3758dc7509d0b3b71b7147f169ee0390066f01ef023baf670bcbb`. It maps virtual addresses to PE raw offsets, independently decodes every owned byte without gaps and compares every instruction. Normalization covers jump/numeric/whitespace spelling and equivalent REPE CMPSB source/destination presentation; operand widths are preserved. Blank old comments and exact old names are checked. Context-only selected instructions establish the forwarding boundary and normal stack balance without adding those callees to owned coverage.

```powershell
python scripts/extract_cleanup_helpers_18.py --binary <private-cm0102.exe> --native-dir <private-exports-18> --preflight <private-annotation-preflight-18.json> --output evidence/cleanup-helpers-18-sites.json
npm run check
git diff --check
```

Confidence is high for the three local bodies' ABI, operand widths, direct writes, comparison/branch behavior and call order. No direct RNG or I/O operation is identified; transitive effects remain open. Repository checks validate retained fixtures and metadata; they do not execute these helpers. No original code bytes, bulk assembly/decompilation, original game data or native project are committed. Shared semantic coverage, native annotations and checkpoint state remain coordinator-owned.

Verification passed: all pinned input/export hashes, 72 native instructions and local branch targets, blank-comment/exact-name preflight, byte-identical repeat extraction (sites SHA-256 `adefacbceed121b42c9348c9f09a267b3296d0de78ba65fe68f3a986e1f8e80e`), all three JSON files parsed, Node v24.19.0 `scripts/check-research.mjs`, and `git diff --check`. The public change contains only the five owned report/evidence/extractor files.

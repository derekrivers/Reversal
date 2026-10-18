# Investigation 13: match dependency contracts

`006f4600 -> 005b57c0` is a read-only byte selection chain with no RNG. It closes R12's unresolved callee effects at `006bce20`. Separately, `006f46b0` removes/appends a slot pointer in coordinate cell lists, updates coordinates and sometimes mirrors them into match state. Its diagnostic paths have additional unresolved effects. Proximity and the `match_pl.cpp` anchor do not put it on the small chain.

This is static original-instruction analysis, with no new execution oracle or implementation. Specimen SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; baseline `87ea0f39d5dcb62fe6969ad6570c3dca8b152673`; read-only checkpoint-12 exports, manifest SHA-256 `fa2728212d3189f2a0ec9f4db14b2355b0da8457bc9bff091d5c2b442b38a489`. Addresses are virtual; raw file offsets are labelled in [sites](../evidence/match-dependencies-13-sites.json). Names and field meanings are research labels. No native database was changed.

The extractor independently decodes all 701 assigned bytes with Capstone 5.0.7, finding 22/3/165 instructions. Instruction addresses and direct calls agree with the exports; all 2/17/32 exported incoming direct-call targets are checked against the original PE. This checks the supplied reference inventory, not indirect-call completeness. Digests identify original ranges without publishing their bytes or bulk listings.

## Entry and return contracts

`S` is ESP on entry. Stack arguments occupy four-byte slots; only their low bytes are consumed.

| Entry | Inputs and result | Cleanup/preservation |
| --- | --- | --- |
| `005b57c0` | ECX=base; index byte at `[S+4]`; AL=byte at `base+5b4+s8(index)` | `005b57cc: RET4`. Changes EAX only; no flags change. EAX upper24 are all zero for nonnegative index, all one for negative index. ECX/EDX and nonvolatile registers survive. |
| `006f4600` | ECX=slot; no explicit stack arguments; AL=raw slot byte `+108` or `+10a` | `006f4639/006f4641: RET`. Saves ESI; EAX/ECX/EDX and flags change. EBX/EDI/EBP survive, including through the fully mapped leaf. EAX upper24 are sign fill from slot byte `+19`, not a normalized boolean. |
| `006f46b0` | ECX=slot; target x/y low bytes at `[S+4]/[S+8]`; no consistent result value is established | `006f47a1/006f4919: RET8`. Reserves `204` stack bytes, saves/restores EBX/ESI/EDI; EBP untouched directly. EAX/ECX/EDX/flags are scratch; diagnostic-path preservation also depends on callees. |

The small chain has no game-state stores, x87 instructions or RNG, including transitively. Its only memory writes are stack mechanics. Both functions lack null, index, lifetime or memory-range guards. Their read-only contract assumes code/data/stack do not alias in ways that invalidate ordinary execution.

## Small chain: exact lookup and selected byte

Let `s=s8(byte(slot+27))`, `i=s8(byte(slot+19))`, and `m=dword(slot+19e)`. `006f4607..006f4622` computes `ECX=m+91e2+18e3*s`, with 32-bit x86 address arithmetic. The multiplier is 6,371, not a guessed structure size. `006f4629` calls the leaf with the low byte of slot `+19` pushed as its argument. The effective lookup is:

`f = byte(m + 9796 + 18e3*s + i)`

The leaf sign extends the index into EAX (`005b57c0`) and replaces only AL with the loaded byte (`005b57c5`). This is neither a zero-extended byte return nor a sign extension of the loaded value. `006f462e` tests bit 1 (`f & 2`): clear selects byte `slot+108` at `006f4632`; set selects `slot+10a` at `006f463a`. These values are returned unchanged, with no normalization, signed comparison or range clamp.

R12's `006bce20` consumes AL as a nonzero predicate at `006bce62`; the remainder of its ordered filter is unchanged. Because the now-complete chain cannot write match state or consume RNG, its post-call `match+8eb2` read has no intervening callee mutation in ordinary nonconcurrent execution. This removes that particular transitive uncertainty from R11's candidate loops; it does not resolve their large dispatch callees or outcomes. The second exported caller `006bcc96` instead sign extends AL at `006bcc9b`, evidence that the raw byte must not be renamed or prototyped as a normalized boolean. The leaf has 17 exported callers in several source areas; its contract is a general signed-index byte load, not exclusively a match predicate.

## `006f46b0`: coordinate cells and membership

Define `C(x,y)=dword(slot+19e)+215e+5a*(12*s8(x)+s8(y))`, all address arithmetic modulo 32 bits. Let `s=s8(byte(slot+27))`. Each observed cell uses byte `cell+58+s` as a count and dword `cell+4*(11*s+s8(index))` as a pointer slot. The constants support a partial layout of two 11-pointer lists followed by count bytes for side values 0/1; neither side validity nor the entire match layout is proved here.

The first gate compares target bytes with slot `+102/+103` (`006f46c0..006f46d4`). If both equal, it returns immediately: no membership repair, match-pointer read or coordinate mirror occurs. Otherwise `006f46dd/006f46e3` makes a **signed** comparison with -1: every negative slot byte `+28` selects insertion, every nonnegative value selects removal then insertion.

For an existing nonnegative index, the instruction order is:

1. Compute old and destination cell addresses from signed current/target coordinates; read old count (`006f472d`). A zero count selects diagnostics before any game-state list mutation.
2. Read `oldcell+4*(11*s+s8(oldcount)-1)` and copy that dword over `oldcell+4*(11*s+s8(oldindex))` (`006f47b6/006f47ba`). This is a last-element swap, not stable-order deletion. Decrement the old count as a wrapping byte (`006f47c9/006f47cb`).
3. Reload side/index from the slot and read the replacement pointer from the overwritten position. If nonnull, write its byte `+28` to the slot's current raw index (`006f47df..006f47e6`). The vacated last pointer is not cleared. If removing the last entry, the pointer may be the moving slot itself.
4. Read the destination count, assign it to moving slot `+28`, increment the destination count as a byte, then store the moving slot pointer at the indexed destination dword (`006f47ed..006f4811`). There is **no capacity check on this route**.

For a negative index, the function computes only the destination cell. It copies the old destination count into slot `+28` and increments that byte count (`006f483c..006f4847`) **before** a signed comparison of the new count to 11 (`006f484d/006f4852`). A passing comparison stores the slot pointer at `006f48d4`. The literal guard is `s8(newcount)<=11`; it is not an unsigned capacity check. For example byte 127 increments to 128 and passes as -128. No valid runtime count domain has been established; this observation does not admit corrupt state as safe.

Both successful routes write target x/y bytes to slot `+102/+103` (`006f48de/006f48e4`). If slot equals `dword(match+f582)`, they also write match `+8ea7/+8ea8` (`006f48f0..006f490a`); otherwise the mirror is skipped. The function does not write `match+f57a`, a score or an RNG state directly. It performs no coordinate or side bounds check and no protection against duplicate membership, invalid pointer/index, overlapping cells or aliases. Formulas describe instruction order; simplification into a well-formed container operation needs those invariants.

## Diagnostic and callee boundaries

There are no calls on the equal-coordinate or successful mutation routes. The zero old-count route calls `00944cff`, `0090d130`, `00944c9f`, `005e8290`, writes dword `00b67a34=0`, and returns via `006f47a1` if those callees return. It does not perform the subsequent direct membership/coordinate writes. Diagnostics use source anchor `00a16058` (`match_pl.cpp`) and line token `1315`; the insertion overflow branch uses `1338`. Each prepares two local 256-byte buffers, uses shared `00ae24d0`, and has unresolved diagnostic/global effects.

Overflow has already changed slot `+28` and destination count. After the same diagnostic sequence and `00b67a34=0`, it calls `005cc7d0`, `005a8f60`, then `00945934(-1)` (`006f48b7/006f48bc/006f48c3`). Tiny dependency checks show `0090d130` returns the constant pointer `00ad4394`, and `005a8f60` is just RET. The remaining diagnostic/cleanup bodies are unassigned.

**Boundary challenge:** Ghidra treats `00945934` as nonreturning. Its original 17-byte wrapper contains `CALL 00945956; ADD ESP,c; RET`, so nonreturn behavior depends on `00945956` and has not been proved by this task. If it returned, control would fall through `006f48c8` with an outstanding pushed argument and caller-clobbered registers; the normal insertion contract is not established for that continuation. This report therefore describes the intended fatal boundary as unresolved rather than promising either termination or safe recovery. No direct RNG exists in the owned body, but RNG and other effects inside the unassigned diagnostic/cleanup callees remain open.

The 32 exported callers include `0071404c` and `00714e7a`, in two large R11 dispatch dependencies. At both, the caller pushes two dword coordinate slots, sets ECX=slot and writes word `slot+198=68` before this call. This supports a relocation boundary, not a full-body claim about either caller. No edge joins this function to `006f4600` or `005b57c0` in the assigned bodies.

## Reproduction and limits

Run `python scripts/extract_match_dependencies_13.py PRIVATE_EXE --exports PRIVATE_EXPORTS_13 --output evidence/match-dependencies-13-sites.json` with Capstone 5.0.7. It rejects different specimen/manifest hashes, verifies contiguous PE decoding, all owned exported instruction addresses/direct calls, all supplied incoming direct-call targets, selected exact operands/widths, branches, stores, returns and small caller/dependency windows. Pseudocode corroborates old generic names only; assembly controls the contract.

The [findings](../evidence/match-dependencies-13-findings.json) record remaining questions, and the [annotation proposal](../evidence/match-dependencies-13-annotations.json) proposes descriptive names only, without prototype/layout changes. Static recovery covers normal instruction contracts; there is no new behavioral oracle, runtime invariant proof, connected shot outcome or full-match equivalence.

Deterministic extraction, wrong-specimen rejection, JSON parsing, staged privacy review, `git diff --check` and `npm run check` under Node 24.19.0 passed. The retained numerical suite checks earlier primitives; it is not execution evidence for these functions. For the semantic coverage register, all three owned bodies support `contract-supported` at this static scope, with the per-function limitations recorded in the findings.

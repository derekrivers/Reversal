# R41-B3: live cached-lookup return compared with x86 and TypeScript

R41-A4 observed a GDI lookup entry and its actual return in one invocation.
The [offline checker](../scripts/check_paired_return_41.py) admits that pair,
regenerates the original-instruction replay through the merged B2 runner,
and compares the live endpoint with that replay and its existing TypeScript
comparison. This closes the previously missing **live lookup return** for
one cached null-result invocation.

It does not establish the intervening live instruction sequence, a completed
enclosing effect, allocation lifetime, save replay equivalence or a resolver
entry-to-result path. B3 performs no game or process operations.

## Evidence and identities

| Item | Identity or boundary |
| --- | --- |
| GDI executable | SHA-256 `0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b` |
| Pinned map specimen | SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; mapping reference, not the observed process |
| A4 private capture | SHA-256 `7cdba6316f5e7286d3e59a8aa29049a12c1ee4d165e7b145e10d1608d990d589`, 28,890 bytes |
| Actual lookup entry | GDI virtual address `0062e6e0` |
| Actual return | GDI virtual address `006cf8f7`, after effect CALL `006cf8f2` |
| Capture times | `2026-10-20T18:37:42.430185Z` and `.430880Z`, 695 microseconds apart |
| Capture implementation | R41-A4 bounded two-event DR0 tool, reviewed head `f34ba20`, merged in [PR #152](https://github.com/derekrivers/Reversal/pull/152) |
| B3 base | Merged main `e620e6cbfc316ce0baf756c10bc3238542a02a8d` |

The checker records input digests without a one-file allow-list. As in B2,
capture provenance is supplied metadata, not independently authenticated by
the checker. It recomputes caller, thread, stack and alias relations, verifies
region hashes and compares those results with the capture's summary flags.
The actual runtime observation rests on A4's retained private record and
reviewed capture procedure. Both executable identities and entry/return code
digests are checked against the local original files.

## What matches

| Comparison | Result |
| --- | --- |
| Pair identity | Same thread; caller return address matches; actual return ESP is entry ESP plus 8 (`RET 4`) |
| Live return versus fresh original replay | All nine recorded general registers match: EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP, EIP |
| Returned pointer | Null in live execution, original replay and TypeScript |
| Original replay versus TypeScript | 85 instructions, 19 ordered nonstack memory events and two nested refresh boundaries |
| Fixed rereads | All 15 entry regions present, complete and hash checked at return |
| Stable endpoint bytes | 1,180 unique represented bytes agree, excluding callee scratch below entry ESP |
| Selected game regions | All 13 unchanged, including lookup/staff globals, date/flags, row, slot and four RNG cells |
| Slot aliases | At both endpoints, slot `+69` equals the participant argument and slot `+6d` equals staff `+61` |
| FS and floating state | Same FS selector/base/head; x87 metadata, 80-byte legacy register area and 512-byte extended area unchanged |
| Callee scratch stack | Changed, as expected for an executed callee; payload is outside the subsystem comparison |

The TypeScript comparison reuses `lookupCached41` and
`compareReplay41b2`; no simulation semantics or shared RNG implementation
change. B2 freshly executes the identified original instructions and checks
the same return, row/mapping, ordered memory events, nested boundaries,
shared RNG object and preserved state against TypeScript. B3 then compares
the actual returned registers and selected endpoint bytes with that fresh
replay. No observed return is supplied as a simulated input or substituted
for an unresolved callee.

The live data are **two boundary snapshots**. The 85-instruction sequence and
19-event ordering belong to the original-instruction replay. Unchanged live
RNG cells at the endpoints do not independently prove the absence of
intermediate RNG activity or writes that were later restored. The replayed
cached path executes no RNG call.

EFLAGS is excluded because debugger delivery/resume flags are outside this
subsystem's contract. Scratch stack payloads are not compared against
emulation. The return snapshot also contains eight stack bytes beyond the
entry's generic 512-byte region; these are checked for representation
integrity but have no entry-state equality claim. Uncaptured allocations and
concurrent activity remain outside the comparison.

## First missing enclosing-effect input

After this null return, static GDI instructions test EAX at `006cf8f7` and
select `006cf929`. The slot float at `slot+4d` is represented by the 446-byte
slot capture. The first following read absent from the runtime closure is
the constant at `00967f28`, read at `006cf92c`; it has backing in the
identified executable. Its runtime value was not separately captured.

The first missing **dynamic referent** is the attribute byte read at
`006cf956`: the preceding instruction at `006cf953` obtains the pointer from
slot `+6d`, and the read uses pointer `+2d` with width one. The pointer aliases
are now observed at both lookup endpoints, but that attribute byte remains
absent. Its value must come from a genuine same-boundary read or an evidenced
producer; no attribute value is invented here.

The checker validates these selected instruction forms in a 98-byte static
interval beginning at virtual address `006cf8f7`, file offset `002cf8f7`.
Its digest is retained in the receipt. It checks that the slot float is
represented and the identified constant and attribute byte are absent.
It does **not** execute that interval. A future continuation also needs the
appropriate floating-register execution model, later helper domains and
their own closure; this report supplies no whole-effect completion claim.

## Reproduction and verification

Requirements are the same as B2: Python 3, Capstone 5.0.7, Unicorn 2.1.4,
Node 24, the two identified local executables and the private A4 capture.

```text
python -B scripts/check_paired_return_41.py --input PRIVATE_A4_CAPTURE --pinned PINNED_EXE --gdi GDI_EXE --node NODE24
python -B scripts/verify_paired_return_41.py --capture PRIVATE_A4_CAPTURE --pinned PINNED_EXE --gdi GDI_EXE --node NODE24 --output evidence/engine-paired-return-41-validation.json
python -O -B scripts/verify_paired_return_41.py --capture PRIVATE_A4_CAPTURE --pinned PINNED_EXE --gdi GDI_EXE --node NODE24 --output results/engine-paired-return-41-optimized.json
npm run check
```

The checker emits one sanitized JSON result and exits zero for a match.
Unsupported or altered input exits one with a stable rejection code. It
creates original replay files only in an automatically removed private
temporary directory. The direct B2 TypeScript comparator still trusts its
supplied replay; B3 uses B2's specimen validation and fresh original execution
before comparing the live pair.

The [verifier](../scripts/verify_paired_return_41.py) checks normal/optimized
results and 20 altered-live cases: return/general registers, thread,
caller/stack metadata, resealed RNG/row/slot effects, invalid aliases at both
endpoints, FS/x87 changes, omitted rereads, inconsistent effect flags, wrong
return code, missing return, conflicting overlapping reads and timestamp
order. Resealed changes preserve hashes and overlapping aliases where the
test targets semantic state, so integrity checks alone cannot satisfy them.
B2 additionally rejects six altered replay/model comparison results.

The [public receipt](../evidence/engine-paired-return-41-validation.json)
contains counts, digests, static addresses, comparison flags, rejection
results and source hashes. Privacy scans cover the selected original code,
captured memory and floating-register areas in raw, hexadecimal and base64
forms; six intentionally inserted excerpts must be rejected. No raw
capture, memory, register values, stack payload, save or player data enters
Git. Shared registries, native database, queue and frontier remain with the
coordinator.

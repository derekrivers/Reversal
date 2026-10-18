# Keeper field producers and lifecycle, investigation 09

Specimen SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`.
Every code/data address below is a PE virtual address, never a file offset. Structure
names and semantic labels remain partial research labels. This is static producer
research; it adds no full-shot or match equivalence claim.

## Evidence and confidence

The private executable was hash checked and decoded with Capstone 5.0.9 in x86
32-bit mode, using PE mappings from pefile 2024.8.26 and the retained Ghidra atlas
function boundaries. Existing private Ghidra export `shot-map/00700420.asm` supplied
the consumer cross-check. Locally generated listings stayed under ignored
`results/keeper-producer-map/`. The accompanying compact evidence records selected
instructions and constants, rather than distributing those listings.

The coordinator subsequently supplied read-only native Ghidra assembly exports
from a disposable project copy. Review of `006ce110`, `006ec010`, `006eecb0`,
`0070a910`, `0070c040` and the relevant `00702050` sites corroborated 40 of the
47 selected instructions. In particular, the initial rating calculation
`006f01f1..006f025c`, final adjustment `006f0472..006f04a2`, fallback clamps
`006ec9de..006eca80`, float calculation/store `006ed927..006ed9a0` and byte
increments `0070701b/0070ae8f/0070c518` agree with the formulas and widths below.
No discrepancy was found in the committed findings or annotation proposals.
The seven sites outside these supplied function exports retain pinned-byte
evidence only; jump-table entries and constant values were independently read
from the pinned PE. Export hashes and reviewed address sets are retained in
`evidence/keeper-producers-09-native-corroboration.json`; bulk exports remain
private. This corroboration does not add an execution oracle.

**High confidence** below means widths, local dataflow and branch targets agree
with the pinned instructions. It does not mean that a whole producer routine has
been emulated. **Candidate** means a semantic interpretation or cross-function
lead that still needs an observed state trace or deeper caller analysis. A scan
for literal displacements is a lead finder: aliases, block clears and indexed
writes prevent treating its results as an exhaustive write inventory.

## Producer map

| Consumer field | Producer and width | Established scope |
| --- | --- | --- |
| Slot `+0x168/+0x16a` | `006f0255/006f025c`, two 16-bit stores, then indexed 16-bit stores in `006f0472..006f04a2` | Equal at these two stages of `006eecb0`; inputs include derived float attributes and a tactical modifier |
| Slot `+0xd1` | `006ed98d`, x87 `FST` float32; `006ed9a0`, dword zero clamp | Recomputed by `006ec010` from record input, fallback word and a local adjustment |
| Slot `+0x0f` | `0070701b`, `0070ae8f`, `0070c518`, byte stores after `INC AL` | Modulo-256 increment on selected tactical-position-1 paths; initialization remains open |
| Slot `+0x3b` | Seven 16-bit stores in `006ec010` | General derived rating, constrained and rescaled before keeper use |
| Match `+0x8eaa` | Byte writes in initialization, coordinate update, countdown and setter routines | Mutable match state; movement/flight countdown is a candidate interpretation |

## Rating words: the stores are followed by a shared adjustment

`006eecb0` receives the slot in ECX, saves it in ESI, calls `006ec010` at
`006eecb9`, and returns with `RET 4` at `006f05c5`. Its input record pointer is
slot `+0x6d`. At `006eecc1..006eece8`, it reads signed byte record `+0x0f`:
if greater than 15 it uses byte 20; otherwise it calls original `__ftol`
(`00945640`) on `0.75 * signed_byte + 5.0`, keeping AL. BL is sign extended into
EBP at `006ef833`; denote that value by `b`.

The local dependency expression for the initial equal rating words is:

```text
square = s16(ftol((b*b + 1.0) * 0.5))
a      = s16(ftol(10.0 * float32(slot+a5) + 0.5))
c      = s16(ftol(10.0 * float32(slot+79) + 0.5))
initial_word = low16(trunc_toward_zero((square + a + c) / 3))
```

The integer average uses signed multiply-high by `0x55555556` and sign correction
at `006f0238..006f0253`. DX is stored to both words. This expression describes
instruction dependencies; x87 precision, conversion overflow and out-of-domain
record inputs have not been tested as a producer contract.

Both words are then visited by an indexed loop: EDI starts at slot `+0x11a`, EBP
is 63 and EBX runs 0 through 62 (`006f040d..006f05b1`). The words occupy indices
39 and 40. The byte dispatch at `006f05e8 + index` selects 7 for both, and
the dword table at `006f05c8 + 7*4` targets `006f0472`. That block computes:

```text
final_word = low16(ftol(0.775 * s16(initial_word)
                       + 7 * (s16(slot+37) + 30)))
```

`0.775` is the float64 constant at `0096a6e8`. The tactical
modifier `+0x37` is itself zeroed at `006eecea` and accumulated earlier in this
routine through tactical-position bit tests and other state adjustments.
It cannot be replaced with an assumed constant. High confidence: equality of
these two words at the observed producer exit stages. No claim that every
possible later alias write preserves equality.

The routine calls `006f44a0` at `006f05b9` after the loop. That helper makes
multiple RNG calls and fills other byte attributes (`+0x104`, `+0x10a`, etc.).
Calling this producer during a shot therefore has RNG effects beyond these
rating formulas. `006bbb60` refreshes active slots in a 20-slot loop at
`006bbe10..006bbe27`; `006e1aa0` calls it immediately after writing slot `+0x19`
at `006e1cab`. These are direct lifecycle links from tactical state to ratings.

## Adjustment float and fallback rating share a producer

In `006ec010`, ECX is the slot, ESI preserves it, slot `+0x69` is a staff record
pointer and `+0x6d` is the player-record candidate. Staff `+0x18` is loaded into
frame byte `+0x12` at `006ec035..006ec040`; that byte is restored to BL at
`006ed7c4`. At `006ed927..006ed967`, signed byte player `+0x3a` is multiplied by
0.8 for BL >39, by 0.9 for BL >37, or left unscaled. The result is spilled to
float32 frame `+0x28` at `006ed96f`. Then:

```text
x87_value = (2 * float32(frame+28) + s16(slot+3b)
             - float32(frame+14)) * 0.1
slot+d1 = float32(x87_value)
if x87_value < 0.0: slot+d1 = 0x00000000
```

The store at `006ed98d` is `FST`, leaving the unspilled value for the comparison
with float64 zero at `006ed993`. EBP is zero from `006ec9cc` along this path, so
`006ed9a0` writes positive zero. The report does not assume that BL is an
authenticated age field, though its thresholds make age a candidate. Frame
`+0x14` begins as zero at `006ec054`, and conditional paths update it at
`006ec855`, `006ec88c` and `006ec9c2`; it is an upstream dependency, not an
independent constant.

Slot `+0x3b` is already a derived 16-bit rating by this point. Initial stores
are at `006ec696` and `006ec789`, from signed record word `+5`, local adjustments
and, on one path, record/slot state including signed slot `+0x100`.
`006ec8c0` further adjusts it with signed bytes `slot+0x17/+0x118`.
The tactical-position-1 path applies a lower bound from
`ftol(0.75 * s16(player+5))` at `006ec9de..006ec9fe`, with an additional lower
bound of 8 in the shown staff-ID/null case at `006eca02..006eca1f`. The upper
bound is player signed word `+7`, increased by 10 for tactical position 1
(`006eca23..006eca59`). Finally `006eca5d..006eca80` stores
`low16(ftol(0.5 * s16(previous_word) + 80.0))`.

These are high-confidence local dataflows, not a complete source-stat formula.
The keeper consumer reads `+0x3b` with `MOVSX word` and uses it as a fallback
RNG bound. Naming it a specific goalkeeper skill would overstate the evidence.

## The byte counter is updated by keeper callers

At each of `00707016..0070701b`, `0070ae87..0070ae8f` and
`0070c510..0070c518`, the instruction sequence is byte load, `INC AL`, byte
store. There is no saturation in those sequences. Each is behind a nonnull
slot `+0x19e` test and a `006c38c0` low-word result equal to 1. The latter two
operate on EDI, the keeper returned by `006ce110`; the first uses EBX in the
shared shot resolver owned by the other workstream.

The new counter also feeds RNG bounds: its zero-extended square is passed to
`0090cfc0`, and a resulting byte can update slot `+0x100`, followed by
`006eecb0` (`00707081`, `0070aef2`, `0070c57b`). That connects counter events
back to field recomputation and extra RNG consumers. A goals-conceded counter
is a plausible semantic lead; branch-to-score/commentary proof belongs to the
shot-resolver workstream. Its initial value, block-copy history, resets and
complete write set remain unknown; zero must not be assumed from these sites.

## Match state `+0x8eaa` has a lifecycle

* Constructor `006b7f20` writes byte zero at `006b84d7`.
* Normal reset routine `006c54a0` writes zero at `006c54c3`. Tiebreak setup in
  `006be710` writes zero at `006be798` and `006be87c`.
* `006cd770` writes match coordinates `+0x8ea7/+0x8ea8`, perturbs target
  coordinates, then sets `+0x8eaa` at `006cd88f`. Its third stack argument
  byte gives zero if zero, otherwise `low8(1 + RNG(s8(argument)+1))`.
* `00700390` is a small `this` setter: load first stack argument AL, write
  `[ECX+0x8eaa]`, `RET 4`. A caller at `006ffc69..006ffc7c` supplies
  `1 + RNG(3)`.
* In `006bbe40`, nonnull `+0xf582` or `+0xf57a` suppresses the update. With
  nonzero `+0x8eaa`, nonzero `+0x8eb2` clears it and `+0x8ea9`; otherwise
  signed values >=2 decrement directly, and signed positive values <2 use
  `RNG(value*value)` versus `RNG(2)` to decide whether to decrement. The
  decrement store is `006bbec3`. Coordinates may then move according to
  match word `+0x8ed8`.
* `006f0630` installs slot coordinates, side and owner pointer `+0xf582`,
  copies slot `+0x19a` to match `+0x8ed8`, and clears the byte at `006f08f5`.

This supports a movement/flight countdown candidate. The keeper postlude reads
it as **signed8** at `00700a8d`, so raw values 128..255 are negative inputs,
even though the common producer sites above emit small nonnegative values.
No exhaustive reachable-domain proof or runtime trace is available.

## Keeper selection and the other keeper callers

`006ce110` is a mutating cache/selection routine: match in ECX, one stack byte
side selector, 32-bit pointer result EAX, `RET 4`. It processes both sides
before selecting the returned cache. Side 0 slots start at match `+0x4796`,
side 1 at `+0x6a6e`; each contains 20 slots at stride `0x1be`. It returns
`+0xf5a2` when the selector byte equals 1 and `+0xf59e` otherwise.

Each existing cached pointer is cleared if its signed slot `+0x19` is negative
(`006ce120..006ce127`, mirrored at `006ce209..006ce210`). Existing nonnegative
caches are retained without repeating the full tactical search. If empty, the
20-slot scan selects the first slot with signed index `+0x19` in 0..10 whose
side-selected tactical word equals 1 (`006ce150..006ce171`, mirrored at
`006ce239..006ce25a`). It does not test slot `+0x2b` here; the keeper consumer
does that separately.

If no such slot exists, it falls back to the first slot with nonnegative
`+0x19` and can modify tactical-index bytes. A saved reserve candidate requires
`+0x19 == 0xfe`, `+0x20 == 0xff` and a `+0x1a` index 0..10 mapping to position
1. The fallback can exchange the reserve `+0x1a` value with the chosen active
index and conditionally rewrite chosen `+0x19` (`006ce1d2..006ce1fa`, mirrored
`006ce2bb..006ce2e3`). With no nonnegative slot the cache can remain null.
This function is not simply a pure position lookup.

Atlas direct callers of `00700420` are `00702050`, `0070a910` and `0070c040`.
The latter two call at `0070aa51` and `0070c188`, respectively, with action
byte `0xff`, variant byte 1 when signed match `+0x8ea9 >3` (else 0), and
coordinates taken from the acting slot. `0070a910` selects the opposite-side
keeper at `0070a99d`; `0070c040` selects the same-side keeper at `0070c0d0`
and skips `00700420` when that keeper pointer equals the acting slot.
Thus the action33 reconstruction does not cover every direct caller.

## Cross-boundary lead and remaining work

For the shot-resolver workstream's match `+0xf5ae` comparison: `006cd3d0`
examines candidate slot pointers, rejects activity >1 or negative tactical
indices, and calls `0070dfd0`. Return AL 2 stores the candidate at `006cd462`;
return AL 1 increments candidate byte `+0x12` then stores it at `006cd47e`.
`006cc540` clears the pointer at `006cc57a`; match advance clears a stale
pointee with null `+0x19e` at `006b9a2d`. Contact/block semantics remain open.

Next bounded work is to reproduce `006ec010/006eecb0` with explicit record,
tactical and modifier preconditions, trace counter initialization/reset aliases,
and establish a valid live match state for these producer calls. Neither this
static map nor existing action33 fixtures establish a whole producer, shot,
shootout or full match contract. Annotation proposals are data only in
`evidence/keeper-producers-09-annotations.json`; the coordinator owns the native
database and checkpoint.

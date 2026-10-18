# Tactical selection and result-statistics boundary, investigation 10

Specimen SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`.
All addresses are PE virtual addresses. Baseline: main
`944954fd19b73a133f4505afc5b28a486479b45e`. Function/field names below are
working research labels. This report records static contracts; no behavioral
TypeScript or new original-instruction oracle is introduced.

## Evidence and scope

Owned functions are `00896290`, `00896660`, and `008967d0`. The pinned executable
was decoded locally with Capstone 5.0.9/pefile 2024.8.26 using retained Ghidra
function boundaries. The coordinator's read-only Ghidra exports independently
corroborate their assembly and incoming direct references. Bulk exports and
listings remain private. Compact instruction sites and export hashes are in
`evidence/tactics-boundary-10-sites.json`.

High confidence applies to the local widths, pointer arithmetic, branch/call
sequence and writes described here. Tactical semantics are supported by the
shared selection word, consumers and match/UI callers, as well as the
`tactics.cpp` anchor. Allocation ownership, plan-field meanings and runtime
validity remain unresolved. Dependencies were read only to interpret these
three boundaries.

## Shared context and record boundaries

Each owned function receives a context pointer in ECX. Observed callers load it
from global pointer `00de1d08`; this supports a shared tactical context label,
without establishing its allocator or lifetime.

| Context field | Width | Observed role |
| --- | --- | --- |
| `+0x000` | pointer32 | Base of `0x28`-byte result-statistics rows |
| `+0x5f1` | pointer32 | Second plan bank |
| `+0x5f5` | signed32 use | Second bank count in setter's combined limit |
| `+0x5f9` | pointer32 | First plan bank |
| `+0x5fd` | signed32 use | First bank count/split point |
| `+0x601` | pointer32 | Base of rows at stride `0x91`; first word selects a plan |

`00896660` sign extends the selection word and returns a pointer into a bank
with record stride `0x18e3` (6,371 bytes). Independently, caller `006e0230`
copies `0x638` dwords plus a word and byte from that result at
`006e0c06..006e0c32`: exactly 6,371 bytes. Its destination is a side-selected
live match region at `match+0x91e2 + side*0x18e3`. The caller then can copy the
same extent to another buffer (`006e0c3c..006e0c49`). These are plan-record
boundaries; the 6,371 individual bytes are not all mapped fields.

## `008967d0`: update the selected plan word

ABI: ECX context; stack arguments club pointer32, **signed low word** plan ID,
and a full dword row-selection option. Success/failure is explicit EAX 1/0;
normal returns use `RET 0xc` (`00896873/008968e3`). Upper argument bits above
the plan ID word are ignored by this routine.

With a nonnull club, `00896817..00896839` admits a signed16 ID from 0 through
`context+5fd + context+5f5 - 1`, using 32-bit arithmetic and signed comparison.
It calls `008982b0(club, option)` at `00896846`. A result of -1 returns 0.
Otherwise `00896854..00896862` writes exactly one word:

```text
*(uint16 *)(context.mapping + 0x91 * returned_row) = low16(plan_id)
```

No plan-bank bytes are copied or changed by the owned body. Null club or an
out-of-range ID takes diagnostics, writes dword zero to global `00b67a34`, and
returns 0 if diagnostics return. The local body adds no bounds check on the
returned row other than the -1 check.

Dependency `008982b0` normally returns club dword `+0`. On its guarded path
with a nonzero option it derives a row using club `+0xcf`, global counts and
classification helpers, and can return -1. Thus the option can select a
different row domain. It is not proven to be a generic Boolean "save" flag.

## `00896660`: resolve a plan pointer, with an external registry path

ABI: ECX context; stack club pointer32 and an opaque full dword option;
pointer32 result EAX, `RET 8`. A null club takes diagnostics, clears
`00b67a34`, and returns null (`008966cb..008966db`).

The bank path starts at `00896759`. Let `club_id` be the club's dword at +0,
and `k = s16(*(context.mapping + 0x91*club_id))`. The result is:

```text
if k < context.first_count:
    context.first_bank  + 0x18e3 * k
else:
    context.second_bank + 0x18e3 * (k - context.first_count)
```

The comparison is signed32 after sign extension of the word. This path does
not validate `k >= 0`, the second-bank count, club ID, or mapped pointer
extent. A valid mapped selection and bank capacity are caller/state
preconditions. The setter's plan-ID validation does not prove that every
other producer or saved state satisfies them.

Before that path, `00600a50(club,1,1,0,0)` is called. If nonzero, the routine
tests `005fd210(club+cf)`; a nonzero result also requires low byte
`005fea50(2,club+cf)` to be nonzero to stay on the registry path. Otherwise it
falls back to the bank path. The registry path calls:

1. `005fbe20(option, club, club+cf)` at `00896737`, with ECX loaded from
   global `00b63c98`;
2. `005fbd00(club+cf)` at `00896749`, returning its pointer unchanged.

This path has effects: dependency `005fbe20` can write a registry selection
byte at an indexed record `+0x9a69`, and `005fbd00` reads that selection to
choose its pointer. This establishes that the public lookup boundary is not
pure. Those helpers' complete state/lifecycle contracts remain outside this
owned unit. The ownership implied by the `human_manager.cpp` dependency is a
manager-specific candidate, rather than a proof about every registry path.

## `00896290`: accumulate result statistics for the selected plan

ABI: ECX context; one stack match-record pointer32; explicit EAX 0/1 and
`RET 4`. The caller is match advance at `006ba9a0`, passing the record pointer
from live match `+0x4792`; it skips that call when the record's dword +0 is -2.

Null match takes diagnostics and returns 0. Before changing either row, the
routine calls `00600a50(club,0,1,0,0)` for each nonnull club at match-record
`+0x1c/+0x20`; any nonzero result returns 0. The exact classification of this
predicate remains a dependency, so this report does not name it an AI-only
filter.

It then visits both sides. For each nonnull club it uses the same direct
club-ID selection word as the bank path, and addresses a statistics row:
`context.stats + 0x28 * signed16(selected_plan)`. It calls
`007e4750(match_record, club, local_descriptor)` at `0089642e` to orient the
score bytes, then updates the row. The helper chooses record score bytes
`+0x47/+0x48` when the relevant signed byte is nonnegative, otherwise
`+0x43/+0x44`, and reverses them for the second club. Its byte outputs are at
descriptor `+0x19/+0x1a` (`007e48ae..007e48f6`). The owned routine ignores the
helper's return, so valid records and successful score extraction are
preconditions for meaningful statistics.

| Row offset | Store width | Local effect / working label |
| --- | --- | --- |
| `+2` | 16 bits | Increment games processed |
| `+4` | 16 bits | Increment when own signed8 score > opponent; wins candidate |
| `+6` | 16 bits | Increment on equal scores; draws candidate |
| `+8` | 16 bits | Increment on lower score; losses candidate |
| `+0xa/+0xc` | 16 bits each | Add sign-extended own/opponent score; goals candidates |
| `+0xe` | 16 bits | Add 3 on higher score, 1 on equal; points candidate |
| `+0x10/+0x18/+0x20` | float64 each | Three derived evaluation metrics |

Counter and sum writes use word arithmetic and can wrap. The metric calculation
reads the updated words as signed16 and clamps each of games, goals for, goals
against and points to at least 1. Let `m`, `f`, `a`, `p` be these clamped
values, and in real arithmetic let `q=p/m`, `g=f/m`, `z=m/a`. The three stored
metrics correspond to `z*g*g*q*q`, `z*g*q*q*q`, and `z*z*g*q*q` respectively.
This is a dependency explanation, not a floating-point replacement contract:
the instructions mix live x87 values with float64 spills at
`008964d9/008964f0/008964f8/00896500/00896506` before the final stores
`00896520/00896531/0089653c`. Runtime x87 precision and exact rounding are
unmeasured here.

There is no local duplicate-match guard or rollback. A missing club logs and
continues to the other side; the routine returns 1 after the loop, even when
a side was skipped. Both clubs selecting the same plan cause sequential
updates of the same statistics row. Return 1 therefore means the outer loop
completed, rather than an atomic successful update of two distinct rows.

## Call boundaries and remaining work

Native incoming direct references agree with the atlas:

| Owned routine | Direct call sites |
| --- | --- |
| `00896290` | `006ba9a0` |
| `00896660` | `005472fc`, `005fec42`, `006e0bfd`, `0072ccfe`, `008a7a0f`, `008ac019` |
| `008967d0` | `006e0be9` |

At `006e0be9/006e0bfd`, the match-manager caller sets the selection, resolves
it, and copies the returned plan extent into match state. The tactics-screen
caller stores the resolved pointer at its `+0xdec` field (`008a7a16`). These
uses support plan-selection semantics without mapping the plan's internal
position/order fields. The second lookup argument and setter's third option
have different downstream uses and should retain separate opaque names.

The owned bodies have no direct RNG calls. Transitive diagnostics/registry
effects are not established as RNG-free. Compact findings list all direct
callees, including diagnostics. No indirect-reference completeness, allocation
ownership, persisted format, full tactical decision algorithm, match-entry
precision, or original-instruction equivalence is claimed. The next bounded
test would supply synthetic banks, mapping and records to the original setter
and bank-lookup paths, and compare return pointers plus every write, including
diagnostics and registry boundaries where admitted. Annotation proposals are
data only; the coordinator retains native write ownership.

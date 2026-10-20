# R41-B: cached participant lookup and the GDI capture boundary

The bounded TypeScript implementation now runs `0062ed70 -> 0062c680 -> RET 4`
when the participant's status row already has the current date. It matches
**18 separate synthetic original entries, 1,566 instructions**, across the
pinned and GDI executables. A runtime capture has not been admitted to this
comparison. The R39 resolver still stops at its null participant diagnostic;
this unit does not change that fixture or connect a fabricated pointer to it.

The original producers remain those established in
[R39-B](action33-participant-39.md): `008968f0` obtains a borrowed staff-record
pointer from database storage; `006eaea0` stores it at slot `+0x69`, and copies
the separate attribute pointer at record `+0x61` to slot `+0x6d`. Staff base
replacement or database teardown invalidates the borrowed pointer. The lookup
global is independently published after `0062a680` returns, and cleared after
its destructor and release. No constructor, allocator, database load or
setup-to-match lifetime runs in this unit.

## Exact executable and operand map

The pinned PE is 7,192,576 bytes with SHA-256
`0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`;
the GDI PE is 7,188,480 bytes with SHA-256
`0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b`.
The [generator](../scripts/replay_engine_state_41.py) checks both identities and
compares **188 instruction pairs in ten selected ranges, 619 bytes per build**.
All addresses in this report are preferred virtual addresses. The
[oracle](../evidence/engine-state-41-oracle.json) records file offsets and
per-build range hashes separately.

Each instruction's size, mnemonic, register, operand width, memory base/index/
scale and displacement must match. Absolute addresses and branch/call targets
use an explicitly authored relocation map. There is no generic constant
subtraction and no allowance to normalize arbitrary differences. These are
PE-only comparisons; this unit does not claim a new native Ghidra export or
whole-build equivalence.

| Role | Pinned VA | GDI VA |
| --- | --- | --- |
| Effect's slot `+0x69` read | `006cfeb8` | `006cf8e8` |
| Effect's actual lookup CALL | `006cfec2` | `006cf8f2` |
| Participant lookup entry | `0062ed70` | `0062e6e0` |
| Lookup's actual refresh CALL | `0062edfc` | `0062e76c` |
| Refresh entry | `0062c680` | `0062bff0` |
| Borrowed participant store | `006eaecb` | `006ea8fb` |
| Candidate match advance entry | `006b98c0` | `006b92f0` |
| Lookup global | `00b63d28` | `00b62c70` |
| Refresh initialization flags | `00b63d10` | `00b62c58` |
| Staff base / signed count | `00ae23bc` / `00ae2364` | `00ae130c` / `00ae12b4` |
| Current date's first DWORD | `00ae2c90` | `00ae1be0` |
| RNG cursor / offset | `00de1f60` / `00de1f5c` | `00de0ea8` / `00de0ea4` |
| RNG last-word pointer | `00de2798` | `00de16e0` |
| CRT RNG state | `00ad6c30` | `00ad5b80` |
| RNG table base | `00aa2454` | `00aa139c` |

The RNG source map includes the complete small-bound instruction interval and
the CRT step. Neither executes in the cached lookup comparison. The lookup's
three initialization/registration arms are compared statically but excluded
from execution; the corresponding callee addresses are address mappings only.
The 17-byte match-advance entry is a probe lead, not a mapped whole function.

## Supported connected boundary

The original CALL into refresh executes with the original argument, receiver
and stack. Three reads test initialization bits 1, 2 and 4. With those bits set,
a nonnegative participant index below the signed staff count, nonnull attributes
and a matching two-WORD date, refresh exits before date conversion, update
calculations, allocator/CRT initialization or RNG calls. The cached exit does
not normalize the mapping at row `+0x0e`.

After the real refresh return, lookup re-reads the participant index and row
base, then reads mapping `rows + 31*index + 0x0e`. Mapping `-1` returns zero.
The admitted nonnegative mappings return `cache + 48*mapping`. The caller's
stack advances by eight bytes, including the return address and `RET 4`
argument cleanup.

The nine cases per build cover staff indices `0/7/31`, mappings `-1/0/2`,
flags `7/255`, varied dates, x87 control words `027f/037f` and three old SEH
heads, including nonzero values. These are mapped synthetic inputs with
count 64. They are not observed game states, reachable-goal examples or a
general cache-validity proof.

The [TypeScript model](../reconstruction/engine-state-41.ts) uses the existing
`RandomState` type and preserves the same caller-owned shared-state object.
The original emulator retains cursor, offset, limit and CRT state at their
actual build-specific addresses. Both compare the unchanged cells before and
after the nested call; no RNG answers are supplied and no call is skipped.
The RNG table is not read on this path and is therefore outside this bounded
memory closure.

The [checker](../reconstruction/check-engine-state-41.ts) compares the returned
pointer, row and mapping, all ordered nonstack reads and writes, both nested
call boundaries, row/RNG digests, restored SEH head, stack cleanup and shared
state identity. The original harness additionally checks all represented
nonstack pages, nonvolatile registers and the x87 control word. Scratch
registers, flags and stack scratch payloads are not TypeScript subsystem
outputs; no exceptional or asynchronous execution is admitted.

## Genuine capture still required

R41-A was given the exact GDI entry, globals and minimal capture closure above.
No game was launched, attached, suspended or otherwise controlled by R41-B.
A useful lookup-entry capture needs:

- Exact executable, module base, thread and entry identity; entry registers,
  return address and participant argument at `[ESP+4]`.
- Receiver's 44 bytes; staff record's 110 bytes; staff base/count and their
  index relationship; the selected 31-byte row and, for a nonnegative mapping,
  its 48-byte cache record.
- Initialization flags, current date and all four RNG cells, captured at the
  same stopped boundary.
- Stack through the nested frame (at least `ESP-0x260` through the arguments),
  actual thread FS base/head and x87 metadata.

For this bounded path, the row's first DWORD must equal the current date's
first DWORD and bits 1/2/4 must already be set. A stale row is a named update
dependency; overwriting the date or setting the flags would not admit it.
Attribute contents are not read in this cached domain, although their
nonnull pointer is read. Later effect execution needs additional referents.

The relevant Windows API for obtaining the WOW64 thread's segment descriptor
is documented as
[Wow64GetThreadSelectorEntry](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wow64getthreadselectorentry).
The returned descriptor combines its base components into the address of
FS offset zero. R41-A owns any implementation and host verification.

A genuine lookup-entry replay would establish a captured boundary only.
Proving that the same staff/lookup objects belong to the shooter at the
R39 effect entry still requires the actual effect caller, slot alias and
intervening lifetime. A lookup receiver alone does not close that edge.

## Verification and reproduction

The [integrity receipt](../evidence/engine-state-41-integrity.json) records
byte-identical normal/optimized regeneration and 13 Python negative probes.
They reject changed/wrong executables, a GDI participant operand-width change,
the wrong lookup-global mapping, original execution with missing initialization,
a stale row, null attributes or out-of-count participant, and raw/hex/base64
private-code excerpts. The 11 TypeScript probes reject altered returns,
mapping/row, boundary RNG digest, missing memory and unsupported state.

Privacy scans cover all overlapping 12–32-byte raw and hexadecimal windows
in the selected original ranges, plus 9–30-byte source windows at complete
base64 groups, including all three embedding alignments. Public evidence
contains authored code, addresses, digests and synthetic scalar state.
Original instructions, game data, runtime memory and source exports are absent.

```text
python -B scripts/replay_engine_state_41.py PINNED_EXE GDI_EXE --output evidence/engine-state-41-oracle.json
python -B scripts/verify_engine_state_41.py PINNED_EXE GDI_EXE --output evidence/engine-state-41-integrity.json
python -O -B scripts/verify_engine_state_41.py PINNED_EXE GDI_EXE --output results/engine-state-41-optimized.json
node reconstruction/check-engine-state-41.ts
npm run check
```

Use Node 24. The task checker remains separate from the coordinator-owned
shared runner. No native annotations, checkpoints, queue or frontier change.

The unfinished offline capture adapter is preserved locally in ignored
`results/capture_engine_state_41.unfinished.py`; it is excluded from this
research commit and requires capture admission tests before use.

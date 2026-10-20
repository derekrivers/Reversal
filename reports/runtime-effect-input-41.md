# R41-A5: bounded effect-input capture extension

This is a tool-only change. No game process was opened, navigated or probed for
this assignment. Live use requires independent review of the exact tool head,
CI and merge, followed by a separate runtime assignment and input revalidation.

## Added read closure

The existing GDI lookup entry `0062e6e0` and effect-caller return `006cf8f7`
remain the only paired breakpoints. For GDI SHA-256
`0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b`,
the paired entry closure additionally reads:

| Input | Address | Width |
| --- | --- | --- |
| Multiplier constant | Loaded image base plus `00567f28`; preferred VA `00967f28`, file offset `00567f28` | 4 bytes |
| Attribute input | Verified attribute pointer plus `2d` | 1 byte |

The instruction forms are recorded by R41-B3 in
[engine-paired-return-41.md](engine-paired-return-41.md): `006cf92c` reads the
constant, `006cf953` obtains the pointer from slot `+6d`, and `006cf956`
reads the attribute byte. This extension captures inputs at the lookup
boundaries; it does not stop at or establish execution of those instructions.
No attribute value or original constant bytes enter the public receipt.

The dynamic read requires the captured effect caller, a complete 446-byte ESI
slot candidate and 110-byte staff record, slot `+69` equal to the lookup
argument, and slot `+6d` equal to staff `+61`. The pointer must be nonzero and
its one-byte range at `+2d` must fit the x86 address space. A failed prerequisite
produces a specific status and no dynamic dereference. A failed or short read
retains its normal incomplete memory record. Missing evidence does not abort
an otherwise valid lookup pair.

At return the existing fixed-region reread captures the same constant and
entry-derived attribute address. The tool recomputes both aliases from the
returned slot/staff bytes and checks ESI against entry. If both pointers change
together, the old address is still recorded as a fixed-region observation, but
`current_attribute_complete` is false. Alias mismatch, missing inputs, null,
overflow and changed ESI likewise prevent a current-attribute claim. There is
no chase of a new return pointer. Constant read completeness is separate from
attribute completeness; live-to-disk constant comparison belongs to later
capture admission, not this tool-only test.

`all_requested_reads_complete` continues to describe only reads actually
requested. Consult `effect_inputs` for skipped dynamic reads and their reasons.
The prior missing-state list still refers to the complete attributes allocation
and other unrepresented effects; one captured byte does not close that scope.

## Bounds and cleanup

The addition is at most five requested bytes per boundary, ten total. Unpaired
captures do not request either added region. Caller/thread/RET4 stack matching,
queued owned-entry draining, application exception forwarding, debug-register
restoration/readback and detach remain unchanged. The planned live request is
40 seconds; the existing CLI maximum is 60 seconds, with the same five-second
loop cleanup allowance, 2,048-event ceiling and five-second emergency stop wait.
There are no additional breakpoints, stepping, writes or retries.

## Verification

The pure fake-memory checker covers valid and relocated inputs; null,
overflow, the last valid x86 byte, unmapped and short reads; caller and both
alias failures; missing slot data; short constant data; changed slot/staff
pointers independently and together; changed return ESI; incomplete return
data; and unchanged unpaired scope. All 18 cases run under normal and optimized
Python. Checks use explicit requirements rather than removable assertions.

The existing nine owned WOW64 pairing cases, three deterministic queued-event
cases and legacy capture/INT3/timeout tests are retained under normal and
optimized Python. These operate only on checker-owned synthetic processes.
Node 24 repository checks, public privacy scanning and diff checks are required
before submission. The sanitized receipt records the completed results and
source digests; private logs and a restore-tested tool archive remain ignored.

No new live equivalence, attribute lifetime, intervening write order, actual
`006cf956` consumption or completed effect is claimed.

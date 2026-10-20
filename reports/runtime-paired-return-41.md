# R41-A3: bounded lookup entry and return observation

## Status and scope

This change adds an opt-in `--paired-return` mode to the reviewed WOW64 capture
tool. It has been tested only against checker-owned synthetic x86 processes.
There is no new game observation, live return, completed effect or lifetime claim.
The tool revision requires independent exact-head review before live use.

The production profile remains restricted to the disposable game-copy path and
GDI SHA-256 `0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b`.
Paired mode permits only preferred lookup entry `0062e6e0` and its evidenced
effect-caller return `006cf8f7`. Their RVAs are `0022e6e0` and `002cf8f7`;
runtime addresses are the loaded module base plus these RVAs. Both mapped
16-byte code windows must match the identified disk image before attachment.
The prior [capture report](runtime-capture-41.md) and R41-B evidence establish
the caller and `RET 4` boundary. The pinned research executable is a separate
specimen; no pinned-runtime equivalence is implied.

## Pairing and bounded observation

1. Arm DR0 at the lookup entry on debug-event threads using the existing
   non-elevated Windows/WOW64 debugger.
2. Stop at the first owned entry hit. Capture the existing register, x87, FS,
   stack and bounded lookup closure. Require `[ESP]` to equal the mapped
   effect-caller return. A different or unreadable caller stops unpaired.
3. Record that thread and `expected return ESP = entry ESP + 8`. Replace only
   its DR0 with the return address; leave newly created threads unarmed.
   Other existing entry watches retain their ownership evidence until drained
   once or restored during final cleanup. No later invocation replaces this
   selected entry.
4. Accept an owned return hit only on that thread, at that address and with
   the expected ESP. A recursive visit to the same address with another ESP
   stops unpaired. The tool does not single-step, retry an ambiguous hit or
   skip ahead in the game.
5. Capture return registers, x87, FS and stack, then reread the exact addresses
   selected at entry. Record complete-read hash equality and nonvolatile
   register equality. Missing reads remain missing; returned ECX/ESI are not
   reinterpreted as a new object graph.
6. Restore saved debug registers with readback, continue the pending event and
   detach. Entry-only timeout, mismatch and error paths use the same cleanup.

The two observations establish thread, caller and stack correspondence. They
do not trace the intervening instructions, prove that a specific `RET` rather
than another control transfer reached the boundary, establish ordered effects,
or prove object ownership/lifetime. A nonvolatile mismatch is reported rather
than silently normalized. Raw observations and fixed-region rereads are private.

Existing limits remain: a requested deadline greater than zero and at most
60 seconds, 2,048 debug events, at most eight explicit regions, each at most
4,096 bytes and together at most 15,872 bytes. Entry has a 512-byte stack read
and at most 1,484 bytes of lookup graph. Return has its own stack/regions and
one reread of the fixed entry regions: at most 52,120 sampled bytes across both
events, plus two four-byte FS heads and the existing identity reads. An invalid
optional ESI range is labelled missing at entry and is not retried at return.
The event loop allows five seconds beyond the requested deadline; exceptional
cleanup can additionally perform one bounded 5,000 ms event wait. These are
bounded API waits, not a hard real-time guarantee.

Application exceptions remain `DBG_EXCEPTION_NOT_HANDLED`; only identified
owned hardware and debugger bootstrap/timeout exceptions are consumed.
No application registers, code bytes or game data are written. The instrument
changes debug registers, pauses execution and may create a timeout-break thread.

### Late entry traps from other threads

Independent review identified a concurrency gap in the initial paired tool:
another armed thread could already have generated its entry exception when the
first entry was selected. Disarming all other threads cannot retract an already
queued exception, and the initial handler would forward that owned exception
to the application.

The correction preserves the other threads' entry watches. A late event is
owned only when its thread is still in the entry-watch set, EIP and DR0 both
equal the entry address, and DR6 reports breakpoint zero. The handler restores
that thread's original debug registers before continuing the pending event,
removes the watch and records the drained thread. The stopped instruction can
then execute normally. Each other thread can produce at most one such owned
entry stop; its entry snapshot never replaces the selected pair. An application
INT3 or a later trap after that watch was removed remains unhandled by the
debugger. The selected return also requires its DR0 to match the return address.

Threads that never reach entry remain armed until final restoration. All
late stops count toward the existing 2,048-event and time limits. This bounded
drain introduces possible extra pauses between the two observations; it does
not establish atomic game state or exclude concurrent writes.

## Synthetic validation

Run on Windows with 64-bit Python:

```powershell
python scripts/check_runtime_paired_return_41.py
python -O scripts/check_runtime_paired_return_41.py
python scripts/check_runtime_capture_41.py
python -O scripts/check_runtime_capture_41.py
```

The new checker creates and terminates its own hidden system x86 PowerShell
children. Its fixture allocates synthetic wrapper/callee/helper instructions;
no original executable bytes or game data are included.

Nine cases pass under normal and optimized Python:

- A nested-helper call returns 42 through `RET 4`; thread, caller, ESP, FS,
  nonvolatile registers and fixed-region rereads agree.
- A different caller stops before arming a return.
- A jump with a wrong stack cannot become a pair.
- A recursive wrapper reaches the identical return address on the same thread
  with a different stack and is rejected.
- A nonreturning callee reaches the deadline; entry is retained, return absent,
  debug registers restored, debugger detached and child alive.
- A native vectored handler processes an intervening application INT3. Its
  counter increases once and the return reread records the change.
- Injected return-read, breakpoint-transition and resume failures all detach;
  each child supports a subsequent successful paired attach, also checking
  that the old hardware breakpoint does not remain enabled.

Three deterministic fake-API queue cases additionally cover selected return,
timeout and an injected late-entry disarm failure. Each queue models another
previously armed thread's entry trap after selection, an unarmed newly created
thread, an application INT3, a foreign trap after disarm, and a third armed
thread that never hits. They require the owned trap to be handled exactly once,
disarming before its resume, preservation of the selected entry, forwarding of
application/foreign exceptions, and restoration of every saved thread before
detach. The queue exercises the actual capture event loop without launching a
process. It does not claim a live simultaneous-thread stress test.
Running the same deterministic queue against the initial `5c35421` tool
rejects its forwarding of the late owned trap under normal and optimized
Python, without launching any process.

The retained single-hit checker also passes under normal and optimized Python:
three real hardware hits, application INT3 preservation, timeout cleanup, FS
closure and optional ESI overflow/null/unmapped cases. `npm run check` uses
Node 24; this Windows debugger checker is an explicit local gate rather than
a game operation in the cross-platform research runner.

## Configuration gate for a later live run

A read-only recheck of the private 784-file configuration still finds ten root
language files absent in the disposable copy; every other manifest entry
matches. The duplicated input save retains SHA-256
`8698569fbd83d9952a9832a95aee17a943c32f18e29621e9396ed228107abbd3`.
No source installation or save was modified, and no game process/UI was
operated during this tool-only change.

Before any later live run: finish exact-head tool review and merge; use that
merged tool on a new follow-up branch; resolve the disposable configuration
against the preserved source hashes and revalidate all 784 entries, executable
and duplicate save. Keep raw results private, restore-test their archive, and
publish only a sanitized receipt. A successful pair would still leave the
effect continuation after `006cf8f7` and ownership lifetime unresolved.

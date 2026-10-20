# R41-A: single-use WOW64 execution interception

The new `scripts/runtime_capture_41.py` uses a Windows debug-event loop and a
DR0 hardware execution breakpoint. Its safe-process checker intercepted a real
six-byte synthetic function twice, at the actual x86 entry EIP, with restoration
and detach between attempts. A deliberately unreachable address exercised
deadline cleanup. This establishes working host interception; no game boundary
has yet been captured at this review checkpoint.

The production CLI accepts only the separately identified GDI executable SHA-256
`0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b`,
inside this worktree's ignored `results/game-copy`. Synthetic capture is available
only to the Python checker with its own live `Popen` child and the system x86
PowerShell image; the CLI cannot select that profile. Disk hash, process path,
WOW64 architecture, module/header identity and 16 live entry bytes are checked.
The result distinguishes preferred VA, RVA, file offset and loaded runtime VA.
The initial allowed entries are R40's four relevant entries plus R41-B's mapped
match advance `006b92f0` and lookup `0062e6e0`.

The debugger receives each thread through process/thread creation events. At the
initial breakpoint it arms those threads, and arms subsequent created threads
while attached. Existing enabled hardware breakpoints are rejected. It records
the thread which actually triggers DR0 rather than assuming the UI thread. At a
hit, Windows has suspended the process threads for the debug event; integer,
legacy x87, extended context and 512 stack bytes are read. The tool restores the
original debug registers, checks address/enable readback, continues the event and
detaches. It never patches code or modifies game data.

The deadline is 60 seconds maximum, with a five-second event-cleanup allowance
and at most 2,048 events. Timeout uses `DebugBreakProcess`, whose remote-break
thread requires process create-thread and VM rights. An early safe test with
insufficient rights failed with error 5; the corrected rights passed timeout
cleanup. The CLI has no elevation or broker. Forced host termination can bypass
cleanup; a Windows cleanup API failure is an explicit failure, not a successful
capture. All-thread event stops affect scheduling.

At GDI lookup entry, the tool follows a bounded graph: entry stack, lookup
receiver, staff argument, selected status row, selected cache record when valid,
flags/count/date/global. R41-B supplies the build-specific mappings. Missing
FS:[0], staff-attribute referent, refresh closure, RNG mapping/table, return
effects and ordered calls remain explicit. Even complete requested reads do not
make a complete replay fixture. No pinned-build runtime equivalence is claimed.

Output uses the existing guarded exclusive private JSON writer beneath ignored
`results/`. Raw captures, saves, game files and screenshots are excluded from Git.
The working copy overlays the installed base files with the user's VirtualStore
language/configuration files, omitting saves and temporary files. Its duplicated
experiment save has SHA-256
`8698569fbd83d9952a9832a95aee17a943c32f18e29621e9396ed228107abbd3`.
The copied config's save directory was changed to the disposable directory.
Full data/config identity and paired-save experiments remain pending.

Run `python scripts/check_runtime_capture_41.py` and its `python -O` variant for
two actual hits, a timeout, target survival and deadline rejection. Both passed
on Windows x64/Python 3.13.7. The repository check uses Node 24.

API basis:
[debug events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events),
[WOW64 context writes](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64setthreadcontext),
[debugger detach](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop).
These are supported API contracts; the live safe-process checks establish the
specific behavior exercised here.

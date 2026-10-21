# R41-A: single-use WOW64 execution interception

The new `scripts/runtime_capture_41.py` uses a Windows debug-event loop and a
DR0 hardware execution breakpoint. After independent review, it intercepted
the real GDI RNG entry and then the participant lookup entry during an ordinary
match. These two run-A captures restored three threads' debug registers and detached.
The lookup's actual return address is the effect caller's `006cf8f7`, its status
stamp matches the current date, and all requested reads and the FS head are
complete. This resolves the previous host-interception blocker.

The production CLI accepts only the separately identified GDI executable SHA-256
`0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b`,
inside this worktree's ignored local game copy. Synthetic capture is available
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

Requested memory is limited to eight explicit regions, each at most 4,096 bytes,
and 15,872 explicit bytes in total, plus the fixed 512-byte stack sample and
four-byte FS head. Lookup captures add at most 1,484 bytes of bounded selected
state, including the optional 446-byte ESI region. Identity/header reads occur
separately before attachment. These bounds are unchanged by the ESI correction.

At GDI lookup entry, the tool follows a bounded graph: entry stack, lookup
receiver, staff argument, selected status row, selected cache record when valid,
flags/count/date/global, staff base and four RNG scalars. The documented
WOW64 selector-entry API also obtains the actual FS base and four-byte head,
with explicit failure metadata. R41-B supplies the build-specific mappings. Missing
staff-attribute referent, refresh closure, RNG table, return
effects and ordered calls remain explicit. Even complete requested reads do not
make a complete replay fixture. No pinned-build runtime equivalence is claimed.

Output uses the existing guarded exclusive private JSON writer beneath ignored
an ignored local capture directory. Raw captures, saves, game files and screenshots are excluded from Git.
The working copy overlays the installed base files with the user's VirtualStore
language/configuration files, omitting saves and temporary files. Its duplicated
experiment save has SHA-256
`8698569fbd83d9952a9832a95aee17a943c32f18e29621e9396ed228107abbd3`.
The copied config's save directory was changed to the disposable directory.
The private inventory hashes 784 files separately from the save. Its canonical
manifest SHA-256 is
`fd4d4fefe5890bc26f7e67722de4efe5738cb76d53035d8953b6bc02cc3a897a`;
all 784 files and the save were unchanged when checked for the second run.

Run `python scripts/check_runtime_capture_41.py` and its `python -O` variant for
three actual hits, a timeout, target survival, actual FS head and deadline
rejection. The third hit follows an application INT3 whose vectored exception
handler increments a private counter. This regression verifies that unrelated
application breakpoints are passed to the application. The initial bootstrap
breakpoint is handled once; the timeout breakpoint must match its exception
address and remote-thread start address on a thread absent from initial inventory.
An independent review caught the earlier swallowing of unrelated INT3 events;
the corrected normal and optimized runs both pass. The full repository check
passed on Node 24.19.0.

API basis:
[debug events](https://learn.microsoft.com/en-us/windows/win32/debug/debugging-events),
[WOW64 context writes](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64setthreadcontext),
[debugger detach](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop).
These are supported API contracts; the live safe-process checks establish the
specific behavior exercised here.

## Live captures and evidence limits

The [sanitized receipt](../evidence/runtime-capture-41-live-summary.json) records
capture hashes, identity, timing intervals and mapping. The two run-A captures have
loaded base `00400000`, thread 19248 and x87 control word `027f`.

| Capture | Preferred/runtime VA | RVA / file offset | Event interval UTC |
| --- | --- | --- | --- |
| RNG A | `0090c860` | `0050c860` / `0050c860` | 17:28:39–17:28:59 |
| Lookup A | `0062e6e0` | `0022e6e0` / `0022e6e0` | 17:29:10 |

These intervals on 20 October 2026 come from output reservation/write times;
the original raw results lacked an event timestamp. The current tool adds that
timestamp for subsequent captures. The RNG hit occurred after kickoff while
the debugger was attached for about 19.86 seconds; lookup hit in 0.73 seconds.
These are actual debug exceptions, not sampled EIP matches.

Lookup A contains the actual staff argument and receiver, matching current
status row, flags, staff base/count, date, stack, FS head, four RNG scalars and
floating-point context. The selected row has a null-result mapping, so no cache
record is required for that admitted lookup path. R41-B separately replayed
this genuine entry through the original instructions and TypeScript; its report
owns that comparison. This capture alone observes entry, not the live return,
ordered effects, slot ownership, producer execution or a complete attempt.

The current tool adds a 446-byte ESI candidate-slot read at the same
event and records the two pointer equalities and effect-return provenance.
The corrected extension passed independent review. Its first run-B attempt was
blocked by a security dialog; after the user dismissed that dialog, a fresh
bounded attempt captured the slot at the actual lookup event. No resumed
process read at Lookup A's old addresses was substituted for same-event state.

The extension review found that an unrelated caller's ESI near `ffffffff`
could overflow the optional 446-byte range and abort an otherwise valid capture.
The corrected tool records an incomplete, out-of-range candidate without issuing
that read; both alias results remain null. A pure fake-memory regression checks
overflowing, null and valid-but-unmapped ESI under normal and optimized Python.
Required region limits are unchanged. The original live captures and their
backup remain byte-for-byte unchanged; this correction applies to future captures.

## Blocked second lookup attempt

The reviewed tool at `ac8a965b1c111cf0e744a89d820c9c48a44ad1fb` attached to
run B for one 40-second lookup attempt. A Windows Security network-permission
dialog for Node.js covered the game before any kickoff input was sent. The
operator did not interact with that dialog or advance the game. The debugger
timed out after 40.106 seconds, restored seven threads' saved debug registers
and detached successfully. The result has `hit: false` and no sample.

This is a timeout while the game remained before kickoff, not evidence that
gameplay omitted the lookup. The same-process reload experiment and ESI
pointer-alias observations remain pending. No more game input or instrumentation
was attempted while awaiting the user's dismissal of the security prompt.
The sanitized receipt records the raw-result hash and cleanup facts without
publishing registers, pointer values or memory.

## Run-B lookup with slot referent

After the user confirmed dismissal, read-only observation found the original
run-B process and kickoff screen intact. A new 40-second-bounded capture then
hit `0062e6e0` at `2026-10-20T17:56:02.489953Z`, on thread 25272, approximately
15.07 seconds after attachment. The operator used the ordinary Kick Off control.
All selected reads and FS head completed, the x87 control word was `027f`,
five threads' debug registers were restored, and the debugger detached.

The stack return again identifies the effect call, and both pointer comparisons
hold at this stopped event: slot `+0x69` equals the staff argument at `[ESP+4]`,
and slot `+0x6d` equals the staff record's `+0x61` attribute pointer. The selected
status row has the current date and a null-result mapping. Raw capture SHA-256:
`174988ab0a5da960a4fc4e1d9e6c02f6616522f3a3b65ee0313578bf0e2e2289`.
R41-B received this capture read-only for original-instruction/TypeScript replay.

This establishes a genuine effect-to-lookup state edge at one boundary. It does
not execute the slot producer, prove ownership or lifetime across calls, capture
the live return, or establish a complete action33 attempt.

## Paired save experiment

Runs A and B each start a fresh GDI process and load the same unchanged duplicate
save with the same 784-file configuration. Both follow fixture → squad → player
profile → Back → tactics → Cancel → Continue → Continue → Yes. No squad or
tactical selection was intentionally edited. The screenshot evidence does not
substantiate a condition change caused by those visits.

Before kickoff, A displayed referee Mohammed Al-Hakim and “Breezy, Shower, 9 C”;
B displayed referee Drazenko Kovacic and “Breezy, 9 C”. These setup differences
were observed before the debugger attached to either run. Cosmetic background
images differed earlier. A subsequently completed 0–1; B completed 3–0.
The earliest recorded gameplay divergence is therefore setup, not final score.

This is a fresh-process comparison, not a same-process reload test. Time and
process-only state were not controlled, and A's CD-prompt transition included
external input detected by the UI bridge. No RNG-initialization, save-restoration
or weather/referee cause is inferred. A whole-save deterministic replay remains
unestablished despite the usable captured function boundary.

The bounded attempt to reload within run B used Game Options → Restart Game →
Yes. Cancel on “Save Game Before Restart” returned to the results screen.
Repeating the route and saving under a new filename preserved the original
experiment save, but the native restart exited process 15240 and created child
process 24804 with parent 15240 at `17:58:49.881519Z`. The child displayed Setup
Game. Thus the observed normal Restart route starts a new process; it did not
provide a same-process reload comparison. No third save load was performed.

Post-restart hashing confirms the input save unchanged and the other original
manifest entries unchanged, apart from ten root language files now absent in
the disposable copy. Their removal was not traced. This later state must not be
confused with the matching 784-file A/B pre-run configuration. Another run needs
configuration revalidation. The separately saved run-B result is private and
has SHA-256
`4bc5e4fa0145994eba5996756963188885471becd865937787e13e6a4671cdd6`.

## Private preservation and resume

Private results retain 16 journey screenshots, three raw hit captures and one
timeout result,
scenario and configuration manifests, the duplicated save and the disposable
game copy. Files named `.png` from the UI bridge contain JPEG bytes; their
original bytes/names were preserved and the private manifest labels encoding.
The screenshot journey covers setup/load, fixtures, squad, player, tactics,
proceed modal, kickoff, running commentary and full-time result.

A separate local ZIP was extracted and all 25 entries independently rehashed.
Archive SHA-256:
`dc24ef02dda83321b290a48c58d3b393ce65438efa54cb94301757e992fbe38f`,
151,793,237 bytes. It includes captures, screenshots, logs/manifests, duplicate
save, both executable identities, active config and English language file.
Remaining installed data is inventoried but not duplicated into this archive.
This establishes local backup/restore only; no off-host durability is claimed.

A second local archive preserves the corrected tool/checker/report, full-check
log, timeout result and resume note: SHA-256
`f3e5d7e2c0cfa6fb22c06df40925f02505d019519f136d74c60eb2142fea9e14`.
All seven entries were independently extracted and rehashed. This supplement
preserves the state before this reporting-only wrap-up; the original capture
archive remains unchanged.

The follow-up capture, three new screenshots, restart/identity manifest and
separate post-match save are preserved in a third local archive, SHA-256
`ae0dcab384cd97569e73dd9d1074a66e7c6af47d67f7dfc375529dbb7917f8de`,
134,394,431 bytes. All six independently extracted entries match their recorded
hashes. The two prior archives were preserved.

The remaining process is the restart child, 24804, at Setup Game with no save
loaded and no debugger attached. The next useful execution observation is a
paired same-thread lookup entry and actual return at `006cf8f7`: expected
`ESP = entry ESP + 8` after `RET 4`, EAX, nonvolatile registers, RNG and selected
row before/after. That needs a separately reviewed bounded two-event extension;
the current one-hit tool does not establish this join. No additional probing
was attempted. No shared registry or canonical Ghidra state was changed.

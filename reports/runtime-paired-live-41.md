# R41-A4: live lookup pair and first UI navigation batch

## Live result

One bounded run of the merged, independently reviewed R41-A3 tool observed
GDI lookup entry `0062e6e0` and its effect-caller return boundary `006cf8f7`.
The selected thread, entry caller and expected `ESP = entry ESP + 8` matched.
The return value was null. All seven saved threads' debug registers were
restored with readback and the debugger detached. No additional probe followed.

| Identity or observation | Recorded value |
| --- | --- |
| GDI SHA-256 | `0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b` |
| Reviewed tool SHA-256 | `7f27a745f6364e4222afb4704d5ffb414f0d5284329f34fdcfd9d99eddc5c4a6` |
| Reviewed source head | `f34ba202c0f05fc936f5708204088ab731cc4bd1`, merged in PR #152 |
| Loaded image base | `00400000` |
| Entry VA / RVA / file offset | `0062e6e0` / `0022e6e0` / `0022e6e0` |
| Return VA / RVA / file offset | `006cf8f7` / `002cf8f7` / `002cf8f7` |
| Process / selected thread | 6268 / 27348 |
| Entry timestamp UTC | `2026-10-20T18:37:42.430185Z` |
| Return timestamp UTC | `2026-10-20T18:37:42.430880Z` |
| Requested bound / elapsed attachment | 40 seconds / approximately 19.031 seconds |
| Late entry traps drained | 0 |
| Private raw capture | 28,890 bytes; SHA-256 `7cdba6316f5e7286d3e59a8aa29049a12c1ee4d165e7b145e10d1608d990d589` |

Both slot pointer aliases were present at entry. The slot, staff record,
lookup receiver and selected status row were unchanged at the paired return.
All thirteen selected non-stack game regions reread completely and matched
their entry hashes, including the four captured RNG globals. The ordinary
512-byte entry stack window was unchanged; the larger window below entry ESP
changed. Both FS-head reads completed. EBX, ESI, EDI and EBP matched at the two
events. These are endpoint comparisons, not an intervening write trace.

R41-B received the private pair read-only for independent original-instruction
and TypeScript comparison. Its separate report owns that replay result.
The next dynamic effect input identified by B is an attribute referent read
after this return; that byte was not supplied by a new probe here.

## Configuration and launch provenance

The previous native restart left ten root language files absent from the
disposable copy. The parked setup process was closed through its ordinary Exit
Game confirmation. Each missing language file was restored from a private
source with the exact hash in the preserved manifest. No source installation
or original save was modified.

Before launch, all 784 baseline data/configuration files matched, including the
exact GDI executable. The duplicate input save retained SHA-256
`8698569fbd83d9952a9832a95aee17a943c32f18e29621e9396ed228107abbd3`.
The configuration manifest file itself hashes to
`92aa3097961c972c8bd868d33766bcec59f0c9f799236a3b46c07044d13b1843`.

The first app-API launch produced `Langlib..cpp 479` and `game_config..cpp 131`
errors before a save was loaded. Both screens were retained and the process
closed after the ordinary error acknowledgements. The 784 files were rechecked
unchanged. Launching with the disposable game directory explicitly set as the
working directory succeeded. This is an observed launch difference, not a
reverse-engineered diagnosis of either error.

The unchanged duplicate loaded into Evening Fixtures. The ordinary route was
Continue Game → squad → Continue Game → proceed confirmation → kickoff.
The visible setup differed from earlier runs: the weather included “Wet”.
No deterministic replay or cause is inferred. The debugger attached at kickoff;
ordinary Kick Off input started the match and produced the pair.

The match subsequently finished 4–0. It was continued once from half time and
once from full time into Evening Results. The input save was not overwritten,
and no new postmatch save was written. The process remained available for UI
mapping. All 784 baseline files and the duplicate save still matched after
the completed UI batch at `18:47:39.839976Z`.

## UI batch and evidence boundaries

The first batch retained 78 private JPEG captures with hashes, dimensions,
capture order, retention timestamps, entry routes, prerequisites, observed actions and
back-path notes. It includes the parked setup and exit confirmation, both
failed-launch errors, successful restore states, match setup/running/half-time/
result states, and the read-only navigation below.

| Area | Captured coverage in this batch |
| --- | --- |
| Match | Overview, Match Stats, Action Zones and Match Report at half time; return to Overview |
| Club information | General Info, Stats, Finances, Income and Expenditure, plus selected dropdown states |
| Club transfers | Players In/Out, Future Transfers, Loans In/Out and Staff In/Out |
| Player | Profile, Injuries & Bans, Contract, Transfer, History; direct return to the same Profile from each main detail tab |
| Player history | Playing Career, Achievements, Injuries and Bans |
| Club fixtures | Fixtures and Next Match |
| Competition | Stages for groups A/B, group selector, Results, Fixtures and Schedule |
| Return routes | Player → squad; club information/transfers → Evening Results; competition → Evening Results |

Naturally empty transfer and history views and visibly disabled date/season
controls were retained. No transaction, tactical change or state change was
manufactured to obtain them. Postmatch navigation left the displayed game date
at Tuesday 14 October 2003, evening. That observation does not prove all hidden
state unchanged. Financial, player and match values remain only in private
screenshots; no screenshot or asset bytes are committed.

The UI mapper owns the screen census and route graph. This is a bounded first
batch, not exhaustive UI coverage. Other groups, scroll positions, filters,
competition bottom views, stage/view selectors and the club league-position
menu remain examples of visible unexplored routes. An expected back action is
distinguished from an exercised transition in the private index.
Its `observed_utc` field records when the already observed screenshot was
retained; it is not an exact input-event or screenshot-acquisition timestamp.

## Preservation and remaining work

The private archive contains all 784 baseline configuration files, the unchanged
input save, the exact reviewed tool, the raw paired capture, all 78 screenshots,
their action index and the identity manifests. It is extracted into a separate
directory and every retained file is rehashed. The sanitized receipt records
the archive hash, entry count and restore result. Generated temporary game files
and process RAM are excluded; this is not a restorable snapshot of the live
postmatch process. Previous archives are preserved. No off-host durability is
claimed.

Process 6268 is parked at Evening Results with no debugger attached. The pair
does not establish ownership lifetime, ordered effects, a completed action33
attempt, full-match reconstruction, same-process reload determinism or pinned
executable runtime equivalence. Any next capture extension requires its own
bounded design and review.

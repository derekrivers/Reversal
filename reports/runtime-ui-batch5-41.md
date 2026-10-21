# R41-A6: navigation entry blocked by game media prompt

The intended read-only navigation batch did not reach a loaded game. The
previous unsaved postmatch process was absent. A separately authorized fresh
launch reached the original game's Insert CD prompt while loading the verified
duplicate input save. One ordinary OK click left the prompt displayed; a fresh
observation confirmed it remained. No further game input followed.

This is a bounded entry-blocker receipt, not new coverage of the requested
loaded-game UI families. Six private JPEG images and four input-action edges
record the startup and media sequence. No raw images, save names, configuration
contents or private paths are published.

## Identity and observed route

| Item | Observation |
| --- | --- |
| Branch base | Merged first UI census, `def6b837947862112c5c4c701a3883ba41c732ca` |
| Prior process | PID 6268 absent; no game process or targetable game window found at preflight |
| New process | PID 13428; launched with disposable game directory explicitly set as working directory |
| GDI executable SHA-256 | `0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b` |
| Configuration manifest SHA-256 | `92aa3097961c972c8bd868d33766bcec59f0c9f799236a3b46c07044d13b1843` |
| Duplicate input save SHA-256 | `8698569fbd83d9952a9832a95aee17a943c32f18e29621e9396ed228107abbd3` |
| Before launch | All 784 baseline configuration files and the duplicate save matched |
| After attempt | 783 baseline files unchanged; `game.cfg` changed; duplicate save unchanged |

The observed sequence was startup splash → Setup Game (natural transition),
Restore Saved Game → file chooser, duplicate selection → selected file state,
OK → Insert CD modal, and one modal OK → modal remains. The splash-to-setup
transition is not counted as an input edge. The media prompt has OK and Quit;
Quit was not exercised. No successful load, loaded-game date, News hit test,
Back transition or security permission dialog was observed in this attempt.

Read-only system inspection found an already mounted virtual optical drive
with media loaded, a game-labelled UDF volume and readable installation files.
No mounting, installation, registry change, executable patch or check bypass
was attempted. The media is present but was not accepted in this launch;
the cause remains unproven.

The earlier A4 receipt describes a disc already mounted and a different,
informational CD Not Required modal followed by successful loading. That is
an observed comparison, not an explanation of this attempt's failure. The
same disk identities do not establish identical environment or in-memory state.

## Configuration divergence

The disposable `game.cfg` changed during the launch/load attempt without an
explicit settings edit. Both versions are retained privately. They are each
535 bytes, with 162 differing byte positions:

- Before: `8d35d1cef56360742ddb87995e4a81c3c1f56ed0f5420838e92f7315dc0a66d7`.
- After: `e3a0c7fbad42fe1f7713a65237610566ff452ed6ff3bdbeca079b4442e44f318`.

The before version was recovered read-only from the restore-tested A4 archive
and checked against its manifest. No configuration was restored into the live
copy during A6. The configuration change is not attributed as the cause of the
media prompt. Any later launch requires renewed configuration validation and
an explicit decision about this divergence.

## Unobserved requested routes

All requested loaded-game routes remain unobserved in A6: News/inbox and its
hit target/unread behavior; Training; Find; Nations & Clubs; manager navigation;
competition Seedings, Team Stats, Player Stats, History and Stage/View menus;
squad View/Filter/league/history; and source-specific bottom Back gaps in club
information, transfers, player detail/history, fixtures and competition views.

The lost postmatch process was not preserved as a RAM snapshot or postmatch
save. Its completed-match route is therefore an explicit unavailable branch,
not silently replaced by a new simulated match. No Continue Game, simulation,
transaction, save, tactical edit or debugger action occurred.

## Retention and checks

Each private capture has a stable ID, original encoded image hash and byte
count, decoded geometry, actual JPEG encoding, window/process context and
retention time. Each of the four actions names its before/after capture IDs
and observed result. Retention timestamps are not exact screenshot acquisition
or input-event timestamps. Hidden effects remain unknown.

The image hashes, JPEG dimensions and action references were checked. The
private archive preserves all six images, their index, preflight/launch/media/
postflight receipts, both configuration versions and the repository check log.
It is extracted into a separate private directory and every archived data file
is rehashed. Existing A4 archives retain the full original inputs; the A6
archive is an observation supplement, not a live-process recovery image.

Node 24 repository checks, selected public-file privacy scanning and diff
checks passed. The sanitized summary owns exact image/archive digests and
counts. The game is left at the observed Insert CD prompt without further
interaction. Independent review precedes merge; subsequent UI or media work
requires a new bounded assignment.

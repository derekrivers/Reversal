# R41-C: journey catalogue and UI evidence boundary

The coverage target is load → squad → player profile → tactics → fixture → match → result. This is a target, not a claim that these are direct transitions. R41-C has no game/process control. R41-A owns navigation and captures; R41-C inspects files offline.

The [R40 report](gdi-reference-40.md) records historical GDI load, match and result observations and [R37 readiness](reference-readiness-37.md) records a squad screen. No underlying historical screenshots are available in this worker's private inputs. Their layout, exact fields and actions therefore remain unverified here. The asset inventory establishes available backgrounds/fonts, not a screen/action contract.

| Stable state ID | Evidence status | Entry/navigation evidence | State/command boundary |
| --- | --- | --- | --- |
| `ui41.load.menu` | Historical R37 text only | Restore Saved Game was visibly available; direct R41 capture pending. | Save selection, failure modals and time effects need capture. |
| `ui41.squad` | Historical R37 text only | Loaded manager's Newcastle squad observed historically; exact route unknown. | No roster view model, sort/filter behavior or native field mapping admitted yet. |
| `ui41.player.profile` | Unobserved | Request: click one visible squad player and record back navigation. | Visible profile/roster identity relationship must be captured before integration. |
| `ui41.tactics` | Unobserved | Request: follow actual squad/navigation route without changing tactics. | Tactical reads/writes, unavailable controls and game effect unknown. |
| `ui41.fixture` | Historical R37 fixtures and R40 opponent context only | Fixture-to-match prerequisites unknown. | Time advancement and selection effects unknown. |
| `ui41.match` | Historical R40 report only | Same duplicated save loaded in two different runs; outcomes diverged. | Commentary/score observations do not establish reconstructed engine commands. |
| `ui41.result` | Historical R40 report only | Two different final scores recorded, no direct R41 capture yet. | Commit, continue, persistence and back behavior unknown. |

## Targeted capture requests

R41-A was asked first for a squad screenshot and the profile of one player selected from that squad, with capture IDs, executable/data/save identities, observed resolution, exact entry route and back behavior. A second request covers the remaining journey states and one useful disabled state when safe around interception work. Raw screenshots and personal manager names remain private. No aimless full-game tour is required.

The reusable component specification is provisional until those captures arrive:

| Component | Evidence required | Current scope |
| --- | --- | --- |
| Navigation rail/header/back | Actual labels, active states, back history and dimensions | Unknown |
| Squad table and player link | Visible columns, exact ordering, formatting and one click-to-profile identity | Unknown |
| Profile header/attributes | Visible labels, units, grouping, value formatting and unavailable values | Unknown |
| Tabs/buttons/dialogs | Enabled/disabled appearance, click/keyboard results, dismissal behavior | Unknown |
| Tactics/fixtures/commentary | Observed fields plus mutation/time/engine dependency | Unknown |

Typography, colors, spacing, table sorting/filtering, empty states, keyboard actions, dialogs and underlying native handlers are not inferred from resource filenames. A screenshot can establish visible layout and values; action effects require recorded navigation or execution evidence.

## React admission rule

A useful squad/profile integration requires a captured relationship between a roster row and a profile, stable local IDs, source capture IDs and exact visible strings. It will render captured read-only snapshots as a **reference-data viewer**, load original data privately, and keep unsupported game commands unavailable. Rendering must not advance state or consume RNG. No live native game binding, save parser, original database import, tactics mutation or match outcome is established by this work.

At this initial offline stage the data boundary is pending R41-A captures. The coordinator requested this bounded offline checkpoint so the runtime interception tool can receive independent review before game attachment. No squad/profile data has been manufactured and no React viewer has been admitted. Resume by inspecting the requested screenshots, transcribing visible values into a private typed snapshot, then building the bounded viewer from that captured boundary.

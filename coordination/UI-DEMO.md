# Synthetic UI demo coordination

## Baseline and boundary

The frontend starts from merged PRs #155, #160 and #161. The C4 census has 50 screenshot-backed states, 81 observed action edges, 111 uncaptured control routes and 12 unknown sections. Those numbers describe a bounded evidence frontier, not a percentage of the original application's UI. The prior React reference viewer implements only Squad → one Player Profile → Back. There is no engine command binding. This phase builds a navigable demonstration with fictional identities and values; original captures, installed assets and saves remain private.

One operator verified a live disposable GDI journey on 21 October 2026: Evening Fixtures → managed club Squad → Back to the same Fixtures. A separate 72-image private action index records safe Find, manager, Training, Last Match, league, History and settings journeys and return paths. The game session was left parked at Evening Fixtures. The earlier A6 media-prompt blocker in PR #161 remains true for that attempt; it does not describe the later successful session. The later disposable `game.cfg` differs from its baseline only in the process environment string, while the executable, duplicate save and other 783 files match.

## Screen and journey checklist

Status codes: **S** retained original screenshot; **N** native action and return observed for the specified route; **R** React implementation; **B** browser navigation checked. The C4 census holds stable `ui41.*` IDs and exact evidence references. Route status is source-specific.

| Area | Representative stable IDs and journey | Evidence | Demo status |
| --- | --- | --- | --- |
| Core | `ui41.load.menu`, `.restore`, `.restore.selected`, `ui41.fixture.evening`, `.evening_results` | S; restore/fixture actions N in A4 | UI-D1 R/B for synthetic entry and fixture/results navigation |
| Club/person | `ui41.squad.selection` → `ui41.player.profile` → Back to Squad; Squad Back to originating fixtures/results | S/N; prior reference viewer has narrow R/B | UI-D1 R/B for all fictional fixture clubs; N only for observed native route |
| Club modes | `ui41.club.info.*`, `.transfers.*`, `.fixtures`, `.next_match` | S; some N, 21 bottom-Back source gaps remain | UI-D2 R/B for tab modes and View menus; source-specific N only where observed |
| Player/tactics/training | `ui41.player.*`, `.history.*`, `ui41.tactics.overview`; newer private Training views | S; selected N | UI-D2 R/B for detail tabs, History View, Tactics, Training and Club History |
| Competition/match | `ui41.competition.*`, `ui41.match.*`, `ui41.result.fulltime` | S; selected N; passive match frames are sequences | UI-D3 R/B for cup and league views, last match and labelled static phase references; source-specific N only where observed |
| Global browsing | Newer private Find, manager/news, league/history/settings views | S/N for selected journeys | UI-D3 R/B for Find, News, manager and options shells; nested rail families remain unverified |

## Current milestone

**UI-D1 merged in PR #162** at `18e1e273`: fixed 800 × 600 game canvas; reusable rail, heading, tabs, tables, menu and footer; stable fictional club/player/competition fixtures; menu/restore, Evening Fixtures/Results, Squad/Profile navigation; context-preserving Back; visible unavailable operation controls; predictable start/reset. Browser checks cover outward and return journeys, populated squads for every fixture club, and dialog dismissal. Rendered Fixtures, Squad, Profile, Setup, and Results were visually compared with private evidence. The exact-head Codex review found a missing CI gate; a dedicated UI build/browser job was added, all CI checks passed and a fresh exact-head review completed without findings before merge.

**UI-D2 merged in PR #163** at `5c5a2f50`: club Finances & Info (General Info, Stats, Finances, Income, Expenditure), Transfers (seven View modes), Fixtures and Next Match; player Injuries & Bans, Contract, Transfer and History (Career, Achievements, Injuries, Bans); squad Selection/Attributes View; Tactics, Training and club History. All entities and displayed values are fictional. Browser checks cover source-preserving returns, lower-strip Cancel/Back paths and popup dismissal. Rendered key screens were visually compared with private native screenshots. Original-game verification exists for selected routes; source-specific native Bottom Back gaps remain explicit. Root and frontend checks, CI and final exact-head Codex review passed before merge.

**UI-D3 current**: cup Group A/B Stages, Results, Fixtures and Schedule; distinct fictional Second Division table/results/fixtures/schedule data; a completed Last Match with ratings/overview/stats/action zones/report; externally selectable static pre-kickoff/running/half-time/full-time references; Find tabs and query-preserving Player/Profile return; News, manager Stats/Job Information/Transfers/History/Board Confidence/Player & Staff Search, and options Manager Status/Selected Leagues/Game Settings shells. The demo routes preserve their source for Back, with game operations visibly unavailable. Browser checks cover the principal cup/league/match/Find/News/settings journeys at 800 × 600 with no external requests. Rendered competition, league, match, Find and News views were inspected. The original game's nested Nations & Clubs and Competitions submenus remain unverified, so their deeper destinations are not claimed. Run root checks, CI and exact-head Codex review before merge.

## Remaining uncertainty

The original application's whole-screen denominator is unknown. Native controls for two nested rail menu families could not be exercised with the available pointer actions; they are unverified. Operation controls, setup/new-game flows, many source-specific Back routes and selected subtabs also remain uncertain. The demo may provide sensible navigation for exploration, but its verification record must distinguish inferred behavior from native-observed behavior.

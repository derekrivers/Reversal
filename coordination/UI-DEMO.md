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
| Competition/match | `ui41.competition.*`, `ui41.match.*`, `ui41.result.fulltime` | S; selected N; passive match frames are sequences | UI-D3 pending |
| Global browsing | Newer private Find, manager/news, league/history/settings views | S/N for selected journeys | UI-D3 pending |

## Current milestone

**UI-D1 merged in PR #162** at `18e1e273`: fixed 800 × 600 game canvas; reusable rail, heading, tabs, tables, menu and footer; stable fictional club/player/competition fixtures; menu/restore, Evening Fixtures/Results, Squad/Profile navigation; context-preserving Back; visible unavailable operation controls; predictable start/reset. Browser checks cover outward and return journeys, populated squads for every fixture club, and dialog dismissal. Rendered Fixtures, Squad, Profile, Setup, and Results were visually compared with private evidence. The exact-head Codex review found a missing CI gate; a dedicated UI build/browser job was added, all CI checks passed and a fresh exact-head review completed without findings before merge.

**UI-D2 current**: club Finances & Info (General Info, Stats, Finances, Income, Expenditure), Transfers (seven View modes), Fixtures and Next Match; player Injuries & Bans, Contract, Transfer and History (Career, Achievements, Injuries, Bans); squad Selection/Attributes View; Tactics, Training and club History. All entities and displayed values are fictional. The browser check repeats complete routes including source-preserving Back from a linked player to the Stats and Squad Attributes views, lower-strip Cancel/Back paths, popup dismissal, and available tab changes. Rendered Club Info, Finances, Transfers, Next Match, player Contract/History, Training, Tactics and Club History were compared with private native screenshots. Original-game verification exists for Squad→Club Info, finance and transfer View selections, Club Fixtures→Next Match, Profile detail tabs and History View, Squad→Tactics→Cancel, Squad→Training/History→return; source-specific native Bottom Back gaps remain explicit. Run frontend build/browser checks, root `npm run check`, CI and exact-head Codex review before merge.

## Remaining uncertainty

The original application's whole-screen denominator is unknown. Native controls for two nested rail menu families could not be exercised with the available pointer actions; they are unverified. Operation controls, setup/new-game flows, many source-specific Back routes and selected subtabs also remain uncertain. The demo may provide sensible navigation for exploration, but its verification record must distinguish inferred behavior from native-observed behavior.

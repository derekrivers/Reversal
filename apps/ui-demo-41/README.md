# Reversal UI demo

This is an 800 × 600, browser-based navigation demo inspired by the observed Championship Manager 01/02 interface. Its club names, people, dates, results, ratings, and background image are fictional. It does not load a game save or change game state. The separate `apps/reference-viewer-41` remains a read-only viewer for private captures.

## Run

Use Node 24 or newer:

```sh
npm ci
npm run dev
```

Open the local URL printed by Vite. The toolbar can reset to the menu, start at Evening Fixtures or Results, or open a labelled static match reference with a phase selector. The menu journey is **Restore Saved Game → demo-season.sav → Ok**. The file name is a synthetic selection; there is no save read. In fixtures or results, choose a club, player, or Competition. Club tabs open Transfers, Next Match, Fixtures, and Finances & Info. Player tabs open Injuries & Bans, Contract, Transfer, and History. The squad's lower strip opens Tactics, Training, that club's Last Match and division table, and club History. The rail opens Find, News, manager and Game Options screens. Game Settings overlays the current screen. View menus reveal the observed subviews. The bottom **Back** button and browser Back restore the originating view, including Find text and page after visiting a player. Menus close by choosing a row, clicking outside, or pressing Escape. Unsupported game operations and unverified nested rail destinations show an unavailable dialog; Escape, Close, or clicking outside dismisses it.

## Verify

```sh
npm run build
npm run check:browser
```

The browser check saves screenshots in `test-results/` and covers restore/cancel, fixtures, all reachable club squads and player profiles, club and player tabs, transfer/finance/history View menus, training/tactics/club-history journeys, cup/league browsing, Last Match and static phase reference, Find/Profile return, News, manager and options routes, Back paths, reset, and unavailable operation dismissal. It verifies the 800 × 600 canvas and blocks external requests. This output is ignored by Git. Run the repository's root `npm run check` as well.

The source checklist and evidence boundary are in [`coordination/UI-DEMO.md`](../../coordination/UI-DEMO.md). Private native captures are intentionally outside this app and outside Git.

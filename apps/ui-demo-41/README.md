# Reversal UI demo

This is an 800 × 600, browser-based navigation demo inspired by the observed Championship Manager 01/02 interface. Its club names, people, dates, results, ratings, and background image are fictional. It does not load a game save or change game state. The separate `apps/reference-viewer-41` remains a read-only viewer for private captures.

## Run

Use Node 24 or newer:

```sh
npm ci
npm run dev
```

Open the local URL printed by Vite. The toolbar can reset to the menu or start directly at Evening Fixtures or Results. The menu journey is **Restore Saved Game → demo-season.sav → Ok**. The file name is a synthetic selection; there is no save read. In fixtures or results, choose a club, then a player. The bottom **Back** button and browser Back restore the previous view. Menus close by choosing a row, clicking outside, or pressing Escape. Operations and views outside this milestone show an unavailable dialog; Escape, Close, or clicking outside dismisses it.

## Verify

```sh
npm run build
npm run check:browser
```

The browser check saves screenshots in `test-results/` and covers restore/cancel, fixtures, all reachable club squads and player profiles, manager menu, results, Back paths, reset, and unavailable operation dismissal. This output is ignored by Git. Run the repository's root `npm run check` as well.

The source checklist and evidence boundary are in [`coordination/UI-DEMO.md`](../../coordination/UI-DEMO.md). Private native captures are intentionally outside this app and outside Git.

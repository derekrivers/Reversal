# Captured squad/profile reference viewer

This React app displays a locally loaded, read-only transcription of visible game
values. One captured roster row opens its captured profile; Back returns to the
same roster. It does not load saves, call the game, run simulation or advance time.
Unsupported controls are disabled. The included example is entirely synthetic.

Use Node.js 24+ from this directory:

```text
npm ci
npm run dev
```

Open the printed localhost address, then choose **Load local JSON** and select a
private snapshot matching `snapshot.ts`. Files are read in the browser, with no
upload, persistence or external asset requests. No captured data, original
backgrounds, game fonts or raw screenshots are bundled. The 800 × 600 layout uses
CSS and browser Arial; it is a reference layout, not a pixel-identical restoration.

The captured model uses strings exactly as displayed, including percentages,
ratings and currency text. Local player IDs connect the two captures; they are not
native database IDs. Only the visible roster slice and one profile's header,
31 attributes and status values were transcribed. Other profile panels and career
statistics are outside the bounded model. Sequential captures are not an atomic
game-state snapshot. The parser checks structural consistency and provenance
fields, not screenshot authenticity or native semantics.

The R41 private transcription is under the worker's ignored
`results/r41-squad-profile-A.json`; the public evidence receipt identifies its
hash and source capture hashes. It is not fetched or shipped with the application.
Use the synthetic example for a public/reproducible demonstration.

```text
npm run build
npm run check
npx playwright install chromium
npm run check:browser
npm run check:browser -- PRIVATE_SNAPSHOT_JSON PRIVATE_OUTPUT_DIRECTORY
```

Browser checks load the file through the actual picker, verify roster order and
formatting, open the supported profile, return without changing displayed values,
check disabled commands and malformed-file rejection, and require zero external
requests at 800 × 600. Rendered screenshots default to ignored `test-results/`.
Keep outputs from private captured data outside Git. Vite binds localhost only.
These checks validate display and navigation, not gameplay behavior.

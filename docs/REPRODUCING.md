# Reproduce the research

## Fast checks without the game

Use Node.js 24 or newer and run `npm run check`. No npm install is needed. Generated results go into ignored `results/`.

These checks compare against the retained original-instruction outputs and check evidence hashes/metadata. They do not emulate x86 in CI or reopen the native database.

## Regenerate the numerical oracles

Use Python 3.12 and Node.js 24. Install the exact emulation dependency into a local environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r reconstruction/requirements-emulation.txt
```

Place the pinned executable locally. `scripts/acquire_target.py downloads/cm0102.exe` can retrieve the commit-pinned specimen; all emulators reject an unexpected SHA-256. Create the `downloads/` parent first if needed. The acquisition script reads ZIP data and never runs the game.

Regenerate into **new directories**, rather than overwriting the committed oracles:

```sh
mkdir -p results
python3 scripts/emulate_random.py downloads/cm0102.exe results/new-random --synthetic-table
node reconstruction/check-random.ts results/new-random/x86-oracle.json \
  results/new-random/random-table.bin results/new-random-validation.json

python3 scripts/emulate_clock.py downloads/cm0102.exe results/new-clock
node reconstruction/check-clock.ts results/new-clock/clock-oracle.json \
  results/new-clock/clock-oracle.bin results/new-clock-validation.json

python3 scripts/emulate_event_rules.py downloads/cm0102.exe results/new-event-rules
node reconstruction/check-event-rules.ts results/new-event-rules results/new-event-rule-validation.json
```

Only admitted original code ranges execute, using synthetic state. Large-bound RNG handling, OS-time seeding, the full commentary loader/formatter, complete goal routines and full matches remain outside these tests.

## Native analysis

Install Ghidra 12.1.4 and JDK 21, set `GHIDRA_INSTALL_DIR` and `JAVA_HOME`, then:

```sh
bash scripts/run_ghidra.sh /absolute/path/to/cm0102.exe /new/analysis
```

For retained native annotations and restore testing, follow [DATABASE.md](DATABASE.md). Export scripts use exact virtual addresses, never file offsets.

REA is optional and separate from the checks:

```sh
npm ci --ignore-scripts --prefix tools/rea
bash scripts/run_rea.sh /absolute/path/to/cm0102.exe /new/rea-analysis
```

REA 6.7.0 resource inspection succeeded in the original environment. Its native bridge failed a process-inspection prerequisite there; direct Ghidra analysis was the documented fallback. Do not remove ownership checks to make that bridge run.

## Configuration mapping

Acquire `external/events_eng.cfg` from the Starter Kit commit recorded in `evidence/event-config-map.json` into an ignored local directory, then use `scripts/map_event_config.py SOURCE results/event-config-map.json`. The mapper requires its exact SHA-256 and indexes all 677 IDs. Its copied source file also stays in ignored local data. This community file has modified delays; the mapping does not authenticate pristine publisher commentary text.

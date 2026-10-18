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

python3 scripts/emulate_penalty_preparation.py downloads/cm0102.exe \
  evidence/random-validation/random-table.bin results/new-penalty-preparation
node reconstruction/check-penalty-preparation.ts \
  results/new-penalty-preparation/x86-penalty-preparation.json \
  evidence/random-validation/random-table.bin results/new-penalty-preparation-validation.json
```

Only admitted original code ranges execute, using synthetic state. Large-bound RNG handling, OS-time seeding, the full commentary loader/formatter, complete goal routines and full matches remain outside these tests.

The penalty-preparation harness joins three calculation slices with synthetic frames, sets sudden-death=1 to suppress commentary and uses the retained synthetic table. It does not execute the shared keeper/goal resolver or establish complete penalty-attempt equivalence.

Regenerate investigation 06's independent shot-resolution boundaries:

```sh
python3 scripts/emulate_penalty_resolution.py downloads/cm0102.exe \
  evidence/random-validation/random-table.bin results/new-penalty-resolution
node reconstruction/check-penalty-resolution.ts results/new-penalty-resolution \
  evidence/random-validation/random-table.bin results/new-penalty-resolution-validation.json
```

The 131,072 classification cases share one synthetic initial RNG state (at table wrap) and sweep both variant bytes and all raw quality words. The 4,096 keeper base cases use sampled ratings/states including wrap and zero bounds. The 4,056 gate cases use signed16 terms and match-state bytes 0/2/8/255. Endpoints are admitted only to stop before executing their instructions. No original instructions are replaced, no complete goal routine executes, and the slices are not composed into an attempt.

`CM0102ExportSelected.java OUTPUT_DIRECTORY HEX_ADDRESS[,HEX_ADDRESS...]` exports assembly and inferred pseudocode locally without modifying the native database. Keep its generated bulk output in an ignored `evidence/*-map/` directory.

Regenerate the keeper postlude and connected penalty response body:

```sh
python3 scripts/emulate_keeper_response.py downloads/cm0102.exe \
  evidence/random-validation/random-table.bin results/new-keeper-response
node reconstruction/check-keeper-response.ts results/new-keeper-response/oracle.json \
  evidence/random-validation/random-table.bin results/new-keeper-response-validation.json
```

This uses 2,048 inputs per entry mode repeated under control words 027fh/037fh (8,192 cases total). The same inputs/RNG states are paired across53/64-bit precision. Only the body/postlude, original RNG and original `__ftol` run; prelude state is synthetic and supplied. `CM0102FloatControlSites.java OUTPUT_JSON` records control-word instructions and bounded incoming-reference samples from the inferred listing; it is not a runtime precision trace.

## Native analysis

Install Ghidra 12.1.4 and JDK 21, set `GHIDRA_INSTALL_DIR` and `JAVA_HOME`, then:

```sh
bash scripts/run_ghidra.sh /absolute/path/to/cm0102.exe /new/analysis
```

For retained native annotations and restore testing, follow [DATABASE.md](DATABASE.md). Export scripts use exact virtual addresses, never file offsets.

`CM0102Inventory.java OUTPUT_DIRECTORY` exports the whole inferred function inventory and direct source-path references without decompiling all functions. Run it as a read-only post-script against the saved project. Then run `python3 scripts/build_code_atlas.py OUTPUT_DIRECTORY/program-inventory.json evidence/code-atlas` to refresh the public JSON Lines atlas, summary and workstream index. Structural function/byte coverage is not behavioral reconstruction progress.

REA is optional and separate from the checks:

```sh
npm ci --ignore-scripts --prefix tools/rea
bash scripts/run_rea.sh /absolute/path/to/cm0102.exe /new/rea-analysis
```

REA 6.7.0 resource inspection succeeded in the original environment. Its native bridge failed a process-inspection prerequisite there; direct Ghidra analysis was the documented fallback. Do not remove ownership checks to make that bridge run.

## Configuration mapping

Acquire `external/events_eng.cfg` from the Starter Kit commit recorded in `evidence/event-config-map.json` into an ignored local directory, then use `scripts/map_event_config.py SOURCE results/event-config-map.json`. The mapper requires its exact SHA-256 and indexes all 677 IDs. Its copied source file also stays in ignored local data. This community file has modified delays; the mapping does not authenticate pristine publisher commentary text.

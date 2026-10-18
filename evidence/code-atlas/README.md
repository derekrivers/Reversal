# Executable code atlas

This inventories the pinned 3.9.68 executable's Ghidra-inferred functions. It is a map of known code locations and direct relationships, **not recovery of the complete original source**.

| Structural observation | Count |
| --- | ---: |
| Internal functions | 9,241 |
| External function symbols | 143 |
| Embedded original source-path strings | 396 |
| Functions directly referencing a source path | 1,892 |
| Functions carrying working research names in this snapshot | 27 |
| Call instructions | 93,349 |
| Call instructions without a static target | 851 |
| Executable memory bytes | 5,660,672 |
| Executable bytes in inferred function bodies | 4,309,884 |

The function-body byte count measures structural analysis only. It must not be presented as a percentage of simulation or source code reconstructed. Most functions still have no established behavioral contract.

This atlas is the investigation-08 structural snapshot. Later investigations add small native annotation overlays through [`investigation-22-annotations.json`](../investigation-22-annotations.json); the checkpoint verifier applies those overlays while retaining the original atlas rows. A working name does not establish a complete function contract.

[`semantic-coverage.json`](semantic-coverage.json) indexes 120 distinct functions with reviewed static evidence from investigations 09–22: 111 local contracts and 9 partial boundaries. Each entry links to its report and compact instruction evidence and is marked either `contract-supported` for a local instruction-backed body contract or `boundary-mapped` for a partial path or dependency. The other 9,121 inventory entries have no entry in this overlay; this includes some earlier validated functions tracked separately. Separate structural registries characterize [3,873 short frame-dependent unwind bodies](../../reports/unwind-family-15.md), [192 conditional receiver-release wrappers](../../reports/delete-wrapper-family-17.md), [143 receiver-cleanup bodies](../../reports/cleanup-family-18.md), and [23 import jump thunks](../../reports/import-thunks-18.md). These registries do not overlap the 120-entry overlay; 4,890 inventory entries have no explicit entry in any of the five registries. These counts measure explicit review scopes, not game completion. [`validation-coverage.json`](validation-coverage.json) separately records original-instruction execution domains.

## Query the map

`functions.jsonl` has one record per internal function: address, working name, inferred body size/bounds, direct callees, source-path anchors and unresolved indirect call sites. `source-units.jsonl` has one record per embedded source path and its observed references. `summary.json` records input hash, counts, imported symbols and limitations.

```sh
python3 - <<'PY'
import json
from pathlib import Path
for line in Path('evidence/code-atlas/functions.jsonl').read_text().splitlines():
    row=json.loads(line)
    if 'match_eng.cpp' in row['direct_source_units']:
        print(row['entry'], row['name'], row['direct_callees'])
PY
```

## Most-referenced source units

| Source unit | Functions with direct reference |
| --- | ---: |
| `human_manager.cpp` | 50 |
| `Database.cpp` | 50 |
| `transfer_manager.cpp` | 42 |
| `tactics_screens.cpp` | 41 |
| `formation.cpp` | 33 |
| `scrman.cpp` | 32 |
| `comp_stats.CPP` | 30 |
| `player_search.cpp` | 29 |
| `news.cpp` | 29 |
| `tactics.cpp` | 27 |
| `staff_records.cpp` | 27 |
| `scout_manager.cpp` | 26 |
| `player_stats.cpp` | 26 |
| `friendly.cpp` | 24 |
| `fix_man.cpp` | 23 |
| `contract_manager.cpp` | 22 |
| `training_manager.cpp` | 20 |
| `club_records.cpp` | 20 |
| `Db_files.cpp` | 18 |
| `club_screens.cpp` | 17 |
| `Setup.cpp` | 16 |
| `league.cpp` | 15 |
| `record_utils.cpp` | 14 |
| `Cup.cpp` | 14 |
| `match_pl.cpp` | 13 |
| `match_eng.cpp` | 13 |
| `manager_manager.cpp` | 13 |
| `comp_screens.cpp` | 13 |
| `wc_europe_league.cpp` | 12 |
| `national_teams.cpp` | 12 |

These are investigation anchors. Assertions can be inlined and a function can reference multiple units; the counts do not establish exclusive ownership. Units with fewer assertions can contain much more unlabelled code.

## Reconstruction coverage

`validation-coverage.json` tracks tested whole functions and tested slices separately. A source-path anchor, a working name, a pseudocode export and a validated implementation are different evidence levels. There is no claim that all code has been understood, that indirect dispatch is complete or that original C++ classes have been recovered.

# Data and evidence inventory

## Inputs

| Input | Source and boundary |
| --- | --- |
| `cm0102.exe` | Starter Kit commit `69cdaedd611450f33fb73fa2f41f14f5039f3918`, `external/Exes.zip:cm0102.exe`; SHA-256 in README |
| Official updater mirror | cm0102-linux commit `befe35e79ccedeafc17dbf56054afcae9143ab27`, `patches/official-3.9.68.exe`; zero executable byte differences; historical publisher authentication unavailable |
| Commentary configuration | Starter Kit commit above, `external/events_eng.cfg`; SHA-256 `f8ed6307e3e295ae388bbaf49c5f4cf67337061a4353e5e1c9c4f3875e85fe88`; community text/delays |
| Community layout leads | CM0102Patcher commit `5481361dd32dad23d0e1d2ecddeeeaa0baaecf83`; corroborating leads, not original source declarations |

Full mirror and input metadata are in [provenance.json](../evidence/provenance.json) and [official-patch-comparison.json](../evidence/official-patch-comparison.json).

## What is tracked

- `scripts/`: acquisition, inspection, isolated emulation, native exports, annotations and database checkpoint verification.
- `reconstruction/`: narrow TypeScript implementations and oracle comparison programs; `requirements-emulation.txt` pins Unicorn 2.1.4.
- `evidence/*-findings.json`: findings at their original investigation scope. Investigation 04 supersedes earlier unresolved event/rule labels.
- `evidence/event-config-map.json`: factual config metadata and selected semantic links; the complete config text is acquired locally when needed.
- `evidence/analysis-index.json`: compact direct-call index from the four focused exports. The full graphs and bulk pseudocode remain in the private bundle.
- `evidence/code-atlas/`: executable-wide inferred function/source-path inventory, filename-based research workstreams and a scope registry separating whole-function checks from instruction slices. The semantic overlay records 134 reviewed static function bodies; separate registries characterize 3,873 unwind, 192 conditional receiver-release, 143 receiver-cleanup and 23 import jump-thunk bodies structurally. These are local bodies, not the complete original source or imported API implementations.
- `evidence/penalty-keeper-entry-validation/`: original-entry action33 oracle using an explicitly synthetic grid, tactical tables and runtime fields; includes ABI checks. Only a summary receipt/digest of the additional local original-grid comparison is public; the original grid data stays under ignored `results/`.
- `evidence/keeper-response-validation/`: original-instruction postlude and connected penalty-body outputs, RNG bounds/states under explicit 53/64-bit precision; synthetic frames and bounded float32 inputs. `float-control-sites.json` is a static instruction-site inventory, not a runtime state trace.
- `evidence/penalty-resolution-validation/`: independent original-instruction category, keeper base-draw and ratio-gate outputs with synthetic frames; the binary fixture contains category/draw-count bytes only, never code or original game memory.
- `evidence/penalty-preparation-validation/`: original calculation-slice outputs with commentary suppressed, synthetic frames and the public synthetic RNG table; no complete shot/goal execution.
- `evidence/*-annotations.*`: reproducible working names, comments and recovered field layouts.
- `evidence/*-validation/`: synthetic numerical inputs and outputs captured from admitted original x86 instruction ranges. No executable instructions are stored in the binary fixtures.
- `checkpoints/`: private archive digests, canonical project-file manifest, expected annotations and a successful native restore receipt.
- `reports/`: the authored investigation report, including the historical findings and their limitations.

## Public RNG fixture

The earlier private investigation loaded the executable's fixed table. For this import a new oracle was generated using the **same original instructions** with a synthetic 51,000-word table in emulator memory. It uses LCG seed `0x10203968`, state update `state*214013+2531011 mod 2^32`, and `(state>>16)&32767` as each table word. This fixture's table digest is recorded in `evidence/random-validation/x86-oracle.json`.

The original fixed-table results remain in the private report/checkpoint. The public synthetic-table experiment is separate evidence, not a replacement claim about original table contents or game-wide random behavior.

## Files kept outside Git

Local game inputs, updater payloads, full language data, commentary source text, Ghidra/JDK installations, native project files and generated backup ZIPs are ignored. The database backup's digest identifies the exact preserved archive; recreating the same annotations from a fresh import may produce different native database-file bytes.

The repository's MIT licence does not relicense original game binaries or external source data. Keep acquired inputs local and retain their source/hash metadata.

# Reversal

Evidence-led reverse engineering of **Championship Manager 01/02, SI patch 3.9.68**. The current priority is mapping function contracts and incrementally reconstructing bounded behavior in headless TypeScript with original x86 instruction validation. Game and UI implementation is deferred.

This repository contains investigations 01–25: an executable-wide code atlas, recovered layouts, narrow TypeScript reconstructions and numerical validation fixtures. Function recovery and bounded original-instruction validation are the current priorities; no complete match or playable browser game has been reproduced.

## Current findings

| Area | Recovered behavior |
| --- | --- |
| Match lifecycle | Setup, advance, result extraction and cleanup in observed callers |
| Match progression | Byte-sized work budget and status; period targets for 45/90/105/120 minutes |
| Tiebreaks | Phases 1–3: 35-yard shootout; phases 4–6: penalties |
| Commentary | 677 event definitions; 4,754 text variants in the pinned community config |
| Rules | Golden-goal stop predicate/latch and pitch-condition abandonment event |
| Executable atlas | 9,241 internal functions, 143 external symbols, 396 embedded source paths and 93,349 call instructions |
| Penalty preparation | Pressure-dependent error budget and shot-quality argument; 3,584 original-slice fixtures; goal/save resolution still open |
| Penalty resolution boundaries | Keeper base draws, signed16 shot categories and a scoring-branch gate; 139,224 independent original-slice cases; complete outcomes still open |
| Keeper response body | Connected penalty base+postlude; 8,192 cases at explicit 53/64-bit precision; entry prelude and full outcome still open |
| Penalty keeper entry | Action33 entry-to-return, including tactical/grid/variant guards; 9,056 public cases plus a local original-grid repeat |
| Native database | 150 named functions, 16 globals, 9 recovered structures and 93 fields; restored from an extracted archive |
| Investigation 09 | Static shot-resolution RNG ordering, keeper field producers, two database read wrappers and CRT x87 precision request; see the scoped reports |
| Investigation 10 | Static shot-helper refresh/effect dependencies, tactical plan boundaries and league aggregation/amount boundaries; see the scoped reports |
| Investigation 11 | Static other-slot shot-helper scan, transfer-manager construction and finance row/load boundaries; see the scoped reports |
| Investigation 12 | Static match-helper ABI, contract row allocation and match-screen selection/dispatch boundaries; see the scoped reports |
| Investigation 13 | Static match lookup/relocation, contract scalar/row lookup and training manager contracts; see the scoped reports |
| Investigation 14 | Static match coordinate/action dispatch, sixteen database read wrappers and five scouting storage accessors; see the scoped reports |
| Investigation 15 | Static other-slot match dispatch, four database field readers, four scouting lifecycle bodies and a separate structural classification of 3,873 unwind bodies; see the scoped reports |
| Investigation 16 | Local match slot/action dispatch, two database stream helpers, two scouting copy bodies and three common unwind targets; eight exact-old native names accepted |
| Investigation 17 | Three match action dispatch bodies, three low-level database helpers and three cleanup bodies mapped; a 21-byte reachable switch arm was restored to its Ghidra function body |
| Investigation 18 | Four match, three database and three cleanup helper bodies mapped; ten reviewed names accepted into checkpoint 18 |
| Investigation 19 | Two match action, three descriptor/allocator and five cleanup/runtime bodies mapped; eight reviewed names accepted into checkpoint 19 |
| Investigation 21 | Three small match helpers mapped and validated against 65,840 original-instruction cases; two larger match state bodies mapped statically; five reviewed names accepted into checkpoint 21 |
| Investigation 22 | Seven complete local bodies mapped under scalar queries, selected-slot scan and runtime callees; one scalar query validated against 274 original-instruction executions, six others remain static; six reviewed names accepted into checkpoint 22 |
| Investigation 23 | Four complete local bodies mapped under status classification, exit callbacks and selector mode-5 lookup; two bounded TypeScript paths validated against 43 and 288 original-instruction executions; four reviewed names accepted into checkpoint 23 |
| Investigation 24 | Three new local bodies mapped for date difference and path formatting, plus the prior status-refresh partial upgraded to a full static body contract; two bounded TypeScript paths validated against 13 and 95 original-entry synthetic cases; three reviewed names accepted into checkpoint 24 |
| Investigation 25 | Three new local bodies mapped for signed status lookup and locale-aware copy, plus two prior partials upgraded to complete local static contracts; bounded TypeScript paths validated against 331, 144 and 180 original-entry synthetic cases; three reviewed names accepted into checkpoint 25 |
| Structural families | Separate registries classify 3,873 unwind bodies, 192 conditional receiver-release wrappers, 143 receiver-cleanup bodies and 23 import jump thunks; these are structural local-body classifications |

Start with [investigation 08](reports/investigation-08.md), [the current research queue](coordination/QUEUE.md), [the executable code atlas](evidence/code-atlas/README.md), [port architecture](docs/ARCHITECTURE.md) and [the research roadmap](docs/ROADMAP.md). The [historical HTML report](reports/investigation-04.html) includes investigations 01–04; download it to view its formatting.

## Run the checks

With **Node.js 24+**:

```sh
npm run check
```

There are no npm dependencies for these checks. They compare TypeScript outputs with retained oracles generated by the actual x86 instructions:

| Check | Comparisons |
| --- | ---: |
| CRT generator | 1,024 steps |
| Small-bound random helper | 2,570 calls, including state and table wrap |
| Commentary clock conversion | 196,608 outputs |
| Event priority lookup | 131,072 outputs |
| Post-goal stop predicate | 262,144 outputs |
| Penalty preparation | 3,584 calculation cases and RNG-state comparisons |
| Penalty resolution boundaries | 131,072 categories, 4,096 keeper base cases and 4,056 ratio gates |
| Keeper response adjustment/body | 8,192 cases with RNG-bound/state comparisons at 53/64-bit precision |
| Penalty keeper entry | 9,056 public entry-to-return cases; another 9,056 local original-grid cases |
| Descriptor-to-handle helper | 344 synthetic memory cases, 4,329 original x86 instruction steps and 11 negative checks |
| Match microhelpers | 65,840 synthetic whole-function cases, including every byte-add input pair; 18 negative probes |
| Indexed signed-word query | 274 synthetic whole-function cases, 2,312 original x86 instruction steps; mapped-memory domain |
| Indexed status count guard | 43 synthetic no-callee entry-to-return cases, 688 original x86 instruction steps; other paths static |
| Mode-5 record lookup | 288 synthetic no-callee entry-to-return cases, 16,200 original x86 instruction steps; diagnostics static |
| Status-refresh guard | 13 preinitialized call-free original-entry cases, 568 x86 steps; update and callee paths remain static |
| Date-pair difference | 95 preinitialized nonrecursive original-entry cases, 5,100 x86 steps; recursive and initialization paths remain static |
| Signed status lookup | 331 original-entry synthetic cases across three functions; refresh and diagnostics paths remain static |
| Slot condition effect | 144 no-callee severe-path original-entry cases, 8,568 x86 steps; remaining paths and transitive callees remain static |
| Locale-aware copy helper | 180 nonzero-locale original-entry cases, 11,619 x86 steps; mode-zero delegated `_strncpy` remains static |

The public RNG table is **synthetic**, generated deterministically and supplied to the original instructions during emulation. The earlier fixed-game-table experiment remains documented in the private checkpoint. Clock and event-rule fixtures also use synthetic state. Passing these checks establishes only the tested primitives' behavior, not full-match equivalence.

The same checks run in [GitHub Actions](.github/workflows/research-checks.yml). CI verifies retained results; regenerating the x86 oracles requires the pinned executable locally. See [reproduction instructions](docs/REPRODUCING.md).

## Preserve and recover the database

The native Ghidra database and full research bundle are preserved separately as private artifacts. The database contains imported game bytes, so this public repository tracks its **manifest, restore receipt, expected annotations and rebuild scripts** rather than the native project.

- [Current checkpoint metadata](checkpoints/2026-10-18-investigation-25/) and [latest checkpoint pointer](checkpoints/latest.json)
- [Database recovery instructions](docs/DATABASE.md)
- [Data and evidence inventory](docs/PROVENANCE.md)

The saved database was opened from an extracted archive in **Ghidra 12.1.4 / JDK 21**, read-only and without reanalysis. Verification checked 150 named functions, 16 labels, 9 partial structures with 93 fields, 227 original code samples, 76 code comments and all 10 project-file hashes. The CI metadata check does not repeat this native reopen test.

## Tooling and specimen

The target is a 7,192,576-byte PE32 x86 image with SHA-256:

```text
0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86
```

It was byte-identical to the executable inside the retained archived official SI 3.9.68 updater mirror. This proves equivalence to that mirror; publisher-issued authentication was unavailable.

[REA](https://github.com/morluto/rea) 6.7.0 successfully inspected PE resources. Its native Ghidra bridge hit a hosted process-inspection prerequisite, so native analysis used Ghidra directly. The failed check was retained, not removed. The optional [REA tool lockfile](tools/rea/) pins `rea-agents` 6.7.0 independently from the dependency-free TypeScript checks.

The existing MIT licence applies to our research code. Original game files and bulk decompiled source are not redistributed here. Commentary labels are mapped from a commit-pinned community configuration with modified delays; they are not authenticated as pristine SI text or timing.

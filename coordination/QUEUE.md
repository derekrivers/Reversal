# Research queue — investigation 09

Specimen: `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses below are virtual addresses. Baseline is main commit `1f1758f225a1802d3f73f925fd3d6c93117f1fa6` and checkpoint `2026-10-18-investigation-08`. The native database has one writer: the coordinator. All names and subsystem assignments remain provisional.

| ID | Owner / branch | Owned functions and question | Dependencies and exclusions | Deliverable and acceptance |
| --- | --- | --- | --- | --- |
| R09-A | Shot resolver researcher / `codex/shot-resolver-09` | `00702050`: bound the action `0x33` path from keeper output through quality, category, gate, RNG calls and score/state writes. | Read `00700420`, `00700bd0`, `0090cfc0` as dependencies; B owns keeper field producers. Avoid claiming full shot equivalence from isolated slices. | Address-specific control/data-flow findings, ordered RNG and unresolved branches, evidence locations and proposed annotations. Behavioral code only with original-instruction oracle. Own `evidence/shot-resolver-09-*`, `reports/shot-resolver-09.md` and task-specific scripts. |
| R09-B | Keeper field researcher / `codex/keeper-producers-09` | Producer contracts for roster slot `+0x168/+0x16a`, `+0xd1`, `+0x0f`, `+0x3b`, match `+0x8eaa`; inspect `006ce110` and callers of `00700420`. | A owns `00702050` action path. Cross-boundary uses are dependency leads, not ownership claims. | For each field: candidate writers, source width, lifecycle/preconditions, and evidence or explicit unknown; proposed annotation changes with confidence. Own `evidence/keeper-producers-09-*` and `reports/keeper-producers-09.md`. |
| R09-C | Database researcher / `codex/database-boundary-09` | `0054d5e0` and `0054d740` (`Db_files.cpp` anchors): establish a bounded file/record loading or saving contract and data ownership. | Do not infer a complete save format or claim adjacent `Db_files.cpp` functions. RNG persistence only as a documented lead if evidence appears. | Assembly-backed widths/calls/state effects, caller/callee boundary and evidence paths, or a clear unresolved report. Own `evidence/database-boundary-09-*` and `reports/database-boundary-09.md`. |
| R09-D | Coordinator / `codex/coordination-09` | Verify migration and native checkpoint; investigate x87 control state at match entry using `0094a698`/`0094f5b0`/`0094f57b`/`0094f658` and match entry leads. Integrate accepted annotations and checkpoint. | Avoid simultaneous writes to canonical project. Only coordinator updates this queue, atlas registries, `checkpoints/latest.json` and shared status. | Restore/hash receipts, scoped x87 findings, review/CI record, serial native checkpoint, resume state. |

States: queued, in progress, reviewable, reviewed, merged, or blocked with a concrete dependency. Mapping may finish without TypeScript; it still needs reproducible source evidence and explicit uncertainty. Worker branches must contain no original executable, native project, updater, original grid, bulk decompilation or private traces. Reviewers must be independent of authors; coordinator alone merges and writes the native database.

## Initial state (historical)

- R09-A/B/C: in progress, independent worktrees at the pinned main commit.
- R09-D: in progress. Migration receipt reports 666 restored files and nine native project files. The restored executable and bundled database archive match the checkpoint hashes; `npm run check` passes on Node 22.20.0. Native reopen verification is pending installation of Ghidra 12.1.4 and JDK 21.
- The separately supplied `cm0102-ghidra-database.zip` is an older checkpoint (22 names); the migration bundle's hash-pinned checkpoint 08 archive is authoritative.
- No PR or merge has been made in this investigation yet.

## Review and checkpoint state

- R09-A: reviewed; independent static shot-resolver mapping on `codex/shot-resolver-09`, PR #8. The review found no actionable issue. Outcome equivalence remains open.
- R09-B: reviewed; keeper producer mapping on `codex/keeper-producers-09`, PR #7. The review found no actionable issue. Runtime producer contracts remain open.
- R09-C: reviewed; database read-wrapper mapping on `codex/database-boundary-09`, PR #6. The review found no actionable issue. Save schema remains open.
- R09-D: native Ghidra 12.1.4/JDK 21 reopen passed on checkpoint 08. The reviewed proposals and startup x87 comments were applied to checkpoint 09, then its independent extracted archive passed read-only verification: 31 function names/comments, 16 labels, 9 structures, 93 fields, 81 original code signatures, 49 code comments and 10 project-file hashes. The prior native archive and project were preserved separately. The x87 match-entry control word is still unmeasured.
- Merge sequence: publish and independently review the checkpoint/coordination PR, require its CI checks, then merge the three disjoint research PRs subject to their checks and repository protection rules. Update each state after the merge result is known.

# Preserve and recover the native analysis database

The native database is the ongoing working checkpoint. Keep `cm0102.gpr` beside the complete `cm0102.rep` directory. Open the existing `cm0102.exe` program in that project; importing the executable into a new project does not recover the annotations.

The [current checkpoint](../checkpoints/2026-10-19-investigation-26/) records:

- 153 named functions; 16 global labels.
- 9 recovered structures with 93 named fields under `/CM0102/Recovered`.
- 230 original code samples and 76 code comments.
- 10 canonical project files, each with SHA-256 and byte length.

`checkpoints/latest.json` identifies the current dated checkpoint. Earlier dated metadata and separately saved archives remain historical. This checkpoint records the canonical files retained by Ghidra after saving the current project.

## Restore the saved archive

1. Obtain the separately preserved `cm0102-ghidra-database.zip`.
2. Compare its SHA-256 with `artifacts.json` in the checkpoint directory.
3. Extract it completely into a writable directory.
4. Open `ghidra-project/cm0102.gpr` with Ghidra 12.1.4 / JDK 21.

The archive contains its own manifest, expected annotations, restore receipt and `CM0102VerifyCheckpoint.java`. Its `RESTORE.txt` shows a read-only headless verification command. This is the preferred continuation path.

## Rebuild annotations when the saved archive is unavailable

Use a **new isolated output directory**, the hash-pinned executable and Ghidra 12.1.4/JDK 21. Run `scripts/run_ghidra.sh` to import and analyze, then apply historical scripts 1–24 in order with `analyzeHeadless -process cm0102.exe -noanalysis`. Step 25 applies only to the preserved checkpoint-25 project, because its exact-old preflight requires that project's prior annotations:

1. `CM0102AnnotateMatch.java /new/match-annotations.txt`
2. `CM0102AnnotateProgression.java /new/progression-annotations.json`
3. `CM0102AnnotateEvents.java /new/event-annotations.json`
4. `CM0102AnnotatePenalty.java /new/penalty-annotations.json`
5. `CM0102AnnotateShotResolution.java /new/shot-resolution-annotations.json`
6. `CM0102AnnotateKeeperResponse.java /new/keeper-response-annotations.json`
7. `CM0102AnnotateKeeperEntry.java /new/keeper-entry-annotations.json`
8. `CM0102AnnotateInvestigation09.java /new/investigation-09-annotations.json /path/shot-resolver-09-annotations.json /path/keeper-producers-09-annotations.json /path/database-boundary-09-annotations.json`
9. `CM0102AnnotateInvestigation10.java /new/investigation-10-annotations.json /path/shot-dependencies-10-annotations.json /path/tactics-boundary-10-annotations.json /path/league-boundary-10-annotations.json`
10. `CM0102AnnotateInvestigation11.java /new/investigation-11-annotations.json /path/shot-helper-11-annotations.json /path/transfer-boundary-11-annotations.json /path/finance-boundary-11-annotations.json`
11. `CM0102AnnotateInvestigation12.java /new/investigation-12-annotations.json /path/match-helpers-12-annotations.json /path/contract-boundary-12-annotations.json /path/match-ui-12-annotations.json`
12. `CM0102AnnotateInvestigation13.java /new/investigation-13-annotations.json /path/match-dependencies-13-annotations.json /path/contract-dependencies-13-annotations.json /path/training-boundary-13-annotations.json`
13. `CM0102AnnotateInvestigation14.java /new/investigation-14-annotations.json /path/match-dispatch-14-annotations.json /path/db-wrapper-family-14-annotations.json /path/scouting-boundary-14-annotations.json`
14. `CM0102AnnotateInvestigation15.java /new/investigation-15-annotations.json /path/match-dependency-15-findings.json /path/db-field-readers-15-annotations.json /path/scouting-lifecycle-15-annotations.json`
15. `CM0102AnnotateInvestigation16.java /new/investigation-16-annotations.json /path/match-core-16-findings.json /path/db-stream-16-annotations.json /path/scout-copy-16-annotations.json /path/unwind-targets-16-annotations.json`
16. `CM0102CorrectMatchBody17.java /new/match-dispatch-17-body-correction.json` to include the original 21-byte switch arm in function `006f09f0`.
17. `CM0102AnnotateInvestigation17.java /new/investigation-17-annotations.json /path/match-dispatch-17-annotations.json /path/db-lower-17-annotations.json /path/scout-cleanup-17-annotations.json`
18. `CM0102AnnotateInvestigation18.java /new/investigation-18-annotations.json /path/match-helpers-18-annotations.json /path/db-helpers-18-annotations.json /path/cleanup-helpers-18-annotations.json`
19. `CM0102AnnotateInvestigation19.java /new/investigation-19-annotations.json /path/match-action-19-annotations.json /path/db-runtime-19-annotations.json /path/cleanup-runtime-19-annotations.json`
20. `CM0102AnnotateInvestigation21.java /new/investigation-21-annotations.json /path/match-microhelpers-21-annotations-proposal.json /path/match-state-21-annotations.json`
21. `CM0102AnnotateInvestigation22.java /new/investigation-22-annotations.json /path/match-scalar-22-annotations-proposal.json /path/match-selection-22-annotations.json /path/match-runtime-22-annotations-proposal.json`
22. `CM0102AnnotateInvestigation23.java /new/investigation-23-annotations.json /path/match-status-23-annotations-proposal.json /path/exit-runtime-23-annotations-proposal.json /path/selection-probe-23-annotations-proposal.json`
23. `CM0102AnnotateInvestigation24.java /new/investigation-24-annotations.json /path/date-difference-24-annotations-proposal.json /path/path-format-24-annotations-proposal.json`
24. `CM0102AnnotateInvestigation25.java /new/investigation-25-annotations.json /path/status-lookup-25-annotations-proposal.json /path/copy-helper-25-annotations-proposal.json`
25. `CM0102AnnotateInvestigation26.java /new/investigation-26-annotations.json /path/investigation-26-exact-old-preflight.json /path/match-dependencies-26-annotations-proposal.json /path/league-comparator-26-annotations.json`

The investigation-26 script requires the preserved checkpoint-25 project and private exact-old preflight/proposal files with pinned hashes; it intentionally refuses an unrelated fresh import. Use the saved checkpoint-26 archive for direct recovery.

Use `-scriptPath /absolute/path/to/Reversal/scripts` and preserve the original project. Then reopen the rebuilt project read-only and execute:

```sh
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /new/project cm0102 \
  -process cm0102.exe -noanalysis -readOnly \
  -scriptPath /absolute/path/to/Reversal/scripts \
  -postScript CM0102VerifyCheckpoint.java \
  /absolute/path/to/Reversal/checkpoints/2026-10-19-investigation-26/expected-database.json \
  /new/rebuilt-verification.json
```

This checks the expected semantic annotations and code bytes. It does not promise byte-identical native database files: fresh analysis, timestamps and database serialization can differ. The saved original manifest's file hashes apply to that original checkpoint only.

## Make the next checkpoint

Close the live project before copying. With a local project at `ghidra-project/` and the pinned specimen at `downloads/cm0102.exe`, `scripts/checkpoint_database.py stage` creates an archive plus an independent `restore-test/` extraction. Run the bundled Java verifier against that extracted project and write `evidence/database-restore-verification.json`; then run `scripts/checkpoint_database.py finalize`.

The script excludes locks, presave files and temporary files while retaining canonical project files. It verifies the restored annotations and hashes before finalizing. Preserve the resulting native archive separately, and commit the new manifest, receipt and annotation scripts together. Existing checkpoint metadata belongs to its dated checkpoint; do not silently overwrite it with another database.

When later annotation receipts replace a comment at the same address, the checkpoint builder retains the latest text for verification. Earlier dated receipts are historical, not simultaneous comments in the current listing.

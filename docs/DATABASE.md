# Preserve and recover the native analysis database

The native database is the ongoing working checkpoint. Keep `cm0102.gpr` beside the complete `cm0102.rep` directory. Open the existing `cm0102.exe` program in that project; importing the executable into a new project does not recover the annotations.

The [current checkpoint](../checkpoints/2026-10-18-investigation-05/) records:

- 22 named functions and comments; 10 global labels.
- 8 recovered structures with 82 named fields under `/CM0102/Recovered`.
- 32 original code samples and 9 code comments.
- 10 canonical project files, each with SHA-256 and byte length.

`checkpoints/latest.json` identifies the current dated checkpoint. Investigation 04 metadata remains historical. The investigation 05 archive retains the database's previous canonical version alongside the latest version; both are hashed.

## Restore the saved archive

1. Obtain the separately preserved `cm0102-ghidra-database.zip`.
2. Compare its SHA-256 with `artifacts.json` in the checkpoint directory.
3. Extract it completely into a writable directory.
4. Open `ghidra-project/cm0102.gpr` with Ghidra 12.1.4 / JDK 21.

The archive contains its own manifest, expected annotations, restore receipt and `CM0102VerifyCheckpoint.java`. Its `RESTORE.txt` shows a read-only headless verification command. This is the preferred continuation path.

## Rebuild annotations when the saved archive is unavailable

Use a **new isolated output directory**, the hash-pinned executable and Ghidra 12.1.4/JDK 21. Run `scripts/run_ghidra.sh` to import and analyze, then apply these scripts in order with `analyzeHeadless -process cm0102.exe -noanalysis`:

1. `CM0102AnnotateMatch.java /new/match-annotations.txt`
2. `CM0102AnnotateProgression.java /new/progression-annotations.json`
3. `CM0102AnnotateEvents.java /new/event-annotations.json`
4. `CM0102AnnotatePenalty.java /new/penalty-annotations.json`

Use `-scriptPath /absolute/path/to/Reversal/scripts` and preserve the original project. Then reopen the rebuilt project read-only and execute:

```sh
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /new/project cm0102 \
  -process cm0102.exe -noanalysis -readOnly \
  -scriptPath /absolute/path/to/Reversal/scripts \
  -postScript CM0102VerifyCheckpoint.java \
  /absolute/path/to/Reversal/checkpoints/2026-10-18-investigation-05/expected-database.json \
  /new/rebuilt-verification.json
```

This checks the expected semantic annotations and code bytes. It does not promise byte-identical native database files: fresh analysis, timestamps and database serialization can differ. The saved original manifest's file hashes apply to that original checkpoint only.

## Make the next checkpoint

Close the live project before copying. With a local project at `ghidra-project/` and the pinned specimen at `downloads/cm0102.exe`, `scripts/checkpoint_database.py stage` creates an archive plus an independent `restore-test/` extraction. Run the bundled Java verifier against that extracted project and write `evidence/database-restore-verification.json`; then run `scripts/checkpoint_database.py finalize`.

The script excludes locks, presave files and temporary files while retaining canonical project files. It verifies the restored annotations and hashes before finalizing. Preserve the resulting native archive separately, and commit the new manifest, receipt and annotation scripts together. Existing checkpoint metadata belongs to its dated checkpoint; do not silently overwrite it with another database.

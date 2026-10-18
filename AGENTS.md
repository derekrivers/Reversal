# Working on Reversal

- Read README.md, docs/ROADMAP.md and docs/PROVENANCE.md before extending the research.
- Keep every binary claim tied to the executable SHA-256 and distinguish file offsets from virtual addresses.
- Treat function names as research labels and structures as partial. Check calling conventions and widths in assembly before changing a prototype.
- Preserve the existing native database. Rebuild into a separate project; do not replace the only checkpoint with a fresh import.
- Keep original executable files, native projects, updater archives, downloaded dependencies and bulk decompiled source outside Git. Follow .gitignore and the checkpoint metadata.
- Commit reconstruction code, oracle provenance, matching findings and annotation scripts together. Clearly distinguish synthetic fixtures from original game data.
- Run `npm run check`. Regenerate an oracle from original instructions when changing the behavior of its reconstructed primitive; changing expected values to make a test pass is insufficient evidence.
- CI checks retained numerical fixtures and checkpoint metadata. It does not reopen Ghidra or reproduce a full match.
- Do not describe a full match, goal formula or playable game as recovered without the relevant evidence.

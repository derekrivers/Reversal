# The executable's Ghidra unwind-entry population

The investigation-08 structural atlas contains **3,873** entries named `Unwind@...` by Ghidra, from `00953480` through `009660d0`. They are 41.9% of its 9,241 inferred internal functions. Their complete pinned PE bodies contain 12,563 decoded instructions and fall into **20 instruction-shape templates**; 1,501 have a direct call and 2,372 have a tail jump. Each has one direct target and no unresolved indirect call site in the atlas. This is a distinct population of short frame-dependent stubs, not 3,873 independently recovered game algorithms.

Specimen: 7,192,576-byte PE32 SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. `scripts/extract_unwind_family_15.py` parses PE sections, checks that hash, reads the original investigation-08 function inventory, and decodes every `Unwind@` body with Capstone 5.0.7. All 3,873 bodies decode continuously to their Ghidra-inferred body ends, with no gaps. Each direct call/jump target agrees with the atlas. The 20 templates preserve operand kinds, registers, memory widths/base registers and body lengths; per-entry data preserve the EBP displacements, literals, control targets and SHA-256 of the original body. The registry contains no original instruction bytes or bulk assembly listing.

## What the templates do locally

| Template IDs | Entries | Local instruction shape and dependency |
| --- | ---: | --- |
| `U01`, `U06` | 1,462 | Load a dword from an enclosing EBP frame slot into EAX; push it, call one direct target, pop ECX and return. |
| `U02`, `U03` | 1,690 | Form an EBP-relative address in ECX and tail-jump to one direct target. |
| `U04`, `U05` | 468 | Load a dword from an EBP frame slot into ECX and tail-jump. |
| `U07`–`U09` | 212 | Load a dword from an EBP frame slot into ECX, add a literal offset, then tail-jump. |
| `U10`–`U14`, `U16`–`U20` | 39 | Push callback/count/stride-like literals and a frame-derived address, call one direct target, then return. The exact helper semantics and ownership remain unresolved. |
| `U15` | 2 | Test one frame flag; one branch tail-jumps with an EBP-derived address, while the other returns. |

The first nine templates cover **3,832** entries. The remaining 41 use the two less common shapes above. Across the population there are 24 distinct direct targets; the most frequent are `005a53c0` (1,711 entries), `00944c94` (1,462) and `00682300` (237). The report does not assign semantic destructor or allocator names to these targets solely from their call frequency. A sample read-only Ghidra export at `0095348b` shows a data reference from `00971ac4` and decompiles with an ambient EBP value. This supports the cleanup-stub interpretation, but parent-function associations and runtime invocation conditions are not established by this census.

The generated [summary](../evidence/unwind-family-15-summary.json) gives each normalized template and count. The [entry registry](../evidence/unwind-family-15-rows.jsonl) gives the exact address, body hash, target, displacements and literals for all 3,873 entries. This is a **mechanical local-body characterization**, separate from [`semantic-coverage.json`](../evidence/code-atlas/semantic-coverage.json), which currently tracks 64 reviewed game-related static contracts and partial boundaries. Counting these unwind entries as 3,873 complete game behaviors would hide their dependence on an enclosing EBP frame and opaque callees. After separating this population, 5,368 structurally inferred non-unwind functions remain; 64 are in that semantic overlay, leaving 5,304 without an entry there (some earlier validated functions are tracked separately).

## Limits and reproduction

The atlas is Ghidra-inferred. This census verifies its named unwind-entry bodies against original bytes but does not independently discover every possible function start or prove the compiler's exception-table semantics. It does not execute these stubs, resolve target effects, identify parent frames, or establish saved-game/gameplay behavior. The direct targets contain no known direct call to the mapped RNG helper, but transitive behavior remains open.

```powershell
& <Capstone-5.0.7-Python> scripts/extract_unwind_family_15.py --binary <private-cm0102.exe> --atlas evidence/code-atlas/functions.jsonl --summary evidence/unwind-family-15-summary.json --rows evidence/unwind-family-15-rows.jsonl
```

The script asserts the pinned specimen, 9,241 atlas rows, 3,873 `Unwind@` rows, exactly 20 operand-aware templates, continuous complete body decoding, one atlas-matching direct target per body and no unresolved indirect sites. Two independent writes matched byte-for-byte. The summary SHA-256 is `1d9322550626bf5db1348c1e15a8b02954778a56502dd0ffa2ae2b2b32ccc8a1`; the registry SHA-256 is `63db9931a00effc51608a94e652dae8fac790a029bb7d840f9aaa906e00ca520`. The output is deterministic UTF-8/LF. The specimen, Ghidra project and generated bulk pseudocode stay private.

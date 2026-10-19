# R32-A: guarded opponent scan and the next resolver calls

The [bounded TypeScript continuation](../reconstruction/action33-opponent-32.ts) extends merged R31-A's original-produced `0070210b` boundary through `006d59b0`, its side getter `00714d30`, the admitted paths of `007160f0`, and flag getter `005b57c0`. With tactical bit `04` clear, the caller reaches **before `00702193 -> 00945640`**, with its x87 conversion input still on the stack. With bit `04` set, execution reaches **before `0071614b -> 005b58e0`**, with the original argument and receiver prepared. Neither call is replaced or executed by this unit.

These are original x86 instructions executed on explicitly synthetic mapped state. No original-game run was observed. R30-C's later `007022fd` interior checkpoint remains separate: the new TypeScript prefix has not joined it, and no resolver return, completed attempt, goal/save or match result is claimed.

## Inputs and integrity

The baseline is merged R31-A PR #116. The pinned PE32 x86 SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All instruction addresses below are virtual; the oracle records file offsets separately. Read-only native exports are the accepted `exports-30-action33-prefix` manifest `5089d7a53a599ffaeada705cc7fb02ae62ab76070e3c886ac57cd99080019a4f` and `exports-09/00702050.asm` hash `40afb06c0e55a22091d0aff2bcca1521feadc9fae0bb87f9416ab4a72472f8cf`.

The [generator](../scripts/emulate_action33_opponent_32.py) verifies the PE, the manifest, every used dependency ASM/C export and all **177 selected instruction operands**, including the two unexecuted stop CALLs. It checks a 181-edge static graph over the admitted ranges and their explicit stop sites. The complete 93-byte `006d59b0`, four-byte `00714d30` and 15-byte `005b57c0` local bodies are compared; only the executed prefix/guard-return parts of `007160f0` are admitted. The retained executions reach 174 instruction starts; `006d59f9`'s count increment remains unreachable in these guard-clear cases.

R30-A's synthetic setup and R31-A's generator source are pinned. The [Node checker](../reconstruction/check-action33-opponent-32.ts) independently reconstructs the shared initial memory, runs the actual accepted R31-A TypeScript prefix, and checks the resulting state and full region digests at `0070210b`. For all 160 unchanged baseline cases these also equal the accepted R31-A oracle byte-for-byte at the represented state/event level. Additional cases still start at original `00702050`; their caller frames are produced by original instructions, with no supplied intermediate return or callee result.

## Scan ABI and ordered behavior

At `0070210b`, ECX is the match receiver and the outgoing stack dword is the shooter pointer. The real CALL pushes `00702110`; `006d59b0` preserves EBX/EBP/ESI/EDI and returns with `RET 4`. Its side getter reads only shooter byte `+27` into AL. Zero selects the opposite roster at match `+6a6e`; a nonzero side selects match `+4796`.

The scan checks 20 slots at stride `1be`. Signed byte `slot+19` below zero skips the candidate; a nonnegative byte calls `007160f0`. That helper saves four registers, pushes the full EAX dword after replacing only AL with `slot+19`, and constructs ECX as `match + 91e2 + 18e3*signed8(slot+27)`. `005b57c0` interprets only the signed low byte of its argument and loads AL from `ECX+5b4+index`, then returns with `RET 4`. The unused upper argument bytes and register bits are retained in the comparison.

`00716121` tests returned AL bit `04`. When clear, `00716194..0071619a` restores the saved registers, zeros EAX and returns. Therefore no admitted candidate equals the nonnull shooter pointer, and `006d59b0` returns count zero in AL. The scan has only stack stores, with no game-state write or RNG use. A zero count for these guarded paths does not establish the general scan's return behavior when a tactical target is found.

When the bit is set, the reconstruction follows the original preparation at `00716125..00716144`. It reads the side and index again, preserves the upper EDX bytes when pushing the index dword, and reconstructs the tactical receiver before stopping at `0071614b`. The enclosing candidate and scan calls remain recorded with `after: null`; no return is invented. A first side-zero shooter example stops with ESP `0200793c` and ECX `0410aac5`. The next genuine dependency is `005b58e0`; its target lookup and subsequent candidate-selection behavior remain open.

## Caller continuation and numerical domain

After the scan returns, the caller stores AL at frame `+25`. It twice loads signed word `match+8ed0`, computes truncation toward zero of division by 11 using the original signed multiply/shift sequence, stores the first quotient's low byte at frame `+16`, and stores the second quotient's low word at match `+8d4c`. It writes shooter side byte `+27` to match `+8d4e` in between. These game-state writes occur in original order and are included in the full-memory comparison.

At `00702168`, the signed dword `match+4786` is loaded into x87 and compared with immutable scalar `1680.0`. The caller stores frame byte `+18 = 1` when the value is at least 1680. It then loads the already-produced float32 distance from frame `+80`, multiplies by immutable float32 `9.0`, and adds immutable float64 `2.5`. The scalar values and original byte hashes are verified against the pinned PE.

The public grid is the same labelled synthetic float32 hypot table used by R31-A. The reconstruction reads those supplied bits; it does not calculate a replacement distance. This continuation admits zero or float32 distances in `[1,16]`. In that domain, multiplication by 9 and addition of 2.5 use fewer than 32 significant binary bits and are exact at both explicit x87 53- and 64-bit precision settings. The model reconstructs active 80-bit ST0, TOP/tag, comparison condition flags and the final integer flags. It rejects a different precision, nonempty x87 entry, unsupported grid distance or changed scalar. It is not a general x87 arithmetic implementation, and rejection is not transactional.

At the guard-clear endpoint, ESP is `0200796c`, ECX is match `04100000`, and ST0 contains the original-produced `distance*9+2.5`. No argument is substituted for `00945640`. That runtime conversion is the next TypeScript dependency before the second distance call, `00713e90`, RNG and the later R30-C checkpoint. R30-A's longer original-only execution does not supply missing TypeScript behavior.

## Compared domain and evidence

The [compressed oracle](../evidence/action33-opponent-32-oracle.bin) contains **220 cases, 63,587 original instructions and 26,821 ordered memory events**, with zero RNG calls:

- 160 unchanged R30-A/R31-A cases, spanning both sides, both precision settings, existing clock/quality/grid/RNG states and an active opposing keeper;
- 32 additional guard-clear cases covering no active opponents, all 20 active, only slot 19 active, and signed nonnegative index 127, with flag bytes `00` and `fb`;
- 16 bit-04 cases, with first/last active opponents and flag bytes `04`/`ff`, stopping before the new tactical lookup;
- 12 comparison cases at 1679, 1680 and 1681 across both sides and precision settings.

The checker compares every ordered operand read/write, including stack arguments, saved registers and return addresses; every instruction address; before/after call snapshots; all eight integer registers and EFLAGS; x87 control/status/tag and active physical-register payloads; and complete final match, tactical, stack, RNG-table, synthetic-grid and immutable-scalar region digests. All four RNG global cells and semantic RNG state are unchanged. Eight-byte scalar operands are fixed hexadecimal values to avoid JSON number precision loss.

The admitted state excludes empty physical x87 payloads, FIP/FDP/selectors, other segment/system registers and per-instruction register snapshots. Intermediate scratch flags are only claimed where observed at the represented boundaries. The initial objects, their lifetimes, aliasing assumptions and precision settings remain synthetic; no native match initialization or original grid construction is established.

## Verification and reproduction

The [integrity verifier](../scripts/verify_action33_opponent_32.py) regenerates the exact oracle using separate normal and `-O` Python processes. Its 12 negative checks reject a modified PE, independent native operand, modified native file/manifest, unannounced bit-04 endpoint, out-of-grid original read, appended JSON whitespace, alternate gzip header, excessive gzip expansion, and raw/hex/compressed original code or grid fragments. It bounds gzip expansion before scanning and checks both compressed and expanded bytes. All Python integrity checks use explicit exceptions.

The [retained receipt](../evidence/action33-opponent-32-integrity.json) and oracle are independently hash-pinned by the Node checker. Public data are synthetic inputs/operands, instruction addresses and digests; no original grids, PE bytes, native exports or full memory dumps are retained. Node also rejects nonempty x87 state, unsupported precision and a changed multiplier. Full `npm run check` passes on Node **24.19.0**. R32-A's checker is run explicitly because the shared runner is coordinator-owned.

```text
python scripts/verify_action33_opponent_32.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --output results/opponent-normal.json
python -O scripts/verify_action33_opponent_32.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --output results/opponent-optimized.json
node reconstruction/check-action33-opponent-32.ts
npm run check
```

Python 3.13.7, Capstone 5.0.7 and Unicorn 2.1.4 generated the retained evidence. Coordinator adoption registers this bounded comparison in the shared runner and validation registry and records independent review in the queue; native state is unchanged. Its two next boundaries remain explicit: `00702193 -> 00945640` with the guard clear, or `0071614b -> 005b58e0` with bit `04` set.

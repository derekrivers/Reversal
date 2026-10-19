# R31-A: grid load and the first resolver-entry prefix

The [bounded TypeScript reconstruction](../reconstruction/action33-grid-31.ts) now matches original `006f09b0` returns and original resolver entry `00702050` through **before `0070210b -> 006d59b0`**. It uses the table as supplied data; it does not replace the lookup with a distance calculation. The 160 prefix cases use the original R30-A synthetic setup and its actual caller frame. Another 590 standalone helper cases exercise table indices, signed-byte narrowing and float32 bit patterns.

This closes R30-C's first missing TypeScript callee and an initial caller segment. The new prefix is not connected across `006d59b0` to R30-C's later `007022fd` checkpoint. No resolver return, participant-effect completion, shot outcome, live match or original database initialization is claimed.

## Pinned inputs and selected instructions

Base is merged R30-C main `36b44d8`. PE32 x86 SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses below are virtual. The [oracle generator](../scripts/emulate_action33_grid_31.py) independently compares all operands in the 187-byte caller prefix, the complete 61-byte/20-instruction helper, and the unexecuted next CALL: **66 static instruction comparisons**. File offsets and range hashes are retained in the compressed oracle.

The existing fresh checkpoint-28 exports are read-only. Their manifest hash is `5089d7a53a599ffaeada705cc7fb02ae62ab76070e3c886ac57cd99080019a4f`; helper assembly hash is `208e1339503ad34b1e76a8c7aac52998a65651a0a120d3403b6e426d30adf677`, and its C export is also pinned. The caller export hash is `40afb06c0e55a22091d0aff2bcca1521feadc9fae0bb87f9416ab4a72472f8cf`. These corroborate the earlier static [R12 contract](match-helpers-12.md).

R30-A's setup source is pinned at `9486fdba017157b918081023641a2360a392839c2339c287e2a8fa97d28cee32`. The Node checker separately pins the accepted R30-A oracle and reconstructs its synthetic memory and entry register values. No new native annotations or instruction ranges beyond this caller/helper scope are adopted.

## Exact helper ABI and numeric behavior

Let S be `006f09b0` entry ESP. ECX is the slot pointer; `[S+4]` and `[S+8]` are four-byte argument slots, but only their low bytes are read. The helper preserves ESI via its original PUSH/POP and returns with `RET 8` at `006f09ea`. EAX, ECX, EDX and arithmetic flags are scratch outputs, and the result is in x87 ST0. There are no calls or RNG accesses inside the helper.

For raw bytes, define `s8(v)` as signed low-byte interpretation and `d(a,b)=s8(abs(s8(a)-s8(b)))`. The actual index is:

`9*d(slot[103], argument_y) + d(slot[102], argument_x)`

The ordered operand sequence is slot Y (`006f09b0`), stack Y (`006f09b7`), saved ESI store (`006f09be`), slot X (`006f09ca`), stack X (`006f09d1`), grid DWORD (`006f09e2`), saved ESI read and return-address read. The X argument appears at current `[ESP+8]` because ESI has been pushed. Original instruction order, widths and values are compared including those stack accesses.

The narrowing at `006f09c4/006f09dd` matters: absolute delta 128 becomes -128, and 255 becomes -1. For example, X bytes 127/128 and Y bytes 0/1 yield index 8, not 264. The reconstruction rejects an index outside the admitted 108-entry table. Original code has no such guard; its corresponding out-of-domain read is rejected by the original execution harness's memory boundary.

`006f09e2` performs `FLD float32[00a15e44 + 4*index]`. Finite normal float32 values and signed zeros extend exactly into the 80-bit register; no arithmetic or distance rounding occurs in the helper. The model reconstructs the active significand/exponent, TOP and tag value. The caller's `007020c4` FSTP back to float32 preserves the loaded bits and leaves x87 empty. Explicit 53- and 64-bit precision controls are both covered. Denormals, NaNs/infinities, a nonempty or uncleared initial x87 stack, other rounding/control settings and exception paths are excluded.

The original grid window is VA `00a15e44`, file offset `00615e44`, 432 bytes, SHA-256 `898bbb4699c000e6f06cba789acc493c22e53a309d88c61896b39ca8f8c66a57`. Its bytes are not retained or used in the public fixtures. Public tables are labelled synthetic float32 hypot values, or repeated fixed patterns containing positive/negative zero, signed normals, smallest normals, largest finite normals and a fractional value. The model itself never calculates hypot. These comparisons do not establish the original grid's construction or its runtime lifetime.

## Actual caller prefix and first remaining dependency

The original entry allocates its frame, saves EBX/EBP/ESI/EDI and reads shooter context and two match fields. At `00702088`, ECX is the original shooter; arguments are `[4,11]` for side byte zero and `[4,0]` otherwise. The real CALL pushes `0070208d`. Its return frame and complete integer state are recorded before the next original caller instruction, without patching the machine or providing a callee result.

The subsequent caller loads the shooter's word `+39`, coordinate bytes and action word `+198`; stores the loaded float32 result at caller frame `+80`; and initializes the observed local bytes/words. Only stack memory changes in this segment. No RNG draw or state transition occurs.

At the stop, ESP is `02007968` (entry SP minus `0x698`), ECX is match `04100000`, ESI and the outgoing stack DWORD are the shooter, EBP is zero, and EDI holds the original supplied quality. The caller frame retains the exact grid bits and local writes. These are outputs of the compared original entry, not a supplied interior checkpoint. The next call `0070210b -> 006d59b0` is independently PE/native checked but is neither executed nor replaced by this unit. R30-A's guarded original execution of that opponent scan is context for the next reconstruction.

## Comparison and claim boundaries

The [76,836-byte oracle](../evidence/action33-grid-31-oracle.bin) retains 160 entry-prefix cases and 590 helper-return cases: 432 table/precision/pattern combinations plus 158 signed-coordinate edge cases. Every one of the 108 table indices is exercised in both precisions and both synthetic tables. There are **21,960 original instructions and 11,920 ordered data events**, with zero RNG calls.

The [Node checker](../reconstruction/check-action33-grid-31.ts) compares exact instruction paths; every data/stack read and write with site, address, width and value; call arguments and before/after snapshots; all eight integer registers and EFLAGS at the boundaries; x87 control/status/tag and active 80-bit payloads; and complete final match (64 KiB), tactical (4 KiB), stack (64 KiB), RNG-table (204,000 bytes) and grid (432 bytes) digests. All four RNG global cells and semantic RNG state remain unchanged. No stack accesses or helper operand reads are projected away.

The admitted CPU state is explicitly those snapshots. Empty physical x87 register payloads, FIP/FDP/selectors, other segment/system registers and intermediate per-instruction register snapshots are not compared. This is a bounded state reconstruction, not a general x86/x87 emulator. The fixtures start with synthetic mapped records and empty x87; they do not establish actual match-entry precision or object lifetime. Unsupported-input rejection is not transactional.

## Integrity, privacy and reproduction

The [verifier](../scripts/verify_action33_grid_31.py) regenerates the complete oracle in separate normal and optimized Python subprocesses, with identical bytes. Seven negatives reject a changed PE, independent native operand, changed native file, changed manifest, original out-of-grid read, appended JSON whitespace and alternate gzip envelope. All Python gates use explicit exceptions. Public schemas, fixed synthetic schedules and operand regions are checked; original code, grids, native exports and full memory dumps are absent. The [retained receipt](../evidence/action33-grid-31-integrity.json) and oracle are hash-pinned by the Node checker.

```text
python scripts/verify_action33_grid_31.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --output results/grid-normal.json
python -O scripts/verify_action33_grid_31.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --output results/grid-optimized.json
node reconstruction/check-action33-grid-31.ts
npm run check
```

Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.22.0 pass these checks. A clean archive of the staged files, initially without `results/`, also regenerates the retained receipt and passes the Node checker. Independent receipt status and negative-check-list mutations fail at the receipt hash gate; the staged binary blob equals the working oracle byte-for-byte. The shared runner is unchanged; the task checker is run separately pending coordinator adoption. No registry, queue, checkpoint or native files are modified.

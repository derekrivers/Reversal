# R36-A: selector ABI and caller continuation

The [TypeScript continuation](../reconstruction/action33-selector-36.ts) now reaches `006ce110` through the actual `0070230c` call from resolver entry `00702050`, executes the admitted selector path, and continues its caller. **224 cases stop before `007023e3 -> 0090cfc0` with bound 2; eight null-keeper cases stop before `00702332 -> 00944cff`.** Neither pending call executes. The selector receives the original-produced R35-A stack, registers, synthetic memory and shared RNG state; no intermediate keeper result is supplied.

This is a bounded original-instruction comparison on synthetic state, not an observed live match, a resolver return, an outcome, or a full machine-state join to R30-C.

## Specimen, dependencies and scope

The pinned PE32 x86 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Code addresses here are virtual; retained range records label file offsets separately. This branch started at reviewed R35-A integration `6977fa037aa62433c682ebd43f3d76c0256b3649`. The R35-A generator, TypeScript module and oracle hashes, plus the R30-C oracle hash, are pinned in the new evidence. R35-A in turn verifies the preceding R34-A dependencies. No shared runner, registry, queue, frontier or canonical native database is changed by this unit.

The [generator](../scripts/emulate_action33_selector_36.py) rechecks the original PE, inherited caller/runtime exports and read-only `exports-29` manifest SHA-256 `ced03a8f3d9da3cc61fcb9d63e0be55cb1cc39776615c038e0320836a526c0da`. It compares every instruction and operand in the new caller ranges and the full 500-byte selector body with native exports. The selector body digest remains `660d12df39b311406471ada13e890b66a43cf89a66285a69a5b605d03fa81b4d`, as recorded by R29-A.

All **232 inherited R35-A cases** start at the original resolver entry. At pre-`0070230c`, their original full represented states, prior instruction sequences, ordered memory events, calls and nine prior region digests exactly match R35-A. The Node checker independently derives that checkpoint by executing the TypeScript prefix. The synthetic fixture schedule, grid and random table are unchanged.

The new selector continuation reaches **125 of 155 selector instruction starts**. All slot reserve-index bytes `+1a` are negative in this inherited schedule, so the 30 remaining instructions belong to reserve-candidate/replacement routes. Those routes are deliberately excluded from the new machine-state implementation. It rejects their first entries at `006ce17e`/`006ce267` and `006ce1d6`/`006ce2bf`. R29-A's complete local static contract and separate scalar-selector tests remain valid at their own scope; they do not expand this connected machine-state evidence.

## Selector effects and exact ABI

The selector receives ECX=match and the existing argument dword `04100001` or `04100000`. It saves EBX, EBP, ESI and EDI, then reads only the low argument byte at `[ESP+14]` near return. It processes both side caches in order before selecting the requested cache. A selector byte of 1 returns side 1; otherwise it returns side 0. The argument's high bytes are preserved on the incoming stack and never normalized by an injected call adapter.

The admitted routes retain a valid cached pointer, clear a negative-index cache, select a direct tactical candidate, or fall back to the first nonnegative active slot. The direct scan continues through all 20 slots after selection to test reserve eligibility. The fallback may rewrite the active index byte after its tactical-word test. There are **13,312 ordered selector match/table events**, including **280 dword stores and eight byte stores**. The exact instruction order, addresses, widths and values match between TypeScript and the original. The selector also performs 2,320 stack accesses over the 232 cases, in addition to the caller's CALL write and caller continuation.

ECX and the four saved registers are preserved. EAX contains the selected pointer or zero; EDX is scratch and is compared at its full returned width. Both original return sites use `RET 4`: after return to `00702311`, ESP is four bytes above the caller's pre-call ESP. This removes the pushed selector argument. The model compares full call/return snapshots, including EFLAGS and represented x87 state. The selector contains no nested call and consumes no RNG; the only RNG call executed in each whole prefix remains R35-A's real zero-bound call.

## Caller boundaries

After the selector returns, the caller stores EAX in EBX and frame `+48`, compares the pointer with EBP=0, and branches.

For the **224 nonnull cases**, action byte `33` becomes index `1d` after subtracting `16`. The actual read at `007023a0` obtains byte 4 from PE dispatch VA `0070a5c5`; the indirect jump at `007023a6` reads target `007023e1` from VA `0070a5a4`. Both immutable windows are pinned against the PE, included in the ordered read comparison and final region digests, and seeded as the same scalar data in TypeScript. The caller pushes bound 2 and stops before `007023e3`. The shared cursor, offset, limit and CRT seed have not advanced. The first remaining positive-path dependency is the nonzero RNG call's machine-state execution and return, followed by the keeper preparation and call.

The **eight null cases** are the inherited `inactive` opponent configurations for source cases 0, 1, 10 and 11 at flags 0 and `fb`. The original selector returns zero. The caller builds the diagnostic frame and stops before `00702332`, with five outgoing dwords `[00a16058,00000000,00000000,02007c00,02007e00]`. The string pointer is retained as an address only; the string is not read or published, and the diagnostic routine is not called. No replacement keeper or success path is invented for these cases.

The existing bit-04 tactical stop, contact branch and nonzero RNG branch in earlier units remain separately bounded. Reserve-candidate paths are the new selector's explicit excluded branches.

## Compared evidence and remaining R30-C join

The [636,672-byte oracle](../evidence/action33-selector-36-oracle.bin), SHA-256 `f019948252ce992d2fd43d5ddf9a51b0646c3fb8fe1837ca4ef009f4dd63d3ce`, retains **159,771 original instruction steps and 62,171 ordered data/stack events** across the 232 original-entry cases. The new suffix contributes **58,328 instruction-state snapshots and 17,032 memory events**. The state snapshots are serialized in exact instruction order and hashed as newline-delimited canonical JSON; the TypeScript checker builds and compares the same digest and count. Final and call-boundary snapshots are retained directly. Full instruction sequences and ordered memory events are retained directly as synthetic operands.

Every snapshot represents all eight integer registers, EFLAGS, x87 control/status/tag and active payloads, plus exact RNG state cells. Final digests cover all **11 admitted regions**: the nine inherited synthetic/scalar regions and the two immutable dispatch windows. Empty physical x87 payloads, x87 instruction/data pointers and hardware exception behavior remain outside the representation. Undefined flag values, such as AF after logical operations, match the pinned Unicorn 2.1.4 observations; this is not a claim about every physical x86 processor.

For the **160 baseline cases**, the selector's ordered match/table events and selected pointer match R30-C's original-execution projection. R35-A already supplies its separately checked `007022fd` input projection. These matches do not establish the entire R30-C machine-state join: the later variant/keeper segment still omits original stack/scratch-register effects, full keeper return bits, keeper operand-read order and x87 status/tag evolution. This unit stops before the variant draw or diagnostic rather than importing that omitted state.

## Integrity and reproduction

The [verifier](../scripts/verify_action33_selector_36.py) regenerates the oracle in separate normal and optimized Python processes and requires byte-identical output. Sixteen negative checks reject changed PE bytes, an independent native argument-offset mutation, changed native selector bytes, a changed synthetic RNG table, corrupt actual preserved ESI, wrong actual return cleanup, a changed actual RNG cell, an unsupported reserve branch, an altered actual dispatch byte, noncanonical/oversized payloads, a changed retained instruction-state digest, and raw/hex/compressed private code fragments. All Python integrity gates use explicit exceptions and remain active under `-O`. The Node checker additionally rejects unsupported reserve, action and dispatch inputs.

```text
python scripts/verify_action33_selector_36.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --output results/selector36-normal.json
python -O scripts/verify_action33_selector_36.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --runtime EXPORTS_30_RUNTIME --r29 EXPORTS_29 --output results/selector36-optimized.json
node reconstruction/check-action33-selector-36.ts
npm run check
```

Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.19.0 were used. Normal and optimized receipts are byte-identical; the task checker and full repository check pass. This integration registers the checker in the shared runner and adds its bounded TypeScript domain to the validation registry. Original PE bytes, bulk native exports and full private memory images remain outside Git.

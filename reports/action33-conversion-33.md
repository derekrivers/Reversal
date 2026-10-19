# R33-A: original-produced conversion and caller continuation

The [TypeScript continuation](../reconstruction/action33-conversion-33.ts) extends R32-A's clear path from **`00702193 -> 00945640`** through the second grid call and the real caller argument preparation to **before `00702222 -> 00713e90`**. It uses the same mutable synthetic memory, actual R31-A/R32-A implementations and original-produced ST0. No intermediate conversion result is supplied to this connected path.

The evidence covers original x86 instructions executed on synthetic state. R30-C's `007022fd` interior segment remains separate; this work does not join it, execute `00713e90`, return from the resolver, or produce a shot outcome. The 16 prior tactical bit-04 cases still stop before `0071614b`; the newly inspected `005b58e0` body is a **separate static contract**, not a connected execution claim.

## Specimen, inputs and boundaries

The baseline is merged R32-A PR #120, `afbdea6`. The PE32 x86 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses here are virtual; [oracle](../evidence/action33-conversion-33-oracle.bin) site records also identify file offsets. All original/private inputs remain outside Git.

The [generator](../scripts/emulate_action33_conversion_33.py) verifies the pinned R30 prefix manifest, caller export and each used dependency file before comparing 242 selected instruction starts and operands, including both unexecuted stop CALLs. The 251-edge static graph must remain within admitted ranges and their declared stops. The complete conversion body is 39 bytes, `00945640..00945666`, at PE file offset `00545640`, SHA-256 `d0a2aca68648a0ae9d5cbfae1b276d4a64d4f797fc0c60f28b64096cdfa3148c`. It has 16 Capstone instruction starts. As in R30-A, native Ghidra's combined `FSTCW` is explicitly verified before comparison with the equivalent `WAIT`/`FNSTCW` decoder split.

The original conversion native ASM/C files come from `exports-09`; their hashes are retained in the oracle. The separate focused bit-04 export manifest is `42425fa15eeb2da209497e396b81bacc99e77a2c608500cdd9febd7ee9091f79`, supplied from a disposable checkpoint-29 copy. Only the selected `005b58e0` files are consumed. No native annotations or database writes are proposed.

The public grid is synthetic float32 data. The 220 unchanged R32-A inputs retain their exact original-produced checkpoint, complete prefix instruction path, ordered operands, calls and represented state. Twenty-eight additional clear cases replace the synthetic grid with seven uniform finite values, across both sides and both precision modes, to challenge integer and signed-byte boundaries. An additional 32 rounding probes start original execution at `00702050` under each incoming rounding-control setting and stop just after the conversion. Their **TypeScript comparison starts at the original-produced conversion checkpoint**; no directed-rounding TypeScript entry-prefix equivalence is claimed.

## Conversion ABI and x87 control

At the clear checkpoint, ESP is `F=0200796c`, ECX is match `04100000`, and physical x87 register 7 is ST0. The caller has already produced `distance*9+2.5` using its original float32 distance and immutable scalars. This admitted domain is `[2.5,146.5]`; the arithmetic preceding the conversion is exact at both tested x87 precisions.

`00945640` consumes ST0 with no integer stack arguments. It saves EBP, allocates twelve local bytes and saves the incoming control word at `[EBP-2]`. `OR AH,0c` at `0094564f` sets both rounding-control bits. `FLDCW` installs that word, then **`FISTP qword [EBP-0c]` at `00945659` truncates toward zero into signed 64-bit storage and pops ST0**. The original control word is restored at `0094565c`. The two dword loads return the low and high words in EAX and EDX, followed by `LEAVE; RET`.

The model converts the actual 80-bit significand/exponent with integer arithmetic. In all admitted cases EDX is zero; this does not establish behavior for negative, exceptional or overflowing inputs. The body preserves EBX/ECX/ESI/EDI/EBP and restores the caller ESP. EFLAGS reflect the `OR AH` operation at return. Ordered memory observations include the real CALL return address, saved EBP, both control-word stores, eight-byte integer store and subsequent loads/restores.

The retained 792 x87 observations explicitly compare the state before control-word saving, at `FISTP` after truncation mode is installed, and after the original control word is restored. The 32 separate probes cover incoming CW `027f/067f/0a7f/0e7f` and `037f/077f/0b7f/0f7f`, with fractional and integral inputs. The temporary CW is always `0e7f` or `0f7f`; all return the same truncated integer for a given ST0 and restore the incoming CW exactly. These are supplied synthetic controls, not a measurement of live match control state.

**Status limitation:** Unicorn 2.1.4 exposes no precision-exception flag for these fractional `FISTP` observations. The reconstructed FPSW values match that emulator observation, including TOP, comparison bits and stack tags. This is not hardware x87 exception/status equivalence. Pending exceptions, unmasked exceptions, special values and hardware exception delivery are excluded. The full caller continuation admits only round-to-nearest/even at 53 or 64 bits. The general runtime conversion outside this finite positive domain remains unvalidated.

## Caller effects and next unsupported call

After conversion, `MOVSX ECX,AL` uses only the **signed low byte** of the returned integer. The original multiply/shift sequence divides that signed byte by five toward zero. The byte multiply by five and store at `007021b1` produce:

`frame[1b] = uint8(5 * trunc(signed8(trunc(distance*9+2.5)) / 5))`.

| Synthetic distance | Converted integer | Signed AL | Stored byte at frame+1b |
| --- | ---: | ---: | ---: |
| 0 | 2 | 2 | 0 |
| 1.5 | 16 | 16 | 15 |
| 13.9375 | 127 | 127 | 125 |
| 14 | 128 | -128 | 131 |
| 16 | 146 | -110 | 146 |

For action `33`, `007021cd` writes dword `120` to frame `+64`. The caller then pushes the side-dependent target `(4,11)` or `(4,0)` and executes the second original `006f09b0` call at `007021e5`. The TypeScript implementation reuses R31-A's grid index/load/ABI behavior and preserves the preceding comparison status bits. The original scalar read at `00967890` is verified as `1.0`; the caller adds it to the returned float32 distance and stores the result as float32 on the outgoing stack.

At the new stop, ECX is the shooter and ESP is `F-1c = 02007950`. Seven outgoing dwords are ready for `00713e90`, in callee argument order: action, raw x argument, raw y argument, target x, target y, float32 bits of `distance+1`, and output pointer `F+7c`. Their complete stack bytes are compared. In the first case they are `[00000033,02007900,00000000,00000004,0000000b,414b4673,020079e8]`. The x argument retains the high bytes of the output-pointer temporary when `MOV AL,shooter.x` changes only AL; it is not normalized to a clean coordinate dword.

This extension writes stack/local state only. The earlier ordered match stores at `+8d4e/+8d4c` still come from R32-A and are checked in the combined entry path. There are no RNG calls or changes to any of the four RNG cells. `00713e90` and its actual caller effects remain the next boundary before the later RNG and R30-C interior checkpoint.

## Independent bit-04 static inspection

The complete 42-byte `005b58e0..005b5909` local body has 12 instructions, two `RET 4` exits and no calls or memory stores. It reads a signed byte at `[ESP+4]`, then a signed dword at `ECX+5bf+4*index`. A negative dword returns zero. A nonnegative dword computes `uint32([00ae23bc] + 110*id)` and returns that address in EAX; it does **not** dereference the resulting address or validate a record range.

This clarifies the next dependency of the original bit-04 caller. R32-A already supplies the tactical receiver and raw index argument at `0071614b`; its admitted candidates have low-byte indices 0 or 19. The lookup-row producer and global `00ae23bc` initialization/lifetime remain open. The subsequent original code compares the result with candidate `slot+69` at `00716182`, then may follow more flag/selection logic. Static address arithmetic is not evidence of a valid staff pointer, returned candidate or joined clear path. The 16 bit-04 execution cases remain unchanged and stop before calling this helper.

## Compared scope, reproduction and checks

The retained corpus contains **280 cases, 99,787 original instruction steps, 43,235 ordered memory events and 238 reached instruction starts**: 232 connected clear continuations, 16 unchanged bit-04 stops, and 32 separately scoped conversion probes. The [Node checker](../reconstruction/check-action33-conversion-33.ts) compares all represented integer registers/EFLAGS, control/status/tag words and active x87 payloads, ordered data and stack operands, instruction paths, actual call/return snapshots, and complete match, tactical, stack, RNG-table, grid and scalar-region digests. Directed-rounding probes compare only the conversion suffix and final admitted state/memory. Empty physical x87 payloads, FIP/FDP/selectors, segment/system state and per-instruction GPR/flag snapshots remain excluded.

The [integrity verifier](../scripts/verify_action33_conversion_33.py) regenerates the oracle in separate normal and optimized Python processes and enforces canonical gzip/JSON and fixed synthetic schemas. Eighteen negative checks reject changed specimen bytes, independent conversion and bit-04 operands, dependency/manifest changes, conversion/focused export changes, an unexpected tactical path, an out-of-grid original read, semantic oracle changes, changed conversion rounding, envelope/expansion changes and raw/hex/compressed private fragments. Privacy scans cover both compressed and bounded expanded payloads plus task code/report/receipt files. No full original memory, code, grid or private export is retained.

```text
python scripts/verify_action33_conversion_33.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --focused EXPORTS_R33_FOCUSED --output results/conversion-normal.json
python -O scripts/verify_action33_conversion_33.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --focused EXPORTS_R33_FOCUSED --output results/conversion-optimized.json
node reconstruction/check-action33-conversion-33.ts
npm run check
```

Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.21.0 were used. Normal and optimized receipts are byte-identical. The task checker and full repository check pass. The shared runner, registry, queue, atlas and native database are coordinator-owned and were not edited here.

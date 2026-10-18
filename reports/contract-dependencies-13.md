# Contract scalar and context-row dependencies, investigation 13

`004d0c60` computes a raw32 scalar using source attributes, context records, an existing contract row and x87 arithmetic. `004cf5f0` finds an existing row whose DWORD `+4` matches a context identifier, optionally trying a helper-derived context. The initializer lead is overturned: neither owned body initializes or reserves rows. The only explicit nonstack store is DWORD global `00ae1080` in `004d0c60`. Opaque callees can have additional effects. R12's caller stores the returned scalar in source DWORD `+52`; units, complete negotiation and persistence remain unresolved.

Specimen SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline: `87ea0f39d5dcb62fe6969ad6570c3dca8b152673`. Addresses are virtual; field offsets are hexadecimal bytes. The bodies span `004d0c60..004d15f1` (2,450 bytes; file offset `000d0c60`) and `004cf5f0..004cf6c0` (209 bytes; file offset `000cf5f0`). An independent Capstone 5.0.7 decode matches all 714/91 instructions in the read-only checkpoint-12 exports. Every direct jump targets an instruction inside its owned body; final returns lead to padding before the next entry. This supports the supplied boundaries without proving all runtime entry paths.

Both functions are **contract-supported** at whole-body static scope. No original-instruction numerical oracle or runtime effect trace was added. Names and field meanings remain research labels.

## Calling convention and R12 relationship

| Entry | Inputs and return |
| --- | --- |
| `004d0c60` | Incoming ECX is forwarded unchanged to `004cf5f0` as manager. Frame slots EBP `+8/+c/+10/+14/+18` are source pointer, context pointer, low8 mode, low16 selector and an unused raw32 slot. All four normal exits use `RET 0x14`. EBX/ESI/EDI/EBP and caller stack alignment are restored; only EAX low32 is claimed as the result. |
| `004cf5f0` | ECX manager, entry ESP `+4` source pointer and `+8` target-context pointer. EAX is a row pointer or zero. All five exits use `RET 8`; EBX/EBP/ESI/EDI are preserved. |

The fifth stack slot in `004d0c60` is popped but never read; all EBP-relative operand reads have displacements `{8,c,10,14}`. Ghidra's four-argument pseudocode is therefore insufficient for a callable ABI declaration. Its receiver omission also hides the manager forwarded at `004d0cd6`. The receiver is not retained after this call.

R12 instructions `004c766b..004c7683` set ECX=manager and push logical arguments `(source, source.DWORD+39, 1, -1, 0)`. `004c768b` stores EAX to source DWORD `+52`. Exported incoming references list 59 calls to `004d0c60` and 148 to `004cf5f0`; their full caller contracts are unassigned. These counts describe the export inventory, not runtime reachability or exhaustive indirect callers.

## Existing-row selection (`004cf5f0`)

Null source or target returns zero. A signed `source.ID < DWORD[00ae2364]` gate admits a lookup in `DWORD[00ae2d0c] + source.ID*0x4f`. Negative IDs pass that gate. The first auxiliary DWORD must be signed nonnegative; it selects `manager.DWORD+0 + index*0x50` and that sum must be nonzero (`004cf62b..004cf63f`). If its DWORD `+4` equals target DWORD `+0`, return that primary row.

Only after primary mismatch does the helper consider auxiliary DWORD `+4` as a secondary index. A nonnegative index forms another `0x50`-stride row; nonzero pointer and matching DWORD `+4` return it. A negative index sets the secondary candidate to zero (`004cf654..004cf65b`, `004cf68e..004cf6a3`). A missing/invalid primary candidate returns zero immediately; a valid secondary alone is insufficient to enter this path.

On both mismatches, `00540a50(target, &source_argument_slot, 1)` is called at `004cf665` with caller cleanup `ADD ESP,0xc`. The pointed slot is the original source argument at entry ESP+4, not a separately zeroed flag. A nonnull EAX and zero rewritten slot replace the target pointer with EAX (`004cf671..004cf679`). The primary row, then nonzero secondary row, are tested again against this chosen target DWORD `+0`. The dependency's meaning, mutation policy, RNG and returned-pointer ownership are unresolved. There are no owned row/source/global writes, allocation or direct RNG calls. Passing a pointer to the argument slot lets the opaque helper mutate this function's stack.

No source-ID lower bound, row-index upper bound, manager/base extent or arithmetic-overflow check is present. Pointer arithmetic wraps at 32 bits. Valid source, context, auxiliary and row storage are preconditions rather than established invariants.

## Scalar entry and initial arithmetic (`004d0c60`)

The first lookup uses **global** manager `DWORD[00ae1050]`, independently of incoming ECX. Null source, rejected high ID or negative primary auxiliary index chooses zero; otherwise it computes the primary row address and stores it in global DWORD `00ae1080` at `004d0caf`. A nonzero row supplies DWORD `+4`, from which `DWORD[00ae23b4] + ID*0x245` forms a derived context. It then calls `004cf5f0(incoming_manager; source, derived_context)` and retains the returned row. The two managers' identity is a caller precondition; this body does not compare them. A source null check during lookup does not make source null safe: `004d0cdb` unconditionally reads source `+61` afterward.

When source DWORD `+61` is zero, nonzero derived context calls `008d0780` with ECX=`DWORD[00de1f54]` and `(source, derived_context, 1)` at `004d15d9`, returning its raw32 EAX. A zero derived context returns zero. This bypasses all owned x87 calculation and the direct RNG call, though earlier row lookup and opaque dependencies may already have effects.

For nonnull attribute pointer A=source DWORD `+61`, signed BYTE tests choose a base B and threshold T:

| First satisfied condition | B | T |
| --- | ---: | ---: |
| A `+15 >= 15` | 13,000,000 | 28 |
| A `+14 >= 15` | 11,000,000 | 29 |
| A `+13 >= 15` | 10,000,000 | 29 |
| A `+12 >= 15` | 9,000,000 | 29 |
| A `+f == 20` | 6,000,000 | 33 |
| Otherwise | 8,000,000 | 29 |

The `+10` comparison and possible `+11` load (`004d0d6f..004d0d75`) do not change this selection: AL is overwritten at `004d0d8d`. For ordinary finite arithmetic, let age-like byte a be signed source `+18`, d=T-a, and h=d when d<=5, otherwise h=8-0.5*d. `004d0daa..004d0df2` constructs `1 + h*abs(ftol(h))*float32(1/3)*(1/12)`. If signed A `+f <15`, five factors additionally depend on signed bytes A `+28/+27/+43/+36/+2f`: respectively `1+(v-15)/75`, `1+v/200`, `1+v/300`, `1+(v-15)/75`, `1+(v-15)/75`. Constants are the original stored float/double approximations.

The result is multiplied by `1.33 - (signed8(A+2d)^2)*0.05*0.034`, stored to float32, then bounded below by 0.01 and above by `max(1.1, signed16(A+9)/3000+0.17)`, finally stored to float32 again (`004d0e95..004d0f20`). These stages, including their signed inputs and float stores, are largely absent from the exported pseudocode. The expressions describe stages; they are not a validated numerical replacement for the ordered x87 instructions.

## Integer magnitude and context scale

With null supplied context C, the initial integer magnitude is signed16 A `+b`. With nonnull C, `005407e0(source, C.DWORD+cf, 0)` supplies signed16 AX (`004d0f3e..004d0f43`). If selector low16 is `-1`, `006e86d0(C.DWORD+cf, source, C, 1, signed_AX)` is called, and its EAX feeds the next stage. Otherwise the loaded selector supplies EAX. The low16 of `EAX*50` is treated signed and floored at zero, then combined with the signed16 helper result and the **unsigned** minimum of that result and 5,000. The resulting DWORD terms are zero-extended through QWORD locals before `FILD`; the float32 factor above affects one term. After multiplication by the stored float32 1/3 and `ftol`, **unsigned** comparisons clamp EAX to `[1,12000]` (`004d0f69..004d0fca`). This is not a signed clamp for malformed input.

Signed16 A `+d >5000` and original a<T+4 admit an unsigned maximum with `(EAX>>1)+A.+d-2500`. If A `+d >8000` and a<=T, a further x87 maximum uses `A.+d*2.25+(EAX>>1)-12500`, followed by `ftol` (`004d0fcf..004d105d`). The square then retains only its low32 product and zero-extends that product for signed-QWORD `FILD` (`004d1067..004d1079`).

Nonzero unsigned source BYTE `+22` and nonnull source DWORD `+1a` permit a signed16 linked value at `+8e` to adjust the age-like byte. Their signed product is divided by 18, truncated to low16 and sign-extended; the adjustment is limited by original T-a and zero, then added with byte wrap. The signed-byte result of `T-adjusted_age+10` is clamped to `[0,19]` before a signed-byte table read at `009a7f30` (`004d108b..004d10f0`). Together with B, the zero-extended square, `1e-8` and 0.01, this forms the initial scalar.

The scale k is selected as follows (`004d1113..004d1238`):

- Null C calls known bounded RNG `0090cfc0(3)` once at `004d1227`, then uses EAX+1. This is the only direct RNG call in either owned body.
- Nonnull C with null DWORD `+53` uses 1.
- Otherwise signed BYTE `[C.+53+7e]` is accepted only in `[1,3]`; values outside that interval select 3. When C DWORD `+57` is nonnull, `(value+1)*0.5` is used before scaling; otherwise use value directly. Signed C BYTE `+64` equal to 2 doubles it; equal to 3 multiplies it by 7.5.
- The numerator is `25*v*v + signed16(C+80)`, with v signed16 `[C.+57+69]` when `+57` is nonnull, otherwise signed8 `[C.+53+85]`. Signed32 integer arithmetic wraps. Divide this numerator by the scaled value times 1000.

The initial scalar is multiplied by `clamp(1-(20-k)^2*0.2*0.02,0.1,1.1)`. If it exceeds `65000*k*k`, replace it with `0.25*scalar+32500*k*k`; then apply a lower bound of `5000*k` (`004d1238..004d12d6`). The executable has no owned loop, so the direct RNG site is executed at most once per normally completing invocation; total draws remain unknown because of opaque callees.

## Mode, date-like and identifier gates

With mode low8 nonzero, context `+53` ID equal to DWORD `009cf434` admits a transform: below 6,000,000 multiply scalar by `scalar*(1/6000000)*0.6+0.3` and floor at 5,000; otherwise multiply by 0.9 (`004d12e3..004d1351`). A selected row with nonzero `00867b50(row)` result then supplies a signed DWORD `+21` cap. `FILD row_value; FLD scalar; FCOMP` leaves the row value on the x87 stack: scalar>=row returns that row value, while scalar<row reloads scalar (`004d136c..004d1382`). Finally `ftol` supplies EAX. There is no direct row `+21` write or general nonnegative return guarantee.

With mode zero, no selected row sets scalar to zero. A row first calls `008d0a70` with ECX=`DWORD[00de1f54]` and source as its stack argument (`004d139c..004d13a3`). If nonzero, compute raw32 D=`(unsigned16(row+2f)-unsigned16(global00ae2c92))*365 + signed16(row+2d)-signed16(global00ae2c90)`. Signed D<1 returns zero. If supplied context equals the saved derived context and signed row BYTE `+3d` is positive, row BYTE `+35 &0x3f ==2` adds `200+7*byte` to D; otherwise halve the scalar. D<350 scales by D/700; other D values divide by `clamp(2.5-D/700,1,2)` (`004d13b0..004d1474`). Calendar semantics and helper effects remain provisional.

For zero scalar or context `+53` ID unequal to DWORD `009cf434`, the alternate identifier path is used: ID equal to DWORD `009cf300` multiplies by 0.8; ID equal to DWORD `009cf484` multiplies by 0.25, then halves excess over 125,000 and over 250,000, each through a separate `ftol`/signed-DWORD reload when its threshold is exceeded (`004d1480..004d1592`). Other admitted `009cf434` values use the transform above. The final row predicate can again cap the scalar at signed row DWORD `+21` before `ftol` (`004d15a7..004d15bd`). Identifiers are comparisons against live DWORD globals, not recovered country or competition names.

## Limits and reproducibility

All x87 stages retain original compare/status-bit gates, float32/float64 stores and explicit integer conversions. The finite-value descriptions above do not define NaN, exception-mask, x87 precision/rounding or out-of-range conversion behavior. `00945640` is the existing `__ftol`-labelled dependency; its complete implementation and environment were not revalidated here. Ghidra also omits the nonzero-mode `009cf434` transform and the zero-mode `009cf300` branch; its output must not be used as a behavioral oracle.

No owned allocation, release, row reservation, row initialization or persistent write is present. `00540a50`, `005407e0`, `006e86d0`, `00867b50`, `008d0a70` and `008d0780` remain effect/RNG dependencies. The original table and valid global/row lifecycle remain required input evidence. The returned row pointer has no demonstrated lifetime extension or ownership transfer. Global `00ae1080` is a published primary candidate, not necessarily the row returned by `004cf5f0`.

Reproduce compact evidence with `python evidence/contract-dependencies-13-extract.py SPECIMEN evidence/contract-dependencies-13-sites.json --native-dir EXPORTS` under Capstone 5.0.7. The extractor pins the PE and export-manifest hashes, compares complete owned listings, checks direct reference targets, verifies boundaries/ECX forwarding/frame-slot reads and emits selected sites plus factual numeric constants. Bulk code, native projects and original tables remain private. `npm run check` passes under Node 24.22.0; this validates the retained unrelated oracles/checkpoint metadata, not these newly mapped scalar calculations.

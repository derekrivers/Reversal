# Investigation 21: slot scalar updates and two-side positioning

R21-B maps `006f5810` and `006c50d0` as complete local static contracts. The first updates float32 slot scalars through profile, flag and signed-byte branches. The second selects an active slot, positions it, then visits both side groups to constrain other coordinates and invoke a callback. These are static instruction findings; no execution oracle, TypeScript port, connected period/match outcome or validated live input domain is claimed.

The pinned PE SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. This work uses merged queue baseline `0eac17d`, checkpoint 19. All addresses and offsets are hexadecimal unless a value/count is explicitly decimal. Function and field meanings remain research labels.

| Virtual entry | Bytes / instructions | Branches / calls / direct RNG sites / state stores | Raw file offset |
| --- | ---: | ---: | --- |
| `006f5810` | 772 / 213 | 34 / 6 / 0 / 10 | `2f5810` |
| `006c50d0` | 271 / 92 | 15 / 7 / 0 / 2 | `2c50d0` |

The [generated sites](../evidence/match-state-21-sites.json) include every local branch successor, direct call, explicit memory read/write and normal return, plus normal stack joins, x87 stack depths and five constant digests. Capstone 5.0.7 decodes the complete PE bodies independently before comparing every instruction address, mnemonic and operand to pinned read-only Ghidra exports. Both bodies are contiguous through their last RET, all branch targets remain inside their bodies, and all exported instructions are structurally reachable. No body correction is proposed. Capstone incorrectly labels FST/FSTP memory operands as reads here; the extractor explicitly classifies those as writes.

## `006f5810`: update slot scalar fields

Entry ECX=p, low-byte flag at entry ESP+4; the one return is RET4 at `006f5b11`. Only ESI is saved/restored; EBX/EBP/EDI are untouched locally. Incoming EDX is unused. No stable EAX/AL result is assigned: EAX can contain a prior value, a callee result, partial byte loads or an x87 status word in AX. The argument's full four-byte stack slot is reused for integer scratch after the flag is consumed. Locals contain one float64 multiplier. No p null check exists.

1. Initialize multiplier K to float64 1.0. If dword p+6d is zero, return without non-frame writes or calls. Otherwise read dword p+69 and its first dword without a null guard, then call `0062c3d0(dword(b63d28); dword(dword(p+69)))`. Compare **signed AX** to decimal1000. Only a greater result repeats the call, reloading p+69, its first dword and the global receiver. K then becomes `C1 - s16(second AX)*C0`, stored to float64, where C0 at96a608 is binary64 approximately0.0004 and C1 at968dc0 approximately1.4. The second result is neither reused from the first nor required to remain above1000; there is no local bound on K.
2. Consume the low-byte flag. Zero selects the +4d route below; any nonzero byte selects the +51 route. All uses of p+6d after calls are fresh loads, rather than the initial guarded pointer. The guard does not prove subsequent validity.

### Zero flag: optionally update +4d, then use existing +51

Read dword p+19e. If nonnull, call `006c38c0(receiver; p)` and test **AX==1**. On that result, freshly load `s=s8(byte(dword(p+6d)+34))`, form integer `10*(s+15)`, multiply by K and add float32 p+4d. FST float32 writes p+4d while retaining the x87 result; compare that retained value with binary64 decimal10000 at968910. Ordered greater writes exact float32 decimal10000 (bits461c4000). Less, equal and unordered retain the first store. This route bypasses the p+19 and p+1f tests.

Otherwise, if signed byte p+19<0, leave +4d unchanged. If it is nonnegative, snapshot byte p+1f and freshly load s as above. Choose integer `12*s+325` when p+1f==ff, otherwise `10*(s+15)`. Multiply by K, add float32 p+4d and FSTP float32 to p+4d. **Reload the rounded float32 store**, then compare with10000 using the same ordered-greater cap. This differs from the retained-result comparison in the AX==1 route. These arithmetic expressions fit signed32 for all signed-byte s; no lower clamp exists.

Every zero-flag route now proceeds to the common tail. It does **not** copy the new +4d into +51. The tail reads the existing +51 independently.

### Nonzero flag: select a candidate for +51

Test signed byte p+20 first. If nonnegative, use it as c; otherwise test signed byte p+21 and use it when nonnegative. For either selected c, freshly load s from the profile and form integer A=`12*s+85`. If decimal46<=c<=64, the x87 candidate increment is `(c*C2-C3)*A*K`, with binary64 C2 at96d798 approximately5.56 and C3 at96d790 approximately255.76. Otherwise it is `A*K`. Add float32 p+4d and FSTP float32 to p+51.

If both bytes are negative, inspect signed byte p+19. When nonnegative, compute `A*K + float32(p+4d)` and FSTP float32 to p+51, with no c-dependent factor. When negative, copy the **raw dword** p+4d to p+51 and proceed directly to the common tail, bypassing the following check.

Each arithmetic route reads byte p+1c before the addition/store and tests that snapshot after storing +51. If it was nonzero, skip the lower-bound call. Otherwise freshly read p+69; if nonnull call `0062c590(dword(b63d28); pointer,0)`. Read signed AX; cap that integer above at decimal6500, sign-extend the resulting AX, FILD, and compare it with **the current float32 p+51 reloaded after the call**. If the integer is ordered greater than p+51, overwrite p+51 with exact float32 decimal6500 (bits45cb2000). Equality, less and unordered preserve the current field. The store is always6500, **not** the returned/capped threshold. Negative return values remain negative; there is no lower clamp on that threshold.

### Common tail and x87 limits

Read float32 p+59, then float32 p+51; add them in x87 and FST float32 to p+51 without popping. Compare the retained x87 result with10000; only ordered greater writes exact float32 10000. Less, equal and unordered retain the first store. The profile-null early return bypasses this tail entirely. The order is +4d/+51 branch work, possible `0062c590`, then +59 addition, then upper cap.

The comparison sequences use FNSTSW AX / TEST AH,41h: unordered has the tested bits set and therefore skips each overwrite. FILD converts signed32 scratch; all profile/selector arithmetic is signed-byte arithmetic widened before integer LEA/SHL operations. FMUL/FSUB/FSUBR/FADD/FIMUL operate with x87 intermediates under the actual control word; FST/P memory widths remain significant. The multiplier is explicitly rounded to float64, the main fields to float32. No control word is set or measured here. Precision, rounding, traps, denormals, signed zeros, overflow and NaN payload behavior have no numerical oracle. Natural-language min/max or ordinary JavaScript arithmetic does not establish equivalence.

There are six direct call sites but at most three calls on any normal local path: one mandatory probe after the initial profile guard, one conditional repeated probe, then either the tactical query or one lower-bound query. There is no local loop and no direct RNG. All three callees remain transitive state/RNG/failure boundaries. The input p, profile, p+69, global receiver and match receiver are not fully validated; aliases or calls can alter later fields/pointers. This report preserves fresh-load order rather than asserting a pure formula or stable input snapshot.

## `006c50d0`: select, position and traverse slot groups

Entry ECX=m; no stack arguments; plain RET at006c51de. EBX/EBP/ESI/EDI are saved/restored. No intended EDX parameter is established; residual high bits of EDX after preceding callees can reach a pushed coordinate argument. There is no normalized EAX return. PUSH ECX supplies a local dword; writing its low byte changes that local, so the final POP ECX yields the original m high24 bits with the saved side byte as its low8, rather than necessarily restoring m. ECX is caller-saved in this contract.

1. Snapshot side byte m+8eae into BL. The local dword initially contains entry ECX=m; overwrite its low byte with side and push that **whole dword** to `006ceb90(m; sideSlot,5,0)`. Thus sideSlot has low8=side, high24=high24(m); it is not a normalized or sign-extended side. Save full returned EAX as q without a null check, then call `006f0630(q)`.
2. The saved BL, unaffected by later match-field reloads, selects y: decimal10 when side==0, decimal1 for **every nonzero side**, includingff. NEG BL / SBB BL,BL / AND BL,f7 / ADD BL,a implements that choice. Write byte m+8ea7=4, then byte m+8ea8=y; call `006f46b0(q;4,ySlot)`. Only ySlot's low byte is assigned; its high24 bits retain entry EBX's high24 bits. The actual callee's prior static contract consumes low-byte x/y. There is no local q validity check or side0/1 restriction.
3. Iterate decimal20 times in ascending index i, interleaving side0 then side1 within each iteration. Let `q0=m+4796+i*1be`, `q1=q0+22d8`. m remains held in EDI and q in EBP; the stride/counter are held in ESI/EBX. Conditions below use fresh memory loads after earlier calls, assuming normal ABI preservation of these nonvolatile registers.

| Per-side predicate in order | Local relocation call |
| --- | --- |
| signed byte slot+19<0, or slot==q | Skip relocation |
| otherwise slot==dword(m+f59e) for side0 | `006f46b0(slot;4,0)` |
| otherwise slot==dword(m+f5a2) for side1 | `006f46b0(slot;4,11)` (decimal11) |
| otherwise signed byte slot+103<2 | `006f46b0(slot; low8(slot+102),2)` |
| otherwise signed byte slot+103>9 | `006f46b0(slot; low8(slot+102),9)` |
| otherwise (signed y in2..9) | Skip relocation |

The first pointer test is equality with the saved selection q, not an active-pointer reload. The special-slot pointers are read only after the signed-status and selected-slot guards pass. In the two variable-x side0 branches, MOV CL or MOV DL changes only a byte before pushing ECX/EDX; side1 uses MOV AL or MOV DL before pushing EAX/EDX. Their high24 bits remain residual. Special x=4 and every y constant in this table are full-dword immediate pushes. Each relocation receiver is recomputed or retained as the full slot pointer, independently of those partial x arguments.

After **every** side0 visit, call `007160e0(q0;0)`, even when signed status is negative or q0==q. Then process side1 and unconditionally call `007160e0(q1;0)`. Increment the stride only afterward. Thus every normal invocation makes exactly40 callback calls, three initial calls, and between0 and40 loop relocation calls: a conservative total43..83 direct calls. The seven call sites do not describe per-invocation call count. No callback result is tested, no direct RNG occurs, and exactly two explicit non-frame write sites exist in this local body. Call effects can be much larger.

Prior static contracts for `006f0630` and `006f46b0` describe active-slot writes and coordinate-cell membership updates, including their unresolved callees/diagnostics. `006ceb90` and `007160e0` are still call boundaries in this report. None of their execution is counted here. The fixed scan does not validate slot lifecycle, memory layout initialization, aliases between selected/match/slot objects, coordinate/list invariants, pointer validity or callee completion. A call can change subsequent predicates, including special-slot pointers and coordinates. Natural-language restart/goal identities are not inferred from coordinates alone.

## Reproduction and evidence boundary

Run `python scripts/extract_match_state_21.py PRIVATE_EXE --exports PRIVATE_EXPORTS_21B --preflight PRIVATE_PREFLIGHT_21B --output evidence/match-state-21-sites.json` with Capstone5.0.7. The extractor checks the pinned executable, manifest, preflight and all four exported-file sizes/digests, exact-old names/sites, all305 instructions/1043 bytes,49 branches,13 call sites,12 state stores, two returns and every normal ESP/x87 join. It records17+1 explicit frame-store sites and75+12 explicit memory-read sites; implicit PUSH/POP/CALL/RET stack traffic is handled by the stack analysis, not those operand lists. Its explicit integrity exceptions remain active under `python -O`. All evidence validates before the output is opened.

The [validation receipt](../evidence/match-state-21-validation.json) records deterministic normal/optimized regeneration, altered-specimen rejection, Node24 checks and privacy review. Those research checks exercise earlier retained primitives and metadata, not execution of these two bodies. The [findings](../evidence/match-state-21-findings.json) and [optional exact-old names](../evidence/match-state-21-annotations.json) are authored metadata. Original bytes, bulk exports/decompilation, game data and native project remain private. Shared coverage/checkpoint changes belong to the coordinator after review.

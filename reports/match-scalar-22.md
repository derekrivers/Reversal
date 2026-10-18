# R22-A: two scalar queries beneath match state update

Two complete local bodies at virtual addresses `0062c3d0` and `0062c590` were checked against the pinned 7,192,576-byte PE32 specimen, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Their raw file offsets are `0022c3d0` and `0022c590`. The read-only Ghidra 12.1.4/JDK21 exports came from independently reopened checkpoint 21, archive SHA-256 `bf4e1739d0c1ab1780fca5f95ec9bf0f9447d7cbe28520366a79aa36b6cc5971`; export manifest SHA-256 `a73c3300131cc5162d3f0122dd04d622fe6581505cea12c499ad4794ce79e239`. Neither native project nor shared registry changed in this branch.

`scripts/extract_match_scalar_22.py` checks specimen, manifest, preflight and every exported ASM/C digest before output. Capstone 5.0.7 decodes every byte of both original PE bodies, comparing each virtual address, mnemonic and operand with the native export. All branch successors remain inside the bodies; all instruction starts are structurally reachable. The compact [sites](../evidence/match-scalar-22-sites.json) list read/write widths, branches, calls, returns, x87 sites and body digests. Native decompilation is a clue only; widths and ABI below come from the matched instructions.

## `0062c3d0`: signed indexed WORD

This is a 36-byte, 12-instruction, call-free body. Entry ECX is the receiver; the full DWORD index is at entry ESP+4; both returns use RET4. It first reads that index, then the signed runtime DWORD count at `00ae2364`. `CMP/JL` admits only **signed index < signed count**. The other path returns EAX=0 and EDX=count without reading the receiver. There is no lower-bound check. Negative indices can proceed to a mapped table, or fault with an invalid one.

On the indexed path, EDX becomes `index*31` modulo 2³² using SHL5/SUB. It then reads the receiver's first DWORD and sign-extends the WORD at `table + EDX + 12` into EAX. EDX retains the displacement. ECX and nonvolatile registers are locally preserved. There are no stores, direct RNG sites or further calls. A signed AX consumer in the R21-B caller is consistent with this full sign-extended result, but caller state does not supply a global lower-bound guarantee.

The headless TypeScript implementation is [match-scalar.ts](../reconstruction/match-scalar.ts). It is checked against **274 complete original-instruction executions, 2,312 instruction steps and all 12 instruction starts**. Synthetic cases cover signed counts -5/0/1/5/20/100, indices -20 through 24, plus four boundary representations. Mapped negative-index table reads are intentional. The comparison checks EAX, EDX and direct read order; the native emulator also checks RET4, ECX/nonvolatile preservation, zero writes and the original trace. EFLAGS are outside the TypeScript comparison. Stable mapped memory is required; invalid pointers, aliases and concurrent mutation are excluded. The [oracle](../evidence/match-scalar-22-oracle.json) is synthetic numerical evidence, without game data or instruction bytes.

## `0062c590`: scaled pair with transitive/x87 boundaries

This is a 198-byte, 70-instruction body with nine local branches, three RET8 sites, two direct call sites and no direct nonframe stores or RNG sites. It saves ESI/EDI. Entry ECX is receiver, entry ESP+4 is a pointer and ESP+8 is a full DWORD flag. A null pointer clears **AX only** and returns; incoming EAX high 16 bits survive. For nonnull input it reads the first DWORD at the pointer and compares it as signed with the same runtime count. At or above count, zero flag returns 10000 and nonzero returns 100. A negative index is not rejected.

For an admitted index, the body calls `0062c400` with the pointer and receiver, saving its AL result. It freshly reads the receiver's first DWORD. Two signed WORDs at offsets `index*31+10` and `index*31+8` are sign-extended and multiplied as 32-bit integers. The subsequent signed `IMUL` with immediate `0x68db8bad`, arithmetic right shift by 12 and sign adjustment form a quotient-like EDX; any overflow and rounding claim must follow those exact instructions. When saved AL is one and signed **DX** is at least 9000, EAX becomes 9000. Otherwise signed **DX** above 100 selects the full EDX; at or below 100 selects EAX=100. Tests use the low signed 16 bits even when the selected value is the full 32-bit register.

If the flag is nonzero, signed AX is stored in the reused stack argument slot, loaded with FILD, multiplied by the original float32 constant at `0096bac8` (approximately 0.0099999997765), then added to float64 0.5 at `00968968`. It calls `00945640` (`__ftol` in native context); signed AX above 100 is capped by replacing EAX with 100. The callee's exact conversion, x87 control word, possible exceptions, and high EAX bits on other paths have **no execution oracle here**. `0062c400` and `00945640` are transitive state/failure boundaries. This body remains a static local contract, without a TypeScript port.

Both bodies read runtime `00ae2364`; it resides outside a raw PE section and has no inferred file-initialized value. The report does not establish a connected slot lifecycle, float equivalence or match outcome. Original bounds and guards do not prove live pointer validity.

## Reproduction and negative checks

With Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.19.0:

```text
python scripts/extract_match_scalar_22.py EXE --exports EXPORTS_22A --preflight PREFLIGHT_22A --output sites.json
python scripts/emulate_match_scalar_22.py EXE --exports EXPORTS_22A --preflight PREFLIGHT_22A --output oracle.json
node reconstruction/check-match-scalar.ts evidence/match-scalar-22-oracle.json
python scripts/check_match_scalar_negative_22.py EXE --exports EXPORTS_22A --preflight PREFLIGHT_22A --node NODE24 --oracle evidence/match-scalar-22-oracle.json --output negative.json
```

Normal and `python -O` executions produce byte-identical site and oracle JSON. In each mode, a one-byte specimen mutation, a manifest mutation and a resealed native-operand mutation are rejected before evidence output. A changed TypeScript WORD read fails the retained oracle check. See [negative checks](../evidence/match-scalar-22-negative.json). The proposed native names and validation registry entry are review-only; the coordinator owns their acceptance and integration.

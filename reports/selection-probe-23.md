# Investigation 23-C: mode-5 record probe

`00601070` is a complete **local static** 399-byte body at virtual address `00601070` (PE raw file offset `0x201070`). The pinned 7,192,576-byte PE SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All 121 decoded original x86 instructions match address, mnemonic and operands in the read-only checkpoint-22 Ghidra export. The [site evidence](../evidence/selection-probe-23-sites.json) records its ten local branches, four direct callee targets, one direct nonframe store and two `RET 8` sites. The native project and original executable remain private. All addresses in this report are virtual unless explicitly called a file offset.

The R22 selected-slot routine `006ceb90` calls this body in mode 5. That caller uses a byte-sized probe counter, but its other service calls, candidate state, score and RNG effects are separate boundaries. This local body alone cannot establish connected selection behavior.

## Entry, lookup and returns

Entry `ECX` is a receiver pointer. `[entry ESP+4]` supplies a dword whose **low byte** is the signed field index; `[entry ESP+8]` supplies an optional full record pointer. Both ordinary returns clean eight argument bytes. EBX and ESI are saved/restored, while EBP and EDI are untouched. EAX is the result; ECX and EDX are scratch and can differ at return. The ordinary no-callee path has no nonstack writes. All pointer accesses require valid mapped storage; no complete pointer or alias validation occurs in this body.

If the record argument is zero, the routine sign-extends the word at `00b77c7a` and loads a fallback dword pointer from `00b74c26 + 0x300 * signed_word`. If that pointer is also zero, it enters a diagnostic path. This exact displacement comes from `LEA index,index*2; SHL 8` and is not an array-element count inferred from pseudocode.

For a nonzero record pointer, the body reads its first dword and computes signed 32-bit `slot = (record[0] - dword[00ae2364]) + 16`. Negative `slot` and `slot > signed(dword[ECX+4]-1)` enter a diagnostic. This is an upper bound relative to the receiver count, with no separate positive-count or overflow guard. The low byte of the first stack argument must be signed `0..49`, otherwise the field diagnostic runs.

The body loads receiver base `dword[ECX]`, then reads a signed status byte at `base + slot*0xa6ef + 0x9a69`. Status byte `1` is changed to `0`; other byte values keep their signed interpretation. It reads a dword identifier at

```text
base + slot*0xa6ef + 0x1e05 + adjusted_status*0x1ecd + signed_field*4
```

Identifier `0xffffffff` returns EAX zero through `006011fc`, without reading output base `00ae23bc`. Every other identifier loads that output base and returns `output_base + identifier*0x6e` modulo 32 bits at `00601163`. There is no local range check on other identifiers or the resulting pointer. The calculation constants, signed status treatment and sentinel distinction are established from complete original operands, not a decompiler type assumption.

## Diagnostics and execution scope

Missing fallback pointer, invalid slot and invalid field each call `00944cff`, followed by `0090d130`, `00944c9f` and `005e8290` through a shared tail. If those calls return, the body writes zero to global dword `00b67a34` and returns EAX zero. The three entry paths pass different immediate codes `0xbf6`, `0xc02` and `0xc09` to `0090d130`. Call order and local stack setup are static facts; formatting, logging, callback, failure and process effects remain callee boundaries. The `0xffffffff` identifier takes the other `RET 8` path without any diagnostic call or global clear.

The [headless TypeScript](../reconstruction/selection-probe.ts) implements only the bounded **no-callee** direct/fallback lookup path, including successful pointer and `0xffffffff` return. The [original-instruction oracle](../evidence/selection-probe-23-oracle.json) executes the complete body entry-to-return in Unicorn 2.1.4 using synthetic, stable, disjoint mapped pages. Its 288 whole-function cases execute 16,200 instruction steps, touch 66 of the 121 instruction starts and all eight conditional branch sites. The fixture covers direct and fallback pointers; slots 0, 1 and 3 of count 4; status bytes 0, 1, 2 and `0xff`; fields 0, 1 and 49; and identifiers `-1`, 0, 5 and 65535. The checker independently derives EAX, ECX, EDX, ordered nonstack reads and taken branch destinations. The emulator also checks `RET 8`, nonvolatile registers and no nonstack writes. Original oracle SHA-256 is `df379919c89eb91a66fd300cc76219fb22dfe16c26b159d3f08909838bb6c7ac`.

This validation does **not** cover diagnostics, invalid/unmapped pointers, unstable or aliased memory, other status/count/identifier extremes, EFLAGS, transitive callee effects or the R22 caller. In particular the 66 executed starts must not be reported as validation of all 121 instructions. The static mapping covers all 121 original/native instructions separately.

## Reproduction

Run `scripts/extract_selection_probe_23.py` with the pinned private PE, `private-native-verify/exports-23` and `private-native-verify/annotation-preflight-23.json`. Run `scripts/emulate_selection_probe_23.py` with the same inputs, then `node reconstruction/check-selection-probe.ts evidence/selection-probe-23-oracle.json`. The extractor checks specimen size/hash, native manifest/file hashes, exact-old preflight, every instruction/operand and local CFG before writing evidence. Normal and optimized Python extraction have identical outputs; both reject changed specimen and native operands without an output file. Normal and optimized oracle outputs also hash identically. The TypeScript checker fails a record-ID mutation at the first affected case. [Validation receipt](../evidence/selection-probe-23-validation.json) records the extractor integrity results. `npm run check` verifies the repository's prior retained units separately; the shared check runner is owned by the coordinator and has not yet incorporated this proposal.

Suggested exact-old name: `probe_mode5_record_00601070` replacing `FUN_00601070`, at high confidence for the local probe mechanics and only bounded confidence for the record's wider meaning. The coordinator decides whether to apply it after independent review and native preflight.

# Investigation 23-B — exit callback and dispatch bodies

The pinned PE32 x86 image is 7,192,576 bytes, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses in this report are **virtual addresses** unless explicitly called file offsets. Both complete local bodies, 179 bytes and 61 original instruction rows, match the read-only checkpoint-22 Ghidra export by address, mnemonic and operand. This is a **static local contract**; there is no original-instruction execution oracle or TypeScript unit for these import/callback-dependent bodies.

| Body | File offset | Size / rows | Local role |
| --- | --- | ---: | --- |
| `00945956` | `00545956` | 153 / 49 | Update exit state, dispatch callback groups and imported process APIs |
| `009459ef` | `005459ef` | 26 / 12 | Invoke nonnull callback slots over an unsigned half-open pointer range |

## `00945956` entry, state and exit routes

The body has three caller-pushed dword arguments and a plain `RET`, so the caller retains the 12 argument bytes on an ordinary return. At entry, before either callback group, it compares the **dword** at `00de2fd4` with 1. If equal, it pushes argument 1 as an exit code, calls the IAT slot `0096716c` (`KERNEL32.dll!GetCurrentProcess`), pushes that returned EAX handle, then calls `00967168` (`KERNEL32.dll!TerminateProcess`). The import identities were read from the pinned PE import directory, not inferred from decompiler names. The assembly contains no test of `TerminateProcess`'s result; if that call returns, execution continues at `00945973`. Thus even this reentry route cannot be described as unconditionally nonreturning from the local body alone.

The next comparison tests argument 2 against zero. It saves EBX, loads argument 3 into EBX, writes **dword 1** to `00de2fd0`, then writes the **low byte** of argument 3 to `00de2fcc`. These are the only two direct global writes before callbacks. The intervening PUSH/MOV instructions preserve the flags from the argument-2 comparison, so `JNZ 009459c7` skips the first two callback groups when argument 2 is nonzero. The dword at `00de2fd0` and byte at `00de2fcc` are distinct direct write sites; their larger surrounding global layout is not recovered here.

When argument 2 is zero, the body first checks the dword lower-bound pointer at `00de4638`. If nonzero, it loads the upper-bound pointer from `00de4634`, starts at `upper-4`, and compares unsigned against the lower bound. It reads each dword callback slot in **descending address order**, calls a nonnull pointer through EAX, decrements by four, and compares the next pointer unsigned against a **fresh read** of `00de4638`. The upper-bound value is loaded only once for this pass; callback behavior could mutate the lower bound, table contents or process state. The code assumes callback ABI behavior sufficient to continue using saved ESI and EBX, but does not validate callback pointers or enforce that behavior.

After that dynamic pass, `00945956` calls `009459ef` for the two dword slots in `[009870bc,009870c4)`, with stack arguments cleaned locally by two POPs. Regardless of argument 2, it then calls `009459ef` for the two slots in `[009870c8,009870d0)` and cleans those arguments. Within each fixed group, callbacks run in ascending slot-address order; the dynamic group is first, the first fixed group second, and the second fixed group last, provided every invoked callback returns ordinarily. Null slots are skipped. The static image proves the two fixed table *ranges* and order, not the runtime contents or callback effects.

Finally the body tests the full dword argument 3, restores EBX, and returns through `009459ed` if it is nonzero. If zero, it pushes argument 1, writes **dword 1** to `00de2fd4`, and calls the IAT slot `00967164` (`KERNEL32.dll!ExitProcess`). The saved EDI is popped and a plain `RET` remains at `009459ee`; that continuation is reachable if the imported call unexpectedly returns. The body does not set a defined EAX result for its ordinary-return route. EAX can reflect a callback or import result, and no caller-visible return value is claimed. A nonzero argument 3 can still encounter the earlier reentry `TerminateProcess` call when the entry global equals 1.

The R22-D `00945934` wrapper is caller context: it passes `(original_arg,0,0)` to this body. Consequently its ordinary route selects all callback groups and reaches the `ExitProcess` call if callback/import execution proceeds normally. The wrapper's own `RET` and this body's post-import `RET` mean that earlier nonreturn annotations should be understood as intended operating-system behavior, not a proof of termination in every environment. Neither callback transitive effects nor diagnostic caller continuation is included in this local contract.

## `009459ef` callback range

The helper takes start and end pointer dwords from the caller stack, saves ESI, and loads start into ESI. At each iteration it compares ESI with the end argument **unsigned**; `JNC 00945a07` returns when start is at or above end. Otherwise it reads a dword callback pointer at `[ESI]`, calls it through EAX if nonzero, adds four to ESI, and loops. It performs no direct nonframe memory write and has no explicit validity, alignment, overflow or callback-signature check. The end argument is reread from the stack each iteration. The helper returns by `POP ESI; RET` with caller-owned argument cleanup; EAX is not assigned a stable result. A callback that does not return prevents the remaining slots and the helper's return. An invalid pointer or nonconforming callback falls outside the admitted ordinary local path.

## Evidence and limits

The extractor pins the specimen, private checkpoint-22 archive SHA-256 `ea4c9888f34fe4282434e41a38e842cabec61ded30d064d0417a166e18f7fcc2`, read-only export manifest SHA-256 `b8d302c629ba6fbb98cb45315ee5df6f238b5b9a8e02a1c8220db3e2f384844d`, preflight SHA-256 `c7128da6c29d92931c1e096fc17112f28b73a4cd0276f7869e80a6800aee9e3a`, all exported file hashes, exact-old names and lengths. It decodes all 61 instructions from original PE file bytes and checks every native operand, the complete branch and call sets, direct global write widths and IAT identities. [Compact sites](../evidence/exit-runtime-23-sites.json) contain addresses and hashes but no executable or bulk native bytes.

Normal and `python -O` output is byte-identical: sites SHA-256 `e26c42aadc1420ff0f555ddf8d8c0f579ea81c91b41299bf2ba295da0cdd61fb`; the [negative receipt](../evidence/exit-runtime-23-negative.json) records its current digest. A changed executable byte is rejected before output; self-consistently rehashed native export changes to a global-write width and an IAT call operand are independently rejected by the PE/native comparison. The four immediate `PUSH` operands that supply both callback ranges are explicitly checked before the ranges are emitted; a deliberately wrong expected range is rejected by the negative runner. The research checks pass under direct Node v24.19.0 and `npm run check` with system Node v22.20.0; those retained checks do not execute these two functions. Optional exact-old name proposals are [separate](../evidence/exit-runtime-23-annotations-proposal.json) for coordinator review.

```powershell
python scripts/extract_exit_runtime_23.py <private-cm0102.exe> --exports <private-exports-23> --preflight <private-annotation-preflight-23.json> --output evidence/exit-runtime-23-sites.json
python scripts/check_exit_runtime_23_negative.py <private-cm0102.exe> --exports <private-exports-23> --preflight <private-annotation-preflight-23.json> --output evidence/exit-runtime-23-negative.json
python -O scripts/extract_exit_runtime_23.py <private-cm0102.exe> --exports <private-exports-23> --preflight <private-annotation-preflight-23.json> --output <private-temporary-output>
npm run check
```

No guaranteed process termination under all environments, callback equivalence, connected match behavior, UI or game reconstruction follows from these static bodies.

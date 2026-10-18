# Three common unwind targets: local contracts

The investigation-15 unwind census found 3,873 short frame-dependent bodies. **3,410** of those entries directly target one of three small functions mapped here: `005a53c0` (1,711 entries), `00944c94` (1,462) and `00682300` (237). These counts are static direct-target counts, not dynamic call frequencies or recovered parent-frame behavior. Each target's complete local body was independently decoded from the pinned PE and compared instruction-for-instruction with a Ghidra 12.1.4 read-only export from checkpoint 15.

## `005a53c0`: one-instruction no-op return

The entire function is one byte and one `RET`. It has no explicit state access, direct call, argument use or callee cleanup. Its use as the callback literal at `0068233c` is visible in the latter body, but callback invocation conditions inside `009462bb` are unresolved. The 1,711 direct unwind entries that target this function therefore have a trivial direct target; each entry still depends on a valid surrounding EBP frame and its own path conditions.

## `00944c94`: one-argument forwarding wrapper

Four instructions push the caller's one stack dword, call `009452ca`, discard the forwarded dword with `POP ECX`, then return. The wrapper itself does not inspect or mutate the pointed-to object. `009452ca` may release storage, but its body is outside this assignment, so the transitive effect is unresolved. The wrapper is called directly by `00682300` after its array-helper call, and by 1,462 unwind entries.

## `00682300`: object cleanup sequence

The 115-byte body contains 34 instructions. It installs an FS:[0] exception frame, saves ESI, writes dword `0096d020` at receiver `ECX+0`, and reads a pointer at receiver `+0xea`. If that pointer is nonzero, it reads a dword at pointer `-4`, then calls `009462bb(pointer, 0x10, [pointer-4], 005a53c0)` in the original stack order. Afterward it calls `00944c94(pointer-4)`. On both pointer paths it calls `0048c650` with the receiver in ECX, restores the exception frame and returns. The body does **not** clear receiver `+0xea`; no safe reuse claim follows from this function alone.

The constant `0x10` is the supplied element stride, and the leading dword is used as a count by the call site. `009462bb` and `0048c650` remain opaque direct dependencies: this report does not assert how many callbacks actually run, whether a callback throws, how storage is released, or what base cleanup changes. The FS:[0] handler target and exceptional unwind path are outside the normal-return contract. The `0096d020` write is a pointer-like constant consistent with a vtable reset, but the original class identity is not established. The function's direct calls are at `00682345`, `0068234b`, and `0068235e`.

## Reproduction and scope

[`extract_unwind_targets_16.py`](../scripts/extract_unwind_targets_16.py) checks the pinned specimen hash, all three atlas spans and original body hashes, every decoded instruction against the private native export, exact direct targets, and the 3,410 direct unwind-target count. Its compact [evidence](../evidence/unwind-targets-16.json) records sizes, hashes, selected instruction sites and calls without executable bytes or bulk assembly. The private export manifest SHA-256 is `aa9c7d6c9c9cd06d5dfe8de02c75ac561737f26cc1fcf36930e1149881ad35fb`; the private exact-old-name preflight SHA-256 is `12d10d6ba68468a8b44f3756f7ac638758fa82523cb7685df16db742548cb93d`. All three names are still `FUN_*` in checkpoint 15, with entry instructions present.

Run with Capstone 5.0.7:

```powershell
& <Capstone-Python> scripts/extract_unwind_targets_16.py --binary <private-exe> --atlas evidence/code-atlas/functions.jsonl --unwind evidence/unwind-family-15-rows.jsonl --exports <private-exports> --preflight <private-preflight> --output evidence/unwind-targets-16.json
```

This is full **local static** coverage for three targets. The 3,410 caller stubs remain a mechanical frame-dependent population, and the called cleanup/free/base functions remain to be reversed. No game, database or match behavior is inferred from their large fan-in.

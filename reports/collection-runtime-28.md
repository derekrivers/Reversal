# R28-C — collection-node copy and CRT allocation boundary

This unit maps two complete **local static** bodies: `0068cfc0`, a 14-byte-node copy constructor used below R28-B, and the existing CRT `operator_new` wrapper at `00944cf1`. No original-entry execution validation or TypeScript port is claimed. Both bodies call an allocator on every entry path. `00944e58` (`__nh_malloc`) is verified as read-only context, not counted as a new contract.

All addresses are **virtual** unless labelled as PE file offsets. The pinned 7,192,576-byte PE32 x86 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The private checkpoint-27 archive SHA-256 is `d2836fd1b28d194dbfda32454106f9af23495809f09a408ed1ee072e6c4b7de1`. Selected native export manifest SHA-256 is `058514c602952b66abeade64ba9a28bbab3873c16503af4ca0f834fb2a6d2ddc`; exact-old annotation preflight SHA-256 is `9f9e52088fc32356aebecb6fc39ba78fea96e14f359383afb01362287409fbb2`.

| Entry | PE file offset | Bytes | Body SHA-256 | Instructions | Local CFG edges | Scope |
| --- | --- | ---: | --- | ---: | ---: | --- |
| `0068cfc0` | `0028cfc0` | 66 | `b1f19b94907f9c8127303801a0278fbdb1cbb453b4a5980d2679f2bd7a23e15d` | 28 | 27 | New local static contract |
| `00944cf1` | `00544cf1` | 14 | `1a3e6f3fdb89b0d6c9d0f1236df07539e1fc039ddc634fc7486c6469fb61a4f8` | 6 | 5 | New local static contract; preserve CRT name/comment |
| `0068d0d0` | `0028d0d0` | 221 | `03091edb8004d3279cfa7588b2e1386cdadad6fd0d3bf124d2847273d0bc002a` | 71 | 73 | Read-only caller context |
| `00944e58` | `00544e58` | 44 | `a820b9f2f0d73f39f7f7f4769451dca7458d287496d2c367daf94b52d0d74477` | 16 | 19 | Read-only callee context |

The [extractor](../scripts/extract_collection_runtime_28.py) pins specimen, checkpoint, all 14 export files, old native identity/body sizes and original CRT comment hashes. Capstone 5.0.7 decodes every original PE byte of these four contiguous spans, including the full `0068d0d0` caller, and matches every native instruction address, mnemonic and operand. It checks all local CFG edges, reachability and exact direct-call targets. [Compact site evidence](../evidence/collection-runtime-28-sites.json) records spans, operand widths, calls and hashes without shipping original code bytes or bulk decompilation. Its explicit integrity gates work under normal and optimized Python.

## `0068cfc0`: node construction with copied payload

The receiver is in ECX. Entry `[ESP+4]` is a DWORD source pointer. The low 16 bits of entry `[ESP+8]` are a signed length: `MOV DI,word ptr [ESP+0x14]` after three saves and `MOVSX ESI,DI` at `0068cfc8`. The routine saves/restores EBX, ESI and EDI; `RET 8` removes two DWORD caller arguments. On an ordinary return EAX is the original receiver. ECX and flags are volatile; the body does not preserve them.

The exact local order is:

1. Read the length WORD, sign-extend it to a DWORD, and copy the receiver to EBX.
2. Push the sign-extended length at `0068cfcf`.
3. Zero receiver DWORDs `+0xa` and `+6` in that order (`0068cfd0`, `0068cfd3`). These writes occur **before** the allocation call.
4. Call `00944cf1` at `0068cfd6` with the already-pushed length.
5. Write the original low-16 length at receiver `+4`, read the source pointer from the original first argument, and write allocator EAX at receiver `+0` (`0068cfdb..0068cfe5`).
6. For a nonnegative length and clear direction flag, `REP MOVSD` at `0068cfee` copies `length >> 2` DWORDs, followed by `REP MOVSB` at `0068cffa` copying `length & 3` bytes. The code adds 4 to ESP between the string operations to remove the allocation argument. It writes no terminator.

The native pseudocode's `undefined4 *` source type does not imply a DWORD-aligned or DWORD-sized payload: the tail operation copies 1–3 bytes. The source, allocated payload and receiver are distinct roles in this function, but disjointness and valid ranges are **caller preconditions**, not checks in the body. The length parameter is signed16, yet the copy count uses logical `SHR`; a negative length becomes a very large unsigned allocation/copy request. There is no negative-length guard, no null allocator-result guard, and no local exception cleanup. DF is not cleared by this body; forward-copy interpretation requires DF=0. Aliasing may affect byte values and observation order.

The read-only caller `0068d0d0` pushes `0xe` once at `0068d0e9`, before the branch at `0068d0ef`. Each arm calls `operator_new` (`0068d0f1` or `0068d137`), tests the returned pointer (`0068d0fd` or `0068d143`), then conditionally calls `0068cfc0` with that nonnull node pointer in ECX (`0068d115` or `0068d15b`). Its entire 221-byte body now matches the pinned PE/native instructions, operands and local CFG; a resealed wrong `PUSH 0xe` operand is rejected. This supports a 14-byte node interpretation with payload pointer `+0`, length WORD `+4`, and link DWORDs `+6/+0xa`; the R27-A iterator later reads those link offsets. The caller's SEH state, insertion and subsequent ownership/release paths are R28-B and later work. These instructions alone do not prove who frees the node or payload.

## `00944cf1`: existing `operator_new` wrapper

This six-instruction cdecl wrapper takes a DWORD size at entry `[ESP+4]`. It pushes constant `1`, then pushes the caller's size from `[ESP+8]` after that first push. At `00944cf7` it calls `00944e58` with `(size,1)`. Two `POP ECX` instructions remove its outgoing arguments, and a plain `RET` leaves caller cleanup of its own size argument. EAX is returned from `__nh_malloc`; ECX is clobbered by the POPs. There is no direct heap access, branch or allocation-result check in this wrapper. Preserve Ghidra's existing `operator_new` name and Visual Studio 2003 library comment.

The 44-byte `__nh_malloc` context body has an unsigned size guard at `00944e58..00944e5d`: sizes greater than `0xffffffe0` return zero; permitted sizes call `00944e84`, and a zero result with nonzero flag can call `0094895b` and retry. Those two callees and any OS allocation, new-handler effects or exceptions are not mapped here. The existing `__nh_malloc` name/comment are likewise preserved.

## Validation boundary and follow-up

An original-entry TypeScript port is not admitted here. There is **no call-free path** through either target, including zero-length input to `0068cfc0`. A faithful original-entry comparison must model allocator return and side effects, possible handler retry/exception, resulting buffer mapping and then ordered constructor writes/copy/ABI. Returning from a stub would not validate the actual transitive behavior. The [structured findings](../evidence/collection-runtime-28-findings.json) record zero executed cases explicitly.

The [negative receipt](../evidence/collection-runtime-28-negative.json) covers eight probes: changed PE, native export, manifest and preflight, then independently resealed wrong constructor operand, wrong wrapper call target, wrong caller allocation-size operand and changed existing library comment. The first four fail integrity checks; the resealed probes reach and fail semantic comparisons. [Validation metadata](../evidence/collection-runtime-28-validation.json) retains the byte-identical normal/`-O` output hashes and Node 24.19.0 repository check result. The repository check does not run this private-input extractor. The sole [native proposal](../evidence/collection-runtime-28-annotations-proposal.json) is a name-only change for `0068cfc0`, from exact-old `FUN_0068cfc0` to `cm0102_construct_collection_node_copy_candidate`. The coordinator must review and apply it; no native project was changed here.

Reproduce with the pinned private inputs:

```text
python scripts/extract_collection_runtime_28.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_28 --preflight PRIVATE_PREFLIGHT_28 --output results/collection-runtime-28-sites.json
python -O scripts/extract_collection_runtime_28.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_28 --preflight PRIVATE_PREFLIGHT_28 --output results/collection-runtime-28-sites-optimized.json
python scripts/check_collection_runtime_28_negative.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_28 --preflight PRIVATE_PREFLIGHT_28 --output results/collection-runtime-28-negative.json
python -O scripts/check_collection_runtime_28_negative.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_28 --preflight PRIVATE_PREFLIGHT_28 --output results/collection-runtime-28-negative-optimized.json
npm run check
```

Static contracts here do not establish the connected collection merge, allocation success, payload lifetime or complete game reversal.

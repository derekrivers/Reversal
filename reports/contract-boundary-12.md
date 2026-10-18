# Contract manager row lifecycle boundary, investigation 12

`004c7560` initializes a manager's staff-contract row collection from global source records. `004c79a0` supplies a row index by optional sentinel reuse or append, growing storage by 200 rows when count equals capacity. This is a static allocation and state boundary, supported by the diagnostic names and original instructions; it does not recover contract negotiation, monetary units or persistent financial effects.

The specimen is SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; worktree baseline is `a5972e1659afa4b2937490cdc57ebd8f4a5887d3`. Addresses are virtual addresses. `+` offsets are hexadecimal bytes. Owned bodies are `004c7560..004c7944` (997 bytes, file offset `000c7560`) and `004c79a0..004c7abd` (286 bytes, file offset `000c79a0`). Names and layouts remain research labels.

## Entry, caller and partial layout

The initializer takes ECX as receiver, saves it in EBX at `004c757c`, and uses no stack argument. It saves/restores EBX/ESI/EDI and conditionally EBP, restores FS:[0], and returns with plain `RET` at `004c7944`. No meaningful EAX return is established. There is no receiver null/extent check. Exception registration and local construction stages are present; unwind bodies are outside scope.

The supplied reference export lists one incoming call, `00829809` in setup `00828110`. The selected original caller instructions request `0x3c` bytes through `00944cf1` at `008297cc`, conditionally call `004c7040` with the allocation in ECX and EBP as a raw32 argument at `008297ea`, publish EAX to DWORD `00ae1050` at `008297fc`, and, when the EAX-versus-EBP comparison permits, pass EAX in ECX to the initializer. EBP was zeroed at `0082876e`; independent decode finds no later explicit EBP writes before this call. Under the observed nonvolatile-register convention, both checks are null checks and the constructor argument is zero. Opaque callees' register preservation, complete setup flow and `004c7040` constructor effects remain outside scope. A nonnull constructor result is not proof of complete manager validity.

| Manager offset | Width | Supported role |
| --- | --- | --- |
| `+0` | DWORD pointer | Base of rows, each `0x50` bytes. |
| `+4` | DWORD | Capacity in rows, initially copied from DWORD `00ae2364`. |
| `+8` | DWORD | Appended extent/count, cleared only after initial allocation succeeds. |

`004c79a0` takes this receiver in ECX (retained in ESI) and one raw32 flag at entry ESP+4 (`004c79a0`). It returns a raw32 index or `0xffffffff` through EAX, preserves ESI, and uses `RET 4` on both exits. Zero flag enables reuse; any nonzero flag skips it. Both inventoried call sites (`004c7873` and dependency `004c7955`) pass 1. No observed zero-flag caller is claimed.

Useful preconditions are writable manager storage; valid initialized global tables; valid `0x6e`-stride source records and `0x4f`-stride auxiliary records; and a consistent nonnegative count/capacity with sufficient mapped rows. The code does not validate these extents, lower-bound source IDs, multiplication overflow or arbitrary allocator inputs. Global count and auxiliary base are reloaded during the scan, so a stable snapshot cannot be assumed without caller/callee evidence.

## Initial allocation and source scan

The routine first constructs a stack temporary through `0085e410` (`004c7587`), then copies global DWORD `00ae2364` to capacity (`004c759a`). It requests `count*0x50` bytes with 32-bit LEA/SHL arithmetic at `004c759d..004c75a4`. The returned pointer is stored at manager `+0` (`004c75ae`). A null result enters diagnostic calls labelled `CONTRACT_MANAGER::initialise_all_staff_contracts()` with source line `0xd7`; if they return, the routine returns without clearing manager `+8`. Existing manager storage is not freed by this owned body before replacement. This supports a fresh/setup lifecycle hypothesis, not safe repeated initialization.

After nonnull allocation, manager `+8` is cleared (`004c7645`). A signed-positive global-count test admits a scan starting at pointer DWORD `00ae23bc`. Each iteration does the following:

1. Clear bit 7 in BYTE `auxiliary_base + scan_index*0x4f + 0xb` at `004c7671..004c7678`. This uses the scan index, whereas later index publication uses the source record's DWORD ID.
2. Call `004d0c60` with ECX=manager and logical stack arguments `(source, source.DWORD+39, 1, -1, 0)` at `004c7683`. Save its raw32 EAX result to unaligned source DWORD `+52` at `004c768b`. The callee's meaning, writes and RNG are unresolved.
3. Conditionally update two eight-byte date-like source groups at `+46` and `+31` through `00417c10`. The following section bounds those calls.
4. Admit a row only when source DWORD `+39` is nonzero and BYTE `+3d` belongs to `{0,6,7,8,9,10,11,12,13,15}` (`004c7832..004c7866`). Request append mode with flag 1 at `004c7873`. A nonnegative signed EAX result publishes that index to DWORD `auxiliary_base + source.DWORD+0 * 0x4f` (`004c788e`), publishes the source ID to DWORD `manager.rows + index*0x50` (`004c789b`), and calls `0085e960` with ECX pointing to that row and `(source, source.DWORD+52)` as two raw32 arguments (`004c78a2`). Its selected return is `RET 8`; its complete 3,647-byte body, allocation, row writes and RNG are dependencies.
5. For the same admitted source class, nonzero source DWORD `+61` admits the BYTE `+3a` update described below, including when row allocation returned negative.

The loop increments scan index, auxiliary offset by `0x4f`, and source pointer by `0x6e` at `004c7915..004c7919`; its signed comparison uses a freshly loaded global count (`004c790f`, `004c791c`, `004c7926`). No complete source-record schema is inferred.

## Date-like state and RNG boundary

For nonzero source DWORD `+39`, `00549ef0` receives low16 arguments `0x1f` and `0x76c`; selected dependency instructions store WORDs at temporary `+0/+2` and a DWORD at `+4`. The owned routine compares only the first two WORDs with source `+46/+48` (`004c76b2..004c76cb`). Equality admits `0054a110`, `00669bd0(source.+39,0,temp)`, `0054c5b0(...,10)` and `0054cfb0`. The latter's AL supplies a BYTE local. Two direct calls to the already named bounded random helper follow, with bounds 6 (`004c772d`) then `0x1c` (`004c7745`), and results feed `00549f70`. The second result is incremented in AL and sign-extended into CX (`004c774d..004c774f`), preserving the other register bits. The year-like seed is written as a WORD from `00ae2c92`, and the AL-derived local as a BYTE, but the subsequent stack loads are DWORDs (`004c7732`, `004c773d`). Those locals' upper bytes are not proven initialized here; no full32 cleaned-value claim is made. `00549f70` consumes four stack arguments and has selected `RET 0x10` at `0054a10b`.

After equality handling or bypass, `0054c770` receives ECX=`00dd6ec8` and value 8 at `004c7779`. Its result WORD `+2` is compared unsigned with source `+48`; equality then compares result WORD `+0` signed with source `+46` (`004c7794..004c77a5`). A greater result calls `0054c770` again with ECX=`source+46` and value `0x34`, assigns that result back to `source+46`, then jumps back to the comparison (`004c77be`). Termination depends on the helper; a single clamp or fixed number of calls is not established.

Independently, nonzero source DWORD `+24` admits a second `00549ef0(0x1f,0x76c)` comparison with source WORDs `+31/+33`. Equality calls bounded RNG with bound 5 at `004c7807`, adds its result plus 1 to a DWORD stack load whose low WORD was copied from `00ae2c92`, and calls `00549f70(10,5,derived,-1)` then `00417c10` on `source+31`.

Selected original `00417c10` instructions show exact destination writes: WORD `+2`, WORD `+0`, DWORD `+4` (`00417c1d..00417c2e`), followed by an eight-byte copy to its output temporary and `RET 8`. Thus these are eight-byte source mutations, including the derived DWORD at each group `+4`; the equality/comparison gates inspect only the first two WORDs. Calendar interpretation is suggested by `Date.cpp` and constants, but full calendar/helper behavior is unassigned. The direct RNG sites and their order are established; total scan RNG is unresolved because `004d0c60`, the date-related helpers and `0085e960` are opaque here. A mapped instruction site is not proof of runtime reachability or a draw count.

## Reserve/reuse and allocation failure

With flag zero and signed-positive count, `004c79a0` scans `[0,count)` at stride `0x50`, returning the first row whose first DWORD equals `-1` (`004c79bc..004c79cb`). This return does not initialize or mark the row, increment count, or change capacity. Reuse therefore requires the caller to populate/claim it; no concurrency protocol is recovered.

After bypassing/exhausting reuse, equality of DWORD count and capacity (`004c79d3`) triggers growth. Capacity is incremented by `0xc8` and stored **before allocation** (`004c79dd`, `004c79e4`). A nonnull old base calls `00945667(old_base,new_capacity*0x50)` at `004c79f1`; a null base calls known `_malloc` at `004c7a02`. `00945667` is a realloc-like dependency, not fully audited. The result overwrites manager `+0` at `004c7a0c` before its null check at `004c7a0e`. Null diagnoses `get_free_staff_contract_space()` at source line `0x175` and, if diagnostics return, sets EAX=`-1` at `004c7a9b`; count remains unchanged, increased capacity remains stored, and the old base is no longer retained by this body. Whether the allocator frees or preserves its old allocation is unresolved. There is no explicit rollback/free in either owned body.

When count differs from capacity, the helper appends without checking `count < capacity` or base validity. On successful growth or growth bypass it returns the old count and stores count+1 (`004c7aa8..004c7ab1`); it does not initialize the row. These arithmetic operations wrap at 32 bits and lack an overflow check. This is a row reservation primitive under a valid-state precondition.

The initializer tests a reserve result signed-negative at `004c7878..004c787a`, skipping publication/row construction on failure but continuing at `004c78a7`. With source `+61` nonnull it clamps signed BYTE `[source.+61+4]` to `[1,50]`, obtains a row through the auxiliary index, negates CL, and writes BYTE `row+3a` at `004c7904`. ID is checked only with signed `ID < global_count` (`004c78d8..004c78da`); a negative ID passes. A negative index or rejected high ID selects EAX=0 (`004c78dc`, `004c78f4`), yet the store still targets `[EAX+3a]`. There is no upper row-index check and no final null guard.

Those branches establish a **conditional static path** from failed reserve or invalid lookup to an invalid/low-address write; they do not establish that this path occurs in a valid game run. With stable initial capacity/count globals, consistent helper effects and at most one appended row per scanned record, initializer growth may be unnecessary. Opaque callees, global changes, sentinel initialization and runtime source IDs remain prerequisites for any stronger reachability claim. The initial allocation failure path itself bypasses the entire scan and never reaches this BYTE store.

## Evidence, proposals and checks

- [Selected instruction evidence](../evidence/contract-boundary-12-sites.json): all 305 initializer and 87 reserve instructions independently decoded and compared with supplied Ghidra exports, six export hashes, body hashes, all 34 direct call sites, receiver stores, incoming references and selected caller/callee sites. No original bytes or bulk decompilation are retained.
- [Findings](../evidence/contract-boundary-12-findings.json): machine-readable boundary, fields, effects and uncertainty.
- [Names-only proposal](../evidence/contract-boundary-12-annotations.json): old `FUN_` names match the checkpoint-11 supplied decompiler exports and coordinator's read-only native preflight. No comment, data-type or prototype replacement is proposed; native integration belongs to the coordinator.
- [Read-only extractor](../evidence/contract-boundary-12-extract.py): requires Capstone 5.0.7 and the hash-pinned executable, with optional `--native-dir` for the supplied `.asm/.c/.refs` files. It parses PE32 sections rather than assuming file offsets equal VAs. Export hashes are locally recorded; no coordinator manifest was supplied.

The extractor passed with exact body coverage and native comparison; a repeated generation produced identical JSON. `npm run check` passed under Node v24.19.0. JSON parsing, Python syntax and `git diff --check` passed; staged paths/content were reviewed for privacy and owned scope. No native database was written.

There is no runtime trace, allocator-failure experiment, contract-state oracle or TypeScript behavior port in this task. Repository checks validate previously retained numerical fixtures and checkpoint metadata; they do not validate these static lifecycle findings, complete negotiation, successful allocation, persistence, money, or full game behavior.

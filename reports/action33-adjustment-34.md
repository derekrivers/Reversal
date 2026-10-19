# R34-A: action 33 adjustment short return and next RNG boundary

The [bounded TypeScript continuation](../reconstruction/action33-adjustment-34.ts) now reaches the real `00713e90` helper from the original `00702050` resolver entry, returns to its caller, and stops immediately before `00702241 -> 0090cfc0`. It reuses R33-A's original-produced clear-path state and mutable synthetic memory. There is no supplied intermediate adjustment result. This is an original-instruction comparison on synthetic state, not an observed live match, resolver completion, or shot outcome.

## Specimen and retained evidence

The pinned PE32 x86 specimen SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The [original-entry generator](../scripts/emulate_action33_adjustment_34.py) compares each admitted instruction in the caller, conversion/grid dependencies, and adjustment helper with hash-checked native exports. The `00713e90` ASM/C files come from the read-only `exports-30-action33-prefix` set; the caller and conversion exports come from `exports-09`. No native database was changed.

The [retained oracle](../evidence/action33-adjustment-34-oracle.bin) covers **232 clear-path original-entry cases, 96,339 original instruction steps, 41,891 ordered data/stack events, and zero RNG calls before the stop**. These are the 204 R32-A bit-04-clear cases plus 28 R33-A distance variants. The 16 bit-04-set cases remain at their separate `0071614b -> 005b58e0` boundary, and the 32 R33-A directed-rounding probes remain separately scoped to the conversion body.

Every R34-A case records its original state and region digests before `00702222`; those trace, event, call and checkpoint records match its R33-A oracle case exactly. The new suffix is checked against TypeScript for the complete represented registers/EFLAGS, x87 control/status/tag/active payload, ordered reads/writes, instruction starts, call/return snapshots and all mapped region digests. The [checker](../reconstruction/check-action33-adjustment-34.ts) also pins the oracle and [integrity receipt](../evidence/action33-adjustment-34-integrity.json) hashes. As in R33-A, physical empty x87 registers, x87 instruction/data pointers and hardware exception behavior are outside the represented state.

## The actual action 33 helper route

`00702222` calls `00713e90` with seven outgoing dwords and `ECX=shooter`. The first dword is action `0x33`; the seventh is an output-word pointer. The helper saves EBX/ESI/EDI, reads the output pointer from its stack, copies the action word into CX, and writes **zero** to the output word at `00713ea4`. Its comparisons reach `CMP CX,0x33` at `00713eeb`; `JZ` at `00713eef` takes the short route to `00713fba`. It restores its saved registers and executes `RET 0x1c` at `00713fbd`. AL is **2** on this route. `006cb6c0` and the helper's nested `00945640` call are not reached by the admitted action 33 route.

The caller stores AL=2 at frame `+0x10`, reads the zero output word, computes zero adjustment and adds zero to shooter word `+0x39` through an actual 16-bit read/write. It reads the output word again, pushes signed zero, and reaches pre-`00702241` with bound zero ready for the shared RNG. The generator checks the actual seventh argument pointer, including its relationship to helper-return ESP, and verifies both that word and the pushed RNG bound. The helper's return cleanup is 28 bytes. In these cases the bounded call leaves all four RNG state cells unchanged, because the RNG instruction has not executed. The first case's actual seven helper argument dwords are `[00000033,02007900,00000000,00000004,0000000b,414b4673,020079e8]`; the x argument's high bytes remain from the caller's output-pointer temporary, as R33-A observed.

## Exact remaining boundary

The **first TypeScript unsupported instruction is `00702241 CALL 0090cfc0`**. The argument is the helper's zero output word; earlier R30-A original-entry observations show this `R(0)` does not advance the shared RNG. This R34-A comparison stops before the call. It does not model the original `0090cfc0` machine-state ABI, stack reads/writes and return, nor the subsequent `00702246..007022fd` caller branches. Consequently no equivalence between this connected TypeScript prefix and R30-C's supplied `007022fd` interior checkpoint is established. That join remains open; an original-produced checkpoint cannot be silently substituted at `007022fd`.

The bit-04-set path is also unjoined. R33-A statically decoded the independent 42-byte `005b58e0` body, but its indexed table producer and global `00ae23bc` initialization/lifetime are not yet proven. R34-A does not turn that static contract into a dynamic call or candidate result.

## Reproduction and limits

The [integrity verifier](../scripts/verify_action33_adjustment_34.py) regenerates the entire oracle in separate normal and optimized Python processes and requires byte-identical canonical output. Twelve negative checks reject a changed PE, changed native helper bytes or operand, a different action route, a deliberately corrupted actual helper output word, noncanonical or oversized payloads, changed oracle result, and raw/hex/compressed private code fragments. The privacy scan covers task files plus the bounded expanded oracle. No original PE bytes, native export body or full private memory image is retained in Git.

```text
python scripts/verify_action33_adjustment_34.py PRIVATE_EXE --fresh EXPORTS_30_PREFIX --caller EXPORTS_09/00702050.asm --output evidence/action33-adjustment-34-integrity.json
node reconstruction/check-action33-adjustment-34.ts
```

Python 3.13, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.19.0 were used. Normal and optimized receipts are byte-identical. The task checker passes all 232 cases. The shared runner, registry, queue, frontier and canonical native database were not edited in this branch.

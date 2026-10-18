# Investigation 20: bounded descriptor-to-handle reconstruction

The headless TypeScript helper for **local body `0094fded`** matches retained outputs from the original x86 instructions in **344 synthetic cases**. All 16 instructions execute across those cases, including both return paths. Independent review reproduced the oracle and passed; the bounded entry is recorded in the validation registry. The canonical Ghidra database was not edited for this reconstruction.

The pinned PE is the 7,192,576-byte `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The complete body is virtual `0094fded..0094fe29`, 61 bytes, file offset `0054fded`. Its bytes have SHA-256 `bc15fa380be7e1320498ba101d1f41e7bf28ecdfa284dfc1438c4a44ff0cc1c9`; the read-only checkpoint-18 assembly export used by R19 has SHA-256 `f5b8380d00d50539877ec35f2042aeb3cc0b93576608db635218395cbc85d533`. Every input hash/extent check uses explicit exceptions and remains active with `python -O`.

## Implemented local contract

[`descriptor-handle.ts`](../reconstruction/descriptor-handle.ts) accepts an unsigned DWORD descriptor and a synchronous little-endian memory interface. It compares the descriptor **unsigned** against DWORD `[00de43e0]`. A passing descriptor selects a page-pointer DWORD at wrapping address `00de42e0 + 4*(signed32(descriptor)>>5)`, then an eight-byte entry selected by `descriptor&31`. Only bit zero of entry byte `+4` controls open status. An open entry returns its stored DWORD unchanged, including zero and `0xffffffff`.

A bound or open-bit failure reads/modifies/writes DWORD `[00de2f90]` to zero, writes DWORD `[00de2f8c]` to 9, and returns `0xffffffff`. The implementation preserves the read of the AND destination and the write order, including when the initial values already equal zero/9. Success preserves both error globals and makes no memory writes. The API rejects JavaScript values outside unsigned DWORD integers before accessing memory; callers representing signed -1 must supply `0xffffffff`.

The supported domain is stable, readable storage with valid error-global write access and no alias between table slots, bound, descriptor pages, stack and error globals. The callback interface must return unsigned byte/DWORD values and throw for unavailable storage. It does not establish native fault recovery, SEH or behavior under concurrent mutation. The table slot for descriptor 2048 aliases the bound global, so a passing descriptor with that index is outside this nonaliasing domain. Artificial high-bit descriptors are included where their signed page index selects distinct synthetic storage. The helper reproduces 32-bit address wrapping, including a page pointer that wraps entry/flag accesses into mapped page zero.

## Original-instruction oracle and comparison

[`emulate_descriptor_handle_20.py`](../scripts/emulate_descriptor_handle_20.py) parses the original PE section mapping and copies **only the pinned 61-byte body** into a read/execute emulator page. It neither transcribes the instructions nor loads original runtime pages. Unicorn **2.1.4** executes in x86 32-bit mode; code hooks admit only the original 16 instruction starts, with an instruction/time budget. The body has no calls. The sentinel return page ends execution only after a normal RET.

All descriptor pages, table pointers, globals, guard bytes and stack bytes use an explicitly synthetic deterministic recipe. The oracle compares every mapped synthetic byte after execution against the initial bytes plus the logged writes; any other mutation fails generation. It also verifies the original code bytes remain unchanged. The original entry frame supplies the descriptor at `[ESP+4]` and a synthetic return address at `[ESP]`. Normal exits reach that address with `ESP=entryESP+4`; EBX/EBP/ESI/EDI and the locally untouched EDX retain distinct sentinels. The stack bytes and argument are covered by the memory comparison. EAX is the raw DWORD result; ECX and EFLAGS are scratch. Fault probes retain the original ESP. TypeScript exposes return/memory effects; it does not simulate the native register file.

[`check-descriptor-handle.ts`](../reconstruction/check-descriptor-handle.ts) constructs the same synthetic input bytes independently in TypeScript, then compares EAX, both error DWORDs, the ordered read/write events and the final digest of **all mapped synthetic memory** against [`oracle.json`](../evidence/descriptor-handle-validation/oracle.json). ABI observations and instruction coverage retained by the original run are also checked. The new check runs through `scripts/check-research.mjs` and the existing Node24 CI workflow.

| Coverage | Result |
| --- | ---: |
| Synthetic cases | 344 |
| Open returns, without error writes | 183 |
| Stored `0xffffffff` returns among open cases | 9 |
| Bound/open-bit failures setting error9 | 159 |
| Unmapped flag/handle read probes | 2 |
| Distinct flag bytes | 256 |
| Original instruction starts reached | 16 / 16 |
| Total original instructions executed | 4,329 |

Cases include descriptors 0/1/30/31/32/33/63/64/2047, bound equality and zero, all flag bytes, zero/high-bit/-1 handles, artificial high bounds with signed negative page indices, misaligned pages, a page-crossing entry and address wrap. Bound failures use a poisoned page pointer to prove that no descriptor-page access occurs. One fault probe lacks the flag storage; another has a readable open flag but an unmapped handle DWORD. Both preserve errors and make no writes before the fault. Initial error values vary and include already-zero DOS error/already-9 errno.

[`negative-checks.json`](../evidence/descriptor-handle-validation/negative-checks.json) records 11 negative checks: altered PE and altered native assembly are rejected before output in both normal and optimized Python; seven temporary TypeScript mutants are rejected by the retained checker. The mutants accept bound equality, accept any flag bit, use logical page shift, use four-byte stride, reject a stored -1 handle, retain the DOS error, or reverse the failure writes. The temporary inputs/source copies stay outside Git. Five additional invalid JavaScript arguments are rejected with no memory access during the retained check.

## Reproduction and limits

Install `unicorn==2.1.4` into a private Python environment outside Git. Node **24.19.0** and Python **3.13.7** produced the retained checks. Pass private input paths explicitly and choose a new output directory:

```text
python scripts/emulate_descriptor_handle_20.py PATH_TO_EXE PATH_TO_0094fded.asm NEW_OUTPUT_DIRECTORY
node reconstruction/check-descriptor-handle.ts NEW_OUTPUT_DIRECTORY/oracle.json results/descriptor-handle.json
python scripts/check_descriptor_handle_negative_20.py PATH_TO_NODE24 PATH_TO_EXE PATH_TO_0094fded.asm results/descriptor-negative.json
node scripts/check-research.mjs
```

[`provenance.json`](../evidence/descriptor-handle-validation/provenance.json) records reproducibility hashes and validation results; the [independent review receipt](../evidence/descriptor-handle-validation/independent-review.json) records the reproduced checks. The retained oracle contains synthetic scalar inputs, numerical outputs, address/event observations and digests; no raw executable instructions, original game pages, native projects or bulk assembly are committed. The [accepted registry delta](../evidence/descriptor-handle-validation/validation-registry-proposal.json) matches the promoted entry.

R18 `0094c552`, OS calls, descriptor initialization/lifetime, locking, save format and allocator behavior remain outside this unit. This evidence establishes the compared local contract in the stated memory domain; it does not establish a full database, subsystem or game reconstruction. UI remains deferred.

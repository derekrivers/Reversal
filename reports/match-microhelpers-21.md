# R21-A: three complete match microhelpers

The complete local bodies at virtual addresses `006f0970`, `007160d0` and `007160e0` are statically mapped and reconstructed in headless TypeScript. The original instructions match the reconstruction in **65,840 synthetic cases**, covering all 65,536 byte addition pairs. This is a bounded memory contract; caller reachability, real match lifecycle and connected gameplay remain open.

The specimen is the 7,192,576-byte PE32 x86 executable SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The work starts at queued merged baseline `0eac17d`. Private read-only Ghidra 12.1.4/JDK21 exports came from independently restored checkpoint 19, archive SHA-256 `bd7470b1eca19f20992e397d2b2e4db25d47c4bd4f74716d18b331d853acea34`. No canonical native project was changed.

## Complete local contracts

Here `p` is entry ECX and `m` is the DWORD read from `p+0x19e`. Fields are research offsets; their source names and broader meaning are unresolved.

| Entry VA | File offset | Bytes / instructions | Contract and ABI |
| --- | --- | --- | --- |
| `006f0970` | `002f0970` | 63 / 12 | Receiver in ECX; no stack arguments; plain RET. Reads `p+0x19e` four times. Ordered stores: DWORD `m+0x4786=0`; BYTE `m+0x8eae=255`; DWORD `m+0xf582=0`; BYTE `m+0x1a7=0`; WORD `p+0x29=0`; WORD `p+0x19c=0`. Each of the first four stores uses a freshly loaded pointer. Observed EAX=0; EDX=last loaded match pointer. |
| `007160d0` | `003160d0` | 15 / 5 | Receiver in ECX; reads low byte at entry ESP+4. Reads BYTE `p+0x2b`, adds argument modulo 256, stores BYTE back. RET4 consumes one four-byte argument slot. AL=argument byte; DL=result byte; upper 24 bits of EAX and EDX preserved. |
| `007160e0` | `003160e0` | 10 / 3 | Receiver in ECX; reads low byte at entry ESP+4; stores it as BYTE `p+0x2b`. RET4 consumes one four-byte argument slot. AL=argument byte; upper 24 EAX bits and all EDX preserved. |

All three preserve ECX and the nonvolatile EBX/EBP/ESI/EDI registers. They make no calls, conditional branches or RNG requests. The reset's XOR changes arithmetic flags; byte addition sets arithmetic flags; assignment preserves flags. EAX is an observed register effect, not a newly inferred meaningful C return value. The reset's XOR leaves AF architecturally undefined; its retained AF=0 is specifically Unicorn 2.1.4 behavior. No other CPU's AF behavior is claimed.

The extractor verifies the pinned specimen, private manifest and preflight digests, all exported ASM/C file digests, exact old native names, every decoded instruction address, full mnemonic/operand spelling after bounded normalization, byte widths, body extent and return membership. All 20 decoded instructions exactly match the complete native bodies, with no omitted starts or extra decoded bytes. It uses explicit exceptions throughout, including under Python `-O`.

## Executed domain and evidence

The emulator maps only each original complete body, a return sentinel and deterministic synthetic memory. Code pages are read/execute only. Each case resets EAX/EDX/EFLAGS, ECX, ESP and all four nonvolatile registers. It verifies entry-to-return execution of exactly the 12/5/3 original instruction starts, return EIP, stack cleanup and preserved registers. It compares all mapped receiver, match and stack bytes against logged writes, including neighbouring fields and stack argument bytes.

The public fixture consists of an authored JSON receipt and 790,080 bytes of numerical EAX/EDX/EFLAGS records. It contains no original instructions or original runtime pages. Ordered native read/write triples and complete initial/final synthetic memory are retained as aggregate SHA-256 digests; TypeScript rebuilds every synthetic byte and independently matches those digests in case order. Reads include the argument and return-address stack reads. TypeScript exposes local memory effects and register observations; native stack/return behavior is checked by the emulator.

| Body | Cases | Inputs |
| --- | ---: | --- |
| Reset | 36 | Three receiver placements, three match placements and four fill/register seeds. Includes unaligned pointers, a pointer DWORD ending exactly at its receiver page boundary, and a reset DWORD ending exactly at its match region boundary. |
| Add | 65,542 | All 256×256 stored-byte/argument-byte combinations, four receiver alignments and varied initial upper register bits/flags; six additional page-end and DWORD argument cases. |
| Set | 262 | All 256 argument bytes; six additional page-end and DWORD argument cases. |

The extra arguments are `0`, `0xff`, `0x100`, `0x7fffffff`, `0x80000000`, `0xffffffff`; the original body consumes only their low byte. Initial flag patterns are `0x202`, `0xad7`, `0x246`, `0x293`. Add/set receiver addresses include `0x10000fd4`, where `p+0x2b` is the final mapped byte. Reset receiver addresses are `0x10000000`, `0x10000001`, `0x10000e5e`; match pointers are `0x11000000`, `0x11000001`, `0x11000a7a`.

The admitted domain requires stable, disjoint receiver, match and stack storage with every access mapped; it does not require natural alignment. No invalid-pointer or alias equivalence is claimed. The original reset has no null or range guard and reloads pointers between writes. Those instructions are preserved in the adapter, while native fault ordering, alias cases and concurrent mutation remain outside this experiment. Invalid JavaScript scalar inputs (`-1`, `2^32`, fractional, NaN and infinity) are rejected before memory effects; these are API checks, not original game input validation.

## Verification and reproduction

With Python 3.13.7, Capstone 5.0.7, Unicorn 2.1.4 and Node 24.19.0:

```text
python scripts/extract_match_microhelpers_21.py EXE EXPORTS_21 PREFLIGHT_21 results/microhelpers-instructions.json
python scripts/emulate_match_microhelpers_21.py EXE EXPORTS_21 PREFLIGHT_21 results/new-microhelpers-oracle
node reconstruction/check-match-microhelpers.ts evidence/match-microhelpers-validation results/match-microhelpers.json
python scripts/check_match_microhelpers_negative_21.py EXE EXPORTS_21 PREFLIGHT_21 NODE24 evidence/match-microhelpers-validation/negative-checks.json
npm run check
```

`NEW_OUTPUT_DIR` must not exist. The original body bytes are loaded from the pinned PE using validated file offsets. Private native inputs are read-only. Both normal and optimized Python runs reject wrong specimens and changed manifests without writing evidence. A separate test reseals only its temporary test manifest to prove an offset mutation fails complete operand comparison in both modes. Eight TypeScript mutations are rejected by retained native register records or access digests: cleared upper EAX, preserved EDX on add, preserved addition flags, missing byte wrap, wrong byte offset, wrong write width, reordered reset writes and cached reset pointer. A valid optimized emulator run produces byte-identical oracle and register files. The existing `npm run check` suite and the new focused check pass on Node 24; the coordinator owns integration into the shared check runner.

The staged privacy inspection permits authored code, field-offset contracts, hashes and synthetic numerical outputs. It checks that none of the three complete original bodies appear verbatim in the staged files and that no native export, game input or project file is staged. Proposed native names and validation registry entries are review-only deltas in the evidence directory. Their acceptance and any canonical native changes belong to the coordinator.

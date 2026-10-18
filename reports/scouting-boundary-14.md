# Scouting storage accessors — investigation 14

The five owned functions share an ECX-supplied manager, an optional key pointer and a fallback lookup. They expose two inline tables and an array of 688-byte records. Two functions read/write dword slots using **byte arithmetic**; two read/write byte slots using **32-bit arithmetic**. The fifth returns a record alias using a signed byte selector and a manager count. They do not allocate or implement a complete scouting workflow.

Specimen: PE32 `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline: `3d81fa3c056c7d28c3c2a6d99e93d96464f43834`; native checkpoint 13. Addresses below are virtual addresses and field offsets are bytes. The `scout_manager.cpp` string at `00a7b094` is navigation evidence; the contracts come from original instructions and whole-owned-body agreement with independent read-only native exports: all 353 owned instructions match.

## Shared lookup and the width difference

Each key stack slot is four bytes. A nonzero key is used directly. A zero key falls back to `read32(00b74c26 + 0x300 * signed16(read16(00b77c7a)))`. The fallback's signed index has no local bounds check. A zero fallback value reaches diagnostics. A nonzero value is dereferenced without validating the pointer. None of these bodies validates the receiver pointer.

For the dword slot pair, define `i8 = u8(read8(key) - read8(00ae2364) + 16)`. The `SUB AL,DL` and `ADD AL,0x10` wrap at eight bits. `JS` followed by `CMP AL,0xf / JG` admits exactly `i8=0..15`, which is then sign extended to index the table. This is not a read of a full dword ID. For the byte slot pair, define `i32 = u32(read32(key) - read32(00ae2364) + 16)`. Their signed checks admit exactly `i32=0..15` after 32-bit wrapping. These pairs can address different storage for the same key: as an arithmetic illustration, key dword `0x1f0` and global dword zero yield `i8=0`, whereas `i32=0x200` fails the byte table guard. This example is not an execution fixture.

| Entry / body bytes | ABI and direct successful effect | Failure return after diagnostic helpers return |
| --- | --- | --- |
| `007f6af0` / 240 | ECX receiver; stack slots `(value32, key)`; `RET 8`. Store value32 at `receiver+0xc+4*i8`; EAX=1. | EAX=0 |
| `007f6be0` / 229 | ECX receiver; stack slot `(key)`; `RET 4`. Return EAX=`read32(receiver+0xc+4*i8)`. | EAX=0, indistinguishable from a valid zero slot by return alone |
| `007f6cd0` / 338 | ECX receiver; stack slots `(selector, key)`; only **signed low byte** of selector is used; `RET 8`. Return EAX=`read32(receiver)+0x2b0*n`, with checks below. | EAX=0 |
| `007f6e30` / 228 | ECX receiver; stack slot `(key)`; `RET 4`. Return AL=`read8(receiver+0x4c+i32)`. On this success path EAX's upper 24 bits happen to be zero because the validated index was 0..15 before `MOV AL`. | AL=`0xff`; upper EAX bits are not established across diagnostic calls |
| `007f6f20` / 240 | ECX receiver; stack slots `(value, key)`; consumes only low byte of value; `RET 8`. Store at `receiver+0x4c+i32`; EAX=1. | EAX=0 |

The dword table occupies `+0xc..+0x4b`; the byte table occupies `+0x4c..+0x5b`. Writes are exactly four bytes or one byte, respectively. Neither setter owns, frees or copies a pointee. Observed callers use a pointer as a dword slot value, but the local setter accepts any 32-bit value. Successful paths in all five bodies contain no calls and no direct RNG access. Diagnostic helpers remain unresolved transitive effects.

## Record alias and actual bounds

`007f6cd0` first reads signed8(selector), rejecting negatives and values above nine (`007f6cda..007f6ce5`) **before** resolving or dereferencing the key. It never substitutes a default selector. With selector `j=0..9`, it computes `n = u32(10*i32+j)` (`007f6d3f..007f6d54`). It then rejects signed32(n)<0 or signed32(n)>signed32(u32(read32(receiver+8)-1)) (`007f6d57..007f6d61`). Count subtraction and all address arithmetic wrap at 32 bits. There is no separate `i32<=15` test in this function.

Success multiplies n by `0x2b0` (688) and adds the base at receiver `+0` (`007f6d63..007f6d77`). No null base test, allocation extent check or overflow check occurs. For the constructor's ordinary count of 160 and nonwrapping indices, this selects 16 groups of ten records. The exact local guard is on the combined n; malformed/extreme inputs are governed by the wrapping formula, not by a separately proven key window. The returned pointer aliases manager-held storage; no record is copied or separately allocated. Receiver `+4` is not read by any owned body.

## Observed initialization and caller use

Selected constructor context `007f6760` preserves the receiver in EBP, zeros sixteen dwords at `+0xc` (`007f6881..007f688b`), and may call load boundary `007f7bb0`; a nonzero load result bypasses the subsequent default allocation and byte defaults (`007f68ac..007f68b3`). The ordinary fallback path sets receiver `+8=0xa0`, requests `0x1ae04` bytes, writes the leading count `0xa0` and supplies count `0xa0`, stride `0x2b0` and element callbacks to `009463af` (`007f68b9..007f6903`). It publishes allocation+4 at receiver `+0` (`007f68ef`, `007f691d`). Arithmetic matches `4+160*688=110084`. Its sixteen-group loop sets bytes `+0x4c..+0x5b` to one (`007f6992`, `007f69a1`, `007f6a4f..007f6a6b`). Callback internals, loaded data and all initializer effects remain outside this contract.

Cleanup context `007f6aa0` reads the base and leading count at base-4, calls element cleanup helper `009462bb` with stride `0x2b0` and callback `007ae4f0`, passes base-4 to `00944c94`, then clears receiver `+0` (`007f6aa3..007f6aca`). This supports manager-held array lifetime; complete allocator/destructor semantics and every cleanup path are unresolved. Interior record aliases can become invalid after this cleanup.

Observed calls load ECX from global pointer `00b74448`. At `00804248`, a caller uses key zero to read a byte slot and stores AL into its own leading byte; it subsequently passes selectors and key zero to the record locator (`00804268`). At `00804460`, the reverse caller writes its leading byte through the byte setter, then uses returned record aliases as receivers of `007b7690` (`0080447a..00804481`). These are snapshot/edit-style traffic leads; the full caller and copy-helper contracts have not been recovered here.

The caller at `008085bc` passes a newly constructed object pointer as the dword slot value with key zero. Another caller invokes `00804450`, performs cleanup/free calls on that object, then writes zero through `007f6af0` (`008131d3..00813204`). This corroborates pointer use and explicit slot clearing in that path. It does not establish that all slot values are pointers, exclusive ownership, a singleton invariant or complete report/editor lifecycle. All 36 incoming native references to the five entries were independently checked as direct calls in the pinned PE; only the selected caller boundaries above were analyzed further.

## Diagnostics and limits

Each failure path calls `00944cff` with two 256-byte local buffers, then `0090d130`, `00944c9f` and `005e8290`, using shared buffer `00ae24d0`. If the calls return, it clears dword global `00b67a34`, sets the failure return and performs callee stack cleanup. Source diagnostic numbers are:

| Entry | Null resolved key | Invalid index | Invalid selector |
| --- | --- | --- | --- |
| `007f6af0` | `0xb8` | `0xc2` | — |
| `007f6be0` | `0xde` | `0xe8` | — |
| `007f6cd0` | `0x109` | `0x113` | `0xff` |
| `007f6e30` | `0x12c` | `0x136` | — |
| `007f6f20` | `0x150` | `0x15a` | — |

Byte slot getter failure `0xff` may also be a stored byte value; the setter does not restrict its byte input. Diagnostics' external effects, termination behavior and transitive RNG remain unresolved. Key/global producers, field meanings, synchronization, disk persistence and full scouting assignment/report behavior are open. High confidence applies to direct ABI, widths, formulas, branches and writes; lifecycle and caller-purpose labels remain bounded interpretations.

## Reproduction

`evidence/scouting-boundary-14-sites.json` contains selected sites, full-body digests, call sites, every owned instruction's agreement with the native export and verified incoming call addresses. `evidence/scouting-boundary-14-findings.json` records machine-readable contracts. Optional exact old/new **name-only** proposals are in `evidence/scouting-boundary-14-annotations.json`; no prototype, structure or comment replacements are proposed.

```powershell
python scripts/extract_scouting_boundary_14.py --binary <private-cm0102.exe> --native-dir <private-exports-14> --preflight <private-annotation-preflight-14.json> --output evidence/scouting-boundary-14-sites.json
npm run check
git diff --check
```

The extractor requires Capstone 5.0.7. It verifies the executable hash, the private manifest hash `233ec2078dc3eacf0d1b83a3d093028caf57c634329bacce4af4ea2efb5c7f86`, all manifest-listed file hashes and optional annotation preflight hash `728f0dbb5ccd7860c03a35203f30b7bb377048879c2b95601b1744fd78e7fc3d`. It decodes every owned instruction and compares operands including widths, then checks all incoming native references against original direct calls. Only compact selected instruction text, hashes and metadata are written; no original bytes or bulk exports are retained. These are five `contract-supported` whole-body static contracts, with selected dependencies only `boundary-mapped`. No execution equivalence or full workflow is claimed.

Verification passed: pinned-PE/native/preflight extraction, two repeat extractions matching the retained UTF-8/LF output (SHA-256 `1c28aa9406cc7818f6deec8c93efee562c962e7136814561b3f69687451df8a0`), `npm run check` on Node v24.19.0 and `git diff --check`. Repository checks validate retained earlier fixtures and metadata; they do not execute these scouting functions.

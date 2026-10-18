# Scouting construction, cleanup and copy callers — investigation 15

The four owned bodies connect R14's manager accessors to a default allocation of **160 records of 688 bytes**, a counted-array cleanup and two callers that copy ten records in opposite directions. Cleanup additionally handles a separate pointer at manager `+0x5c`. These are complete local static contracts with unresolved helper effects; they do not recover a full scouting lifecycle, persistence or exclusive ownership.

Specimen: PE32 `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline: `a4fa4bc7745ad3fbc67759325c45a9058ceaecc0`, native checkpoint 14. Addresses are virtual addresses; offsets are bytes. Capstone 5.0.7 independently decoded all four contiguous native body ranges: **371 instructions / 1,223 bytes**, all agreeing with the read-only native assembly after documented spelling normalization. All five incoming native references were verified as direct calls in the pinned PE. No original instruction bytes or bulk exports are retained here.

| Entry / bytes / instructions | Local ABI and normal return | Contract |
| --- | --- | --- |
| `007f6760` / 818 / 243 | ECX=manager, one four-byte stack slot, `RET 4`; EAX=manager | Initialize tables; pass a media-path gate; conditionally call `007f7bb0`; otherwise allocate and default a counted record array |
| `007f6aa0` / 74 / 27 | ECX=manager, `RET`; EAX unspecified | Conditional counted-array destruction/release and separate `+0x5c` release; clear the two pointer fields after the respective calls return |
| `008041c0` / 251 / 71 | ECX=caller object, one stack slot whose signed low byte is examined; `RET 4`; EAX=object | Construct two embedded ten-record arrays and another subobject; choose leading byte; copy ten manager records into the first array; clear explicit metadata |
| `00804450` / 80 / 30 | ECX=caller object, `RET`; EAX=1 if control reaches normal return | Write leading byte through manager accessor; copy the first embedded array's ten records into manager record aliases |

## Manager construction: initialization and gate

`007f6785..007f67a1` clears sixteen dwords each at `manager+0x68..+0xa7` and `+0xa8..+0xe7`. This precedes any load/default allocation. The two ranges are cleared by interleaved stores through one advancing pointer. The body does not directly write manager `+4`.

The normal initialization path is gated by drive enumeration. The PE import table identifies `009670f8` as `GetLogicalDriveStringsA` and `00967100` as `GetDriveTypeA`. The body asks for a 200-byte drive buffer, checks only for a nonzero return and first byte, tests drive type 5, formats an executable path ending in `cm0102.exe`, and calls `004c0aa0(path, local_buffer, 0)`. A zero result at `007f6817` admits initialization and establishes ESI=0. A nonzero result calls `004c0c10(local_buffer)` before the scan advances. The byte scan counter adds four and is **sign extended** for the next buffer index (`007f6829..007f6833`); do not generalize this to an unrestricted safe string walk. Enumeration failure, an empty list or exhaustion invokes two `0066f4e0` calls and `005e8290(...,1)`, then repeats enumeration. Those callees' UI, I/O and termination effects remain boundaries. The owned body also installs/restores an FS:[0] exception frame; exception handler bodies are not covered by its normal-return contract.

After the gate, `007f6881..007f688b` clears sixteen dwords at `manager+0xc..+0x4b`, the R14 dword-slot table. A nonzero input stack slot permits a call to `007f7bb0(input)` only when the signed result of `(g ^ (g >> 31)) - (g >> 31)`, with 32-bit wrapping and `g=read32(00dd7110)`, is at least `0x3e025`. This is the x86 absolute-value idiom with its signed `INT_MIN` edge: that value remains negative and fails this comparison. A nonzero load-helper return jumps straight to the manager-return epilogue. The four owned bodies do not establish what that helper loads, whether it succeeds transactionally or which pointers/counts it publishes.

## Default allocation and record setup

When the input/gate does not select loading or `007f7bb0` returns zero:

| Site | Direct effect / immediate call boundary |
| --- | --- |
| `007f68b9..007f68ce` | Set manager `+8=0xa0`; clear dwords `+0x5c`, `+0x60`, `+0x64`; call allocator boundary `00944cf1(0x1ae04)` |
| `007f68e5..007f6903` | For nonnull allocation A, write `read32(A)=0xa0`; call `009463af(A+4,0x2b0,0xa0,007ae390,007ae4f0)` |
| `007f690e..007f6920` | Publish A+4, or zero on allocation failure, to manager `+0` and test it |
| `007f69a9..007f6a40` | For each group `i=0..15` and selector `j=0..9`, invoke the four boundaries described below on record `base+688*(10*i+j)` |
| `007f6a4f..007f6a6b` | Set byte `manager+0x4c+i=1`, advance the record-group index by ten, repeat sixteen times |

The allocation request is exactly `4 + 160*688 = 110084` bytes. A+4 is the first record, the leading dword is the allocation cookie, and manager `+8` independently holds 160. Selected helper-loop instructions show `009463af` invokes its construction callback with ECX advancing by the supplied stride; its exception/failure machinery and callback bodies remain unresolved. Nothing here allocates sixteen independent arrays.

Each record receives the following **ordered** calls on the ordinary default path. The base pointer at manager `+0` is reloaded at every inner iteration, before these calls:

1. `007ae570`, ECX=record, argument `read32(00ae23bc) + 110*(read32(00ae2364)-16+i)` with wrapping x86 arithmetic. The globals are reread once per outer iteration.
2. `007ae640`, ECX=record, four-byte argument whose **low byte** is j. The stack local's other three bytes are not initialized in this body; the full argument must not be asserted to equal j without the callee's width contract.
3. `007ae6e0`, ECX=record, argument 1 for j=0, 2 for j=1, 3 for j=2, and 4 for j=3..9.
4. `007fc150(argument_with_low_byte_j, record+0xb, 100)`, caller cleans twelve stack bytes. The first argument carries the same uninitialized upper bytes. This is a call boundary, not a proven 100-byte memory write.

These callbacks and helpers may allocate or mutate nested state. No direct RNG call appears in the four owned bodies; transitive RNG is unproved. On a null allocation, the constructor calls diagnostics with `scout_manager.cpp` and diagnostic number `0x65`, clears global `00b67a34`, calls `005cc7d0`, `005a8f60`, then `00945934(-1)`. There is no local jump around defaulting if that last call unexpectedly returns. The contract therefore does not claim a recoverable null-allocation return or prove termination from the caller alone.

## Cleanup and alias lifetime

`007f6aa0` reads manager `+0`. If nonnull base B, it reads the dword at **B-4**, calls `009462bb(B,688,read32(B-4),007ae4f0)`, then calls `00944c94(B-4)` and clears manager `+0`. Selected `009462bb` loop sites support reverse-stride callback traversal; helper exception/unwind effects are outside this contract. The array cleanup count comes from the cookie, **not manager+8**.

It then separately reads manager `+0x5c`; a nonzero value is passed to `009452ca` and that field is cleared after return (`007f6ad1..007f6ae1`). Selected `00944c94` instructions show it forwards its argument to `009452ca`, which remains an allocator release boundary. This routine neither frees the receiver itself nor clears manager `+8`, `+0xc..+0x5b`, `+0x60/+0x64` or `+0x68..+0xe7`. It performs no pointer validation, extent validation or cross-field consistency check. Repeated calls after ordinary completion skip both now-null pointer fields; that narrow observation does not prove all nested/global resources have been released.

The allocation/cookie/release relationship supports manager-held record storage and explains why R14 record aliases can become invalid on cleanup. The owned instructions do not prove exclusive ownership, absence of aliases, complete resource cleanup or loaded-array allocator compatibility. In particular, the R14 dword-slot table is not traversed or cleared by this cleanup.

## Ten-record copy callers

`008041c0` first calls `009463af` twice with count ten, stride 688 and callbacks `007ae390`/`007ae4f0`, using embedded bases **object+1** and **object+0x1b0e**. It calls `0068d020` with ECX=object+0x361e. Selected helper instructions clear fourteen bytes there (word at +0 and dwords at +2/+6/+0xa). These subobjects are constructed even when the subsequent manager lookup fails. The first record array ends immediately before object+0x1ae1; the second spans `+0x1b0e..+0x35ed`.

The signed low byte of the caller's stack argument is accepted only in 0..9. Otherwise it calls R14 byte getter `007f6e30(key=0)` through the pointer read at global `00b74448`. The chosen AL is written to object+0; fallback output is not checked again, so getter failure `0xff` can be stored. This leading byte does **not** choose which records are copied: a separate j loop always covers 0..9.

For each j, it reloads global `00b74448`, calls R14 record accessor `007f6cd0(selector_with_low_byte_j,key=0)`, then invokes `007b7690` with **ECX=object+1+688*j, source argument=returned manager alias**. After the call returns it clears dword `object+0x1ae1+4*j`. Finally it clears dwords `+0x1b09`, `+0x361a` and `+0x3634`. This body supplies no manager lookup copies into the second embedded array beyond its construction callbacks. Other bytes/fields cannot be assumed initialized by these direct stores.

`00804450` first calls R14 byte setter `007f6f20(value_with_low_byte=read8(object),key=0)` through global `00b74448`, ignoring its return. It then reloads the global for every j, calls the same record accessor with key zero and low selector byte j, and calls `007b7690` with the direction reversed: **ECX=returned manager alias, source argument=object+1+688*j**. The selector stack slot in both callers retains uninitialized/unrelated upper bytes, which R14's signed-low-byte accessor ignores. Neither caller guards a null returned alias or examines a copy-helper result. `00804450` returns 1 after ten returned calls regardless of the byte setter's result; it is not a demonstrated transaction-success flag.

Selected `007b7690` instructions corroborate receiver=destination and stack argument=source: it copies `0xac` dwords (688 bytes) from the argument into its saved receiver. The same selected boundary also shows prior cleanup of destination fields `+0x1ee/+0x170` and later allocation/copy/registration calls. Consequently these callers cannot be described as plain memcpy or proven shallow copies. The helper's complete nested ownership, self-copy safety, failure behavior and transitive effects remain open. No complete helper contract is claimed.

As read-only caller corroboration, `0080857c` requests `0x3638` bytes and calls `008041c0`, then places the returned pointer into the R14 dword slot through `007f6af0`. At `008131d3..00813204`, another path calls `00804450`, calls object cleanup `00813140`, releases the object, and clears that dword slot. These selected paths support the observed object/slot traffic without proving a complete editor/report workflow, singleton or exclusive ownership. `00813140` is unresolved.

## Reproduction and scope

The deterministic extractor verifies the pinned executable, export manifest hash `65503dc3cf33eff2a9a40c1cdc456f5798bc8e04d1d9bbad6132c06b9677ca58`, every manifest-listed file hash and preflight hash `c20393d151da0afff24f0ff7f806f91857d90f454cbff5a52d7bc0463517d1f1`. It independently maps PE VAs to file offsets, decodes every owned instruction without gaps, compares each native instruction including operand widths, verifies all incoming references as original direct calls, and extracts the two import names. Selected helper spans are independently decoded but are not covered by native whole-body agreement or promoted to full contracts.

```powershell
python scripts/extract_scouting_lifecycle_15.py --binary <private-cm0102.exe> --native-dir <private-exports-15> --preflight <private-annotation-preflight-15.json> --output evidence/scouting-lifecycle-15-sites.json
npm run check
git diff --check
```

The compact sites file contains body hashes, addresses, calls/branches, selected instructions and native receipts. Findings and optional exact-old-value name-only proposals are separate JSON files. These four bodies qualify as `contract-supported` static local contracts, with all transitive and selected context dependencies `boundary-mapped`. No numerical reconstruction or execution oracle was added. Verification uses Node v24.19.0 for repository checks; those checks validate earlier retained fixtures and metadata, not execution of these functions.

Verification passed: all-owned-instruction native comparison, manifest/preflight/import checks, five incoming calls, two byte-identical repeat extractions (sites SHA-256 `670a470c41246d7884a7fa90844cbe5fba5791c4728ac1623fdf3f3c90f85cfb`), JSON parsing, Node v24.19.0 repository checks and `git diff --check`. The staged scope/privacy check admitted only the five authored task files, compact instruction sites/digests and research metadata; it found no binary payload, bulk export or original game data.

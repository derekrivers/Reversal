# R32-B: slot side-byte initialization and the next owner boundary

Original entry `006eada0` produces the one-byte zero later read from slot `+0x27` at `006eaf77`. Executing that initializer before the existing lookup and placement entries advances the synthetic placement frontier to `006eaf8f`, immediately before the match `+0x4792` owner-pointer read. The original nonnull staff-record lookup separately reaches the same CRT exit-list boundary as R31-B; it still has no initialized lookup object or normal effect return.

The pinned specimen is the 7,192,576-byte PE32 x86 image SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses are virtual unless labelled PE file offsets. Baseline is merged PR #117 at `06de3f3db9da6627a9efae47e5d0d87942b696ae`. [R30-D](action33-state-30.md) and [R31-B](action33-lifecycle-31.md) retain the earlier provenance and execution limits.

## Source, width and lifetime

The initializer occupies `006eada0..006eae97`, with a plain `RET` and no callees or branches. `006eada0` copies receiver ECX to EAX; `006eada5` zeros ECX; `006eadb2` stores CL at `[EAX+0x27]`. This is exactly one byte. It initializes a member of the caller's receiver storage; it does not allocate or publish that storage. EAX returns the receiver and ESI is preserved. Neighbouring bytes are checked as part of complete synthetic region comparisons.

The fresh checkpoint-29 disposable export reports that `006eada0` was absent as a Ghidra function. The coordinator defined only the straight-line `006eada0..006eae97` body in that disposable project and exported it. This is new instruction-backed function identification; it is not an accepted canonical annotation or an existing atlas entry.

The original owner constructor `006b7e50` has a vector-construction call at `006b7e85`. Its argument setup supplies callback `006eada0`, count 40, stride `0x1be` and storage beginning at receiver `+0x4796`. That static context supports the initializer's slot-array role. The enclosing game constructor and its allocations, exception cleanup and owner lifetime have not executed in this fixture.

The initializer's zero is the value on a fresh initialized slot. Placement `006e0d00` computes `manager->slots + 0x1be*index`; `006eaea0` saves that same pointer in ESI. Its early `006eaf77` read therefore aliases the original initializer's receiver byte. The admitted prefix never changes this field. This pre-existing byte is distinct from the current call's manager `+0x18` argument: all four supplied manager values 0..3 still read zero from the fresh slot.

Later in the same placement body, `006eb196` reloads BL from the third entry argument's low byte (`[ESP+0x34]` with ESP at entry minus `0x28`), and `006eb481` stores BL to slot `+0x27`. Intervening calls remain unexecuted here; the reload/store relation is local static data flow with callee preservation obligations. It must not be described as an observed completed update. Reusing a slot after a completed placement can therefore require its prior member value; rerunning the initializer before every replacement would erase that state and is not established by this experiment. Bulk copies, alternate owners and final storage destruction remain unresolved.

## Original instructions on synthetic storage

The [extractor](../scripts/extract_action33_slot_32.py) uses the existing guarded R31-B machine and original lookup callees. Each of 80 cases starts with fresh synthetic memory, runs the original initializer on the selected slot, executes lookup `008968f0` to return its actual staff pointer, then passes that returned pointer into a separately prepared `006e0d00` function-entry frame. The schedule spans club IDs 0..3 and roster indices 0..19. Table rows, database counts, staff/attribute storage, manager state and CPU frames remain labelled synthetic inputs.

The initializer's expected member writes are authored independently. Complete nonstack regions are compared after each entry against admitted changes. Ordered data/stack access digests, trace digests, complete region hashes and register observations are retained. The initializer and lookup verify actual return ESP/EIP, receiver/result and nonvolatile integer registers. This is not independent reconstruction of all stack bytes, flags, or a TypeScript comparison.

Placement executes the read at `006eaf77`, observes the original-produced zero, loads the saved context pointer at `006eaf7a`, tests CL and takes `JZ 006eaf8f`. The harness stops before reading context `+0x4792`. The original path would next read `[owner+0x1c]` at `006eaf95`, then prepare `(staff,club)` for `006eafa0 -> 004cf5f0` with ECX from `00ae1050`. No owner/club value or contract-lookup result is injected. The focused raw listing provides a next producer lead: `006b7f41` loads EDX from `[EBP+8]`, `006b7f45` aliases incoming ECX in EBX, and `006b7f4e` stores EDX at `[EBX+0x4792]`. The listing does not establish a complete enclosing function or prototype. Its incoming owner argument, and the owner's `+0x1c/+0x20` club members, remain required original state producers.

The five placement arguments retain their distinct provenance: `(match, returned_staff, 0x89abcd00|club, 0xa5a50000|index, 0x89abcd80|club)`. The third and fifth low bytes differ in every case. Slot `+0x69` and `+0x6d` continue to alias the actual original lookup result and its attribute pointer. The new initializer's zero at `+0x27` is preserved through both earlier entries until the observed read.

## Nonnull status remains at CRT initialization

On each machine a separate original `0062ed70` entry receives the actual nonnull staff pointer with ECX loaded from the still-zero `00b63d28`. The original code passes that record to `0062c680`, initializes date storage through `0054a110`, and enters registration `0094627a -> 0094620d`. It stops before `00946214 -> 0094bef1`, with the outgoing exit-list-base argument zero from original loader-zero global `00de4638`.

Complete nonstack changes are limited to date fields, the static flag and the SEH-chain link. No lookup-object member is dereferenced before this stop, no nonnull lookup object is fabricated, and no status/effect return is claimed. R31-B's null-record diagnostic observations are unchanged prior evidence and are not re-executed by this nonnull-only schedule. The independent constructor's first Windows boundary remains `0062a6b1 -> GetLogicalDriveStringsA`, also prior evidence.

## Integrity, privacy and reproduction

The [compressed oracle](../evidence/action33-slot-32-oracle.bin) contains compact synthetic observations and digests, without original code bytes, source strings, pages or bulk listings. The new private export manifest SHA-256 `4a50131744515c61a2f18ed4149342950e81c0e051bb79399aaefd349737ed3d` pins the disposable function creation/status, assembly and caller evidence. Inherited state, staff, focused lifecycle, support and status exports retain the R31-B hashes. Capstone compares **875 instructions in 20 selected ranges** against the pinned native addresses, mnemonics and operands; unvisited static ranges are not execution coverage. The four stages execute **25,280 original instructions** (67 initializer, 135 lookup, 66 placement and 48 status instructions per case).

```text
python -B scripts/extract_action33_slot_32.py PRIVATE_PE PRIVATE_STATE PRIVATE_STAFF PRIVATE_LIFECYCLE PRIVATE_SUPPORT PRIVATE_EXPORTS_25 PRIVATE_SLOT_EXPORTS evidence/action33-slot-32-oracle.bin
python -B scripts/verify_action33_slot_32.py PRIVATE_PE PRIVATE_STATE PRIVATE_STAFF PRIVATE_LIFECYCLE PRIVATE_SUPPORT PRIVATE_EXPORTS_25 PRIVATE_SLOT_EXPORTS evidence/action33-slot-32-oracle.bin evidence/action33-slot-32-validation.json
node scripts/check-action33-slot-32.mjs
npm run check
```

The [verifier](../scripts/verify_action33_slot_32.py) regenerates evidence under normal Python and `-O`, checks byte identity, and uses explicit exceptions for specimen, manifest and native-operand integrity. Negative probes reject a changed initializer field, wrong side-read field and wrong slot context store during actual original-instruction execution. Privacy gates scan compressed and bounded expanded bytes, plus authored task files, for raw/hex/base64 code and diagnostic-source samples; injected raw/hex fragments and oversized expansion are rejected. The [validation receipt](../evidence/action33-slot-32-validation.json) records counts and gate results.

Normal and optimized Python evidence and validation receipts are byte-identical. All nine negative probes pass. The retained checker validates schemas, hashes, schedule, byte aliases, argument provenance, exact frontiers and independent semantic mutations; it and the full `npm run check` pass under Node 24.19.0. Coordinator adoption registers it in the shared runner and records independent review in the queue. No atlas, canonical native database or checkpoint file is changed.

# R36-B: source eligibility and contract-row production boundaries

Original entry `004c7560` now executes its real stack-temporary constructor and stops **before `004c75a4 -> 00944e46`**, requesting `staff_count*0x50` bytes. Separate original `004c79a0` entries on empty synthetic storage stop before their allocator at `004c7a02`. A separate exhaustive interior gate confirms that nonnull source DWORD `+39` and class byte `+3d` in `{0,6,7,8,9,10,11,12,13,15}` admit row reservation. No allocator returns, auxiliary indices, manager rows or lookup returns are supplied or executed.

The specimen is the 7,192,576-byte PE32 x86 executable SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline is merged main `d984a187df89656313a76db249e56b91735ed984` after PR #127. All addresses are virtual unless explicitly marked PE file offsets. Names and partial field roles remain research labels. This extends [R35-B](action33-aux-35.md), [R34-B](action33-contract-34.md), [R12](contract-boundary-12.md) and [R13](contract-dependencies-13.md); it does not join their disconnected execution windows into a live setup.

## Initializer entry and first allocator

`004c7560` saves its ECX receiver in EBX, registers an exception frame, and calls `0085e410` at `004c7587` with a stack temporary. This helper calls original `0054a110` twice to initialize two eight-byte date groups, writes selected sentinel/zero fields, restores FS:[0], and returns its receiver in EAX with plain RET. It does not zero the whole temporary. The helper's complete contiguous 99-byte body is PE-only decode; the date helper is independently compared with its native export. All three calls execute without stubs.

At `004c758c` the initializer loads staff count `00ae2364`, writes that DWORD to receiver `+4` at `004c759a`, computes `count*0x50` with wrapped 32-bit LEA/SHL, and pushes it for `00944e46`. Nine synthetic counts, including zero and overflow cases, execute **61 original instructions each** to pre-`004c75a4`. The full nonstack state and complete stack are checked against independently authored writes, including temporary fields, call return addresses, saved registers and the active exception link. No allocator is entered, no allocation result is forged, and receiver `+0/+8` are not initialized by this prefix. Its patterned receiver storage is explicitly supplied synthetic storage, not a constructed live manager. Overflow inputs demonstrate arithmetic only, not valid staff counts.

The static continuation stores the allocator result to manager `+0` at `004c75ae`. A null result enters diagnostics and bypasses count clearing and the scan. Only its nonnull branch clears manager `+8` and begins the source loop. Therefore capacity publication before allocation is not proof of allocated or initialized rows. Original `00944e46` and the heap/runtime dependencies identified in R35-B remain the first unresolved boundary on this initializer entry.

## Eligibility, reservation and exact index writes

The 512 separate interior windows start at `004c7832`, with a mapped synthetic source record in EDI. They cover both null/non-null DWORD `+39` and every byte value at `+3d`. A null context skips the class read. Exactly ten cases admit reservation: the class values above with nonnull context. Eligible windows stop before `004c786c`; all others stop before loop continuation `004c7907`. Complete mapped memory remains unchanged, including the stack. These windows do not execute earlier scalar/date work, load source `+52`, call the reserve helper, or produce an index.

The complete initializer body is independently compared with native operands. Its **static** publication sequence is:

| Site | Original effect | Scope |
| --- | --- | --- |
| `004c786c..004c7873` | Load source DWORD `+52`; call `004c79a0` with ECX=manager and raw32 flag 1 | Static; prior scalar result unresolved |
| `004c7878..004c787a` | Signed-negative EAX skips index publication and row constructor | Static failure branch |
| `004c788e` | Write returned raw32 index to `auxiliary_base + source.ID*0x4f` | Static DWORD store; uses source ID, not loop ordinal |
| `004c789b` | Write source DWORD ID to `manager.rows + index*0x50` | Static DWORD store; does not populate row `+4` |
| `004c78a2` | Call `0085e960` with ECX=row and arguments `(source, source.DWORD+52)` | Static; row constructor not executed |

There is no source-ID bound at these publication instructions. A nonnegative reserve result selects a row with wrapped 32-bit arithmetic; valid backing extents and source IDs are external state requirements. The `0x4f` auxiliary stride and `0x50` manager-row stride must remain distinct.

Original `004c79a0` accepts ECX receiver and one DWORD flag; full native comparison confirms both normal `RET 4` exits. Zero flag can reuse the first existing row whose initial DWORD is `-1`; nonzero flags skip reuse. Its append path compares count with capacity for equality, increments capacity by 200 before growth, and calls `00945667` for a nonnull old base or `00944e46` for a null base. It stores the allocation result to `+0` before checking null. Diagnostics can then return `-1`; there is no local rollback of capacity/base. Count differs from capacity selects append without an independent count-less-than-capacity guard. A successful no-growth append increments count and returns its old value; those append/return paths are static here.

Five separate original reserve entries start with zeroed synthetic receiver storage and flags `0,1,2,80000000,ffffffff`. They all reach **pre-`004c7a02`** with capacity=200, base=0, count=0 and outgoing allocation size 16,000. The zero flag takes 23 instructions; the others take 18. Exact nonstack and stack writes are independently checked. This establishes a growth-request frontier and the write-before-allocation order on empty storage; it does not establish a valid manager lifecycle, allocation failure return, reused row or successfully reserved index.

## Row contents and lifetime remain dependencies

Selected **PE-only static** row-constructor instructions show an original `0054a110` call followed by `0085e9a1 -> 00549f70`. Later `0085ea42` loads source `+39` to EBP; `0085ea55 -> 00540a50` can replace that context when the helper returns nonnull and its pointed local is zero. `0085eaf0..0085eaf3` read DWORD `[EBP]` and write it to row DWORD `+4`. This is the field compared with the target context ID by R13's lookup. The publication caller's source-ID write alone cannot establish this field. Selected return-tail instructions corroborate `RET 8` at `0085f79c`. No whole constructor contract, numerical result, context resolution or row contents are executed or claimed.

Earlier in the initializer, every scanned source first calls `004d0c60`; its EAX is stored to source `+52`, and source/date predicates can invoke further helpers and RNG before eligibility. R12/R13 describe those static dependencies. Starting at the eligibility window skips that work, so its ten admitted cases do not prove ten reachable row creations or a complete source scan. The failed-reservation continuation can also reach the later row-byte update under additional attribute/ID predicates; the inherited static invalid-address concern is not a newly observed runtime failure.

The selected original setup site publishes constructor EAX to `00ae1050` at `008297fc` and invokes this initializer at `00829809`. R35-B's independent auxiliary allocation/default path remains required: its default DWORD indices `-1/-1` are not populated rows. The growth call takes the old row base and its result overwrites manager `+0`; a borrowed row pointer has no demonstrated stability or lifetime across that call. Teardown invokes `004c74f0`, frees and clears the receiver before separately freeing/clearing the auxiliary base (`00830378/0083037e/00830386`, then `008303b6/008303be`). These are native-compared selected static sites. No release semantics, complete shutdown order, save reconstruction or lifetime extension is executed.

## Evidence and reproduction

The [extractor](../scripts/extract_action33_contract_row_36.py) retains **446 native-compared static instructions**, separately from **98 PE-only decoded instructions**. Neither static count is an execution count. The executed domain is nine initializer entries, five reserve entries and 512 eligibility windows, **7,466 original instruction steps**. No allocator, index publication, row constructor or contract lookup return executes. No TypeScript implementation, full match setup or gameplay outcome is claimed.

Private input manifests are pinned to `12bcb7700e4982f1cc8d15786f27cc018db58fdba02de89b0e1eb81c10a6076c` for checkpoint-11 contract exports, `92d0708d6eada4983366d522314881e04c293b0bfaab4c467eb08f71992d7741` for checkpoint-29 support, and `b338531e13c4626c151a5538fe871488698b056bfbb00fb9f9e669b82e4dd59a` for checkpoint-28 state. Every manifest file's size and digest is verified. Original bytes, strings, exports, tables and native projects remain private and read-only; the [oracle](../evidence/action33-contract-row-36-oracle.bin) contains only synthetic observations, addresses, widths and digests.

```text
python -B scripts/extract_action33_contract_row_36.py PRIVATE_PE PRIVATE_EXPORTS_12 PRIVATE_SUPPORT PRIVATE_STATE evidence/action33-contract-row-36-oracle.bin
python -B scripts/verify_action33_contract_row_36.py PRIVATE_PE PRIVATE_EXPORTS_12 PRIVATE_SUPPORT PRIVATE_STATE evidence/action33-contract-row-36-oracle.bin evidence/action33-contract-row-36-validation.json
node scripts/check-action33-contract-row-36.mjs
npm run check
```

The [verifier](../scripts/verify_action33_contract_row_36.py) regenerates byte-identical evidence under normal Python and `-O`; its explicit integrity gates remain active in both. Negative probes cover specimen/manifests, executed stride, temporary-store destination, reserve capacity and eligibility, static row-index width, raw/hex/base64 code samples and bounded decompression. The standalone [checker](../scripts/check-action33-contract-row-36.mjs) checks retained schemas, arithmetic, exhaustive eligibility, call boundaries and claim limits without private inputs. Normal and optimized verifier receipts match; all thirteen negative probes passed. The checker passes directly and through the shared runner under Node 24.19.0; this integration registers it there. The TypeScript validation registry, frontier and canonical native project remain unchanged.

The exact next blocker is `004c75a4`'s unresolved original row allocation, plus the independently unresolved manager constructor/auxiliary allocation and earlier scalar/date state. R34-B therefore remains stopped before `004cf62b`; no auxiliary record or returned contract row has been fabricated to continue it.

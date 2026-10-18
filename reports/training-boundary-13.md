# Training storage boundaries — investigation 13

The five owned functions expose two packed regions in an ECX-supplied training manager, copy a 54-byte block in either direction, and allocate/default a separate array of six-byte rows. They are not five constructors. Only `008b3c50` allocates; constructor and cleanup evidence comes from read-only dependencies.

Specimen: PE32 `cm0102.exe`, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Baseline: `87ea0f39d5dcb62fe6969ad6570c3dca8b152673`, checkpoint 12. All instruction addresses are virtual addresses; offsets below are bytes. The `training_manager.cpp` anchor at `00a8ccd0` provides navigation only. Contracts below come from original instructions, decoded with Capstone 5.0.7 and compared against every instruction in the five supplied native exports: 283 instructions total. No game execution or behavioral equivalence is claimed.

## Exact owned boundaries

Define `i = u32(read32(00ae2364) - read32(key) - 1)`. The signed checks admit exactly the bit patterns `0..15`; arithmetic wraps at 32 bits. The identity represented by `key[0]` and the meaning of global `00ae2364` remain unresolved.

| Entry / body bytes | Assembly-supported contract |
| --- | --- |
| `008b4cd0` / 212 | ECX = manager, stack slot 1 = key pointer; `RET 4`. Rejects null key before dereferencing (`4cda..4cdc`); reads its first dword and applies the index checks (`4d0d..4d1e`). Success returns EAX = `manager + 0x652d + 54*i` (`4d20..4d33`). No allocation or successful-path store. Invalid input reaches diagnostics then explicitly returns zero. |
| `008b3930` / 188 | ECX = manager, stack slot 1 = key pointer, low byte of stack slot 2 = **signed** selector; `RET 8`. Dereferences the key **without** a null guard (`3940`). Valid index uses selector `j` if `0 <= signed8(j) < 10`, otherwise `j = 1` (`394d..395f`). Returns EAX = `manager + 155*(7 + 10*i + j)` (`3962..3973`). Invalid index reaches diagnostics and explicitly returns zero. No allocation or successful-path store. |
| `008b35a0` / 157 | ECX = manager, stack slots = key, output buffer; `RET 8`. Calls `008b4cd0` with the same receiver (`35a0..35ab`). On success copies **13 dwords + one word = 54 bytes** from returned block to output (`3620..3630`). No explicit return-value contract. Does not validate the output pointer or call an update helper. |
| `008b23b0` / 182 | ECX = manager, stack slots = key, input buffer; `RET 8`. Saves receiver in EBX, calls `008b4cd0`, then copies **54 bytes** from input into returned block (`243a..244c`). Calls `008b2880` with original receiver and stack arguments `(read32(key+0x39), key)` (`2449..2454`). No explicit return-value contract. Final block content may differ from input because the callee can mutate it. |
| `008b3c50` / 230 | ECX = manager; no stack arguments, plain `RET`. Calls `00945501(read32(00ae236c), 6)` (`3c50..3c61`), immediately stores returned pointer, including null, to manager `+0x651d` (`3c69`). On nonnull result iterates while signed loop counter is less than the reloaded global count. Source rows start at `read32(00ae23c4)` and advance `0x46`. For each row, unchecked dword ID at `+0` indexes destination `pointer + 6*ID`. Clears bit `0x20` in byte `+5`, then writes byte `+0` = 1 when **signed8(source[0xf]) < 15**, else 6 (`3cee..3d2b`). No semantic return value established. |

The copies are forward x86 string operations; neither function clears DF, checks buffer length nor provides `memmove` overlap guarantees. The contract assumes the usual clear direction flag and valid buffers. The copy-in path requires the key to be readable through `+0x3c`, beyond the locator's four-byte minimum.

## Shared state and layout evidence

Successful accessors return interior aliases into the caller's receiver. They do not return separately owned allocations. Their contents also depend on the current `00ae2364`, so a key alone does not identify stable storage independently of that global and manager lifetime.

The constructor-context call to `009463af` at `008b0ef8` supplies receiver, stride `0x9b` and count `0xa7` (155 and 167). The arithmetic is exact: `167*155 = 0x651d`. The 155-byte accessor addresses indices `7..166`, ending exactly where the separate pointer field at `+0x651d` begins. This supports a region of seven preceding records plus 16 groups of ten; meanings of the preceding records and selector values are not recovered. The 54-byte accessor spans `+0x652d..+0x688c`: `16*54 = 0x360`, ending at `+0x688d`. The same constructor initializes 96 nine-byte subrows there, setting each leading dword to `-1`, next dword and final byte to zero (`008b1016..008b1034`). Thus each 54-byte block contains six such subrows in this default path.

Two observed callers load manager from global pointer `00de1f44`. `008b0a00` reads ten 155-byte records and the 54-byte block into another object's buffers (`008b0a9a..008b0af3`); `008b0b40` copies those records back and calls the copy-in function with its buffer at `+0x7a3` (`008b0b75..008b0bda`). These are evidence of shared receiver use and editing/snapshot-style traffic. They do not establish a singleton invariant, thread safety, a complete editor lifecycle or persistent disk effects.

## Allocation/defaulting and lifecycle limits

Allocator dependency `00945501` multiplies its two 32-bit arguments, rounds allocation sizes, uses heap paths and returns EAX. Its ordinary heap call is IAT `00967154`, identified from the PE import table as `KERNEL32.dll!HeapAlloc`, with flags 8; alternate successful paths call fill helper `0094a640` with zero (`00945597..009455ac`). Selected fill instructions corroborate byte/dword filling. This supports a calloc-style zeroing allocation, not a C++ row constructor. Untouched row bytes remain zero in that allocation domain; the owned loop explicitly sets only bytes 0 and 5. Dense, valid nonnegative source IDs are a caller/data precondition: this function does not bound IDs against the allocation count or validate the source pointer. The allocator multiplication is 32 bits; large/negative counts are not proven safe.

Constructor context `008b0ec0` first tries `008b10d0` when its stack argument is nonzero; a nonzero result bypasses `008b3c50`. Otherwise it calls `008b3c50` at `008b1011`, initializes the inline nine-byte rows, calls a further defaulting helper and clears a word at `+0x688d`. `008b1070` tests manager `+0x651d`, passes it to `009452ca` at `008b107e`, and clears the pointer at `008b1086`. That allocator-family release helper can reach imported `HeapFree` (IAT `0096715c`). This supports manager-held allocation and cleanup; it does not prove every lifecycle path or destructor invocation. Calling `008b3c50` repeatedly overwrites the old pointer without a release; null allocation also overwrites it. The function itself supplies no repeated-call safety.

The copy-in callee is materially mutable: at `008b28f4`, `008b2880` locates the same 54-byte block, runs a six-subrow stride-nine loop, can reset dword/dword/byte fields (`008b293d..008b2945`) and writes individual subrow bytes (`008b2b89`). Its complete transitive behavior and RNG effects remain open. This is enough to reject a pure setter interpretation of `008b23b0`; no full refresh algorithm is claimed.

## Diagnostics and uncertainty

All owned failures call the same chain `00944cff → 0090d130 → 00944c9f → 005e8290` and then clear dword global `00b67a34`, if the helpers return. Diagnostic numbers are `0x31a` (copy-in lookup failure), `0x604` (copy-out lookup failure), `0x68f` (155-byte invalid index), `0x6e3` (null allocation), `0xa20` (54-byte null key) and `0xa2a` (54-byte invalid index). The copy wrappers add their own diagnostic after a locator has already diagnosed and returned zero. Only the two locators explicitly set EAX to zero on failure. Diagnostics' external effects and failure termination behavior are not fully traced.

Confidence is high for instruction widths, formulas, branch conditions, copies and direct writes; moderate for lifecycle/semantic labels. No successful accessor, copy-out or initializer body directly calls the RNG helper. That does not establish transitive RNG purity, especially for copy-in. Training outcomes, selector meanings, source record identities, synchronization, persistence and complete initialization remain unresolved.

## Reproduction and proposed annotations

`evidence/training-boundary-13-sites.json` retains selected instruction sites, original-span digests, calls, PE imports and whole-owned-body native agreement. `evidence/training-boundary-13-findings.json` provides compact contracts and confidence. The private export manifest SHA-256 is `fa2728212d3189f2a0ec9f4db14b2355b0da8457bc9bff091d5c2b442b38a489`.

```powershell
python scripts/extract_training_boundary_13.py --binary <private-cm0102.exe> --native-dir <private-exports-13> --output evidence/training-boundary-13-sites.json
npm run check
git diff --check
```

The extractor requires Capstone 5.0.7 and verifies the executable hash. With `--native-dir`, it verifies the supplied manifest and every listed export hash before comparing the five complete owned listings. No original bytes, bulk disassembly or native database are retained. Optional name-only proposals are in `evidence/training-boundary-13-annotations.json`; no prototype or structure changes are proposed.

Verification: extractor passed against the pinned PE and hash-verified native exports; `npm run check` passed on Node v24.19.0. Those repository checks cover retained earlier fixtures and metadata, not execution of these training functions. All five owned bodies are `contract-supported` at whole-body static scope; the named context functions remain `boundary-mapped` dependencies.

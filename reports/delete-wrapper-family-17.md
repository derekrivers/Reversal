# A 192-function conditional release wrapper family

The investigation-08 atlas has 197 **non-`Unwind@`** functions with a 30-byte Ghidra-inferred body. Complete pinned-PE decoding shows that **192** have the same eleven-instruction control/data-flow shape; five have different bodies and are explicitly excluded. These 192 are mechanical local contracts, not 192 recovered object types or gameplay algorithms.

Each wrapper saves the receiver from ECX in ESI, calls its own direct target once, then tests **bit 0 of the low byte of its single stack argument**. If that bit is set, it pushes the original receiver and calls `00944c94`, the one-argument forwarding wrapper mapped in [the unwind-target report](unwind-targets-16.md). Both paths put the original receiver into EAX, restore ESI and return with `RET 4`. Thus the first callee always runs, and the conditional second call receives the original receiver. The wrapper itself has no direct RNG or non-stack state write. Its return may be a pointer whose storage was released transitively; callers must not infer continued validity from EAX alone.

The first call target is distinct for every entry, but it is **not always adjacent** to the wrapper: 185 targets sit at entry+0x20 and seven are elsewhere. The branch skips precisely the conditional call and stack cleanup. No object layout, vtable, destructor effect, or `009452ca` release behavior is established by this family shape alone. Calling it a conditional release *wrapper* is a code-flow description, not a recovered original C++ declaration.

[`extract_delete_wrapper_family_17.py`](../scripts/extract_delete_wrapper_family_17.py) verifies all 197 candidate spans against the pinned PE, fully decodes every 30-byte body, requires exact operand/branch/stack shape for the 192 selected wrappers, matches the direct callees in the atlas, and compares three widely separated members against Ghidra 12.1.4/JDK21 read-only exports from checkpoint 15. The [summary](../evidence/delete-wrapper-family-17-summary.json) lists counts and five exclusions; the compact [registry](../evidence/delete-wrapper-family-17-rows.jsonl) retains per-body SHA-256 and direct targets without original code bytes or bulk assembly. Private sample-export manifest SHA-256: `afcbab808d685d44e4a93ef4988d06f15072458a2b8b5a67b32baea105a27a6c`.

Run with Capstone 5.0.7:

```powershell
& <Capstone-Python> scripts/extract_delete_wrapper_family_17.py --binary <private-exe> --atlas evidence/code-atlas/functions.jsonl --exports <private-sample-exports> --summary evidence/delete-wrapper-family-17-summary.json --rows evidence/delete-wrapper-family-17-rows.jsonl
```

The complete original images and Ghidra listings stay private. These 192 entries should be tracked as a separate boilerplate family alongside the 3,873 frame-dependent unwind entries, rather than silently counted as recovered game behaviors. The remaining **5,176** inferred non-unwind functions do not belong to this 192-wrapper family; earlier static semantic and execution-validation registries cover some of them separately.

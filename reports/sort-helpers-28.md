# R28-A — sort tail-selection and byte-swap helpers

This investigation maps two complete local x86 bodies called beneath the R27 generic sorter `00945333`. It validates a bounded TypeScript reconstruction of the call-free byte swap at original entry. The helper mapping does not validate the connected sort, comparator or league standings.

Addresses are virtual addresses unless explicitly labelled as file offsets. The PE32 x86 specimen is 7,192,576 bytes, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Native read-only exports came from checkpoint-27 archive SHA-256 `d2836fd1b28d194dbfda32454106f9af23495809f09a408ed1ee072e6c4b7de1`; export manifest SHA-256 `058514c602952b66abeade64ba9a28bbab3873c16503af4ca0f834fb2a6d2ddc`, exact-old preflight SHA-256 `9f9e52088fc32356aebecb6fc39ba78fea96e14f359383afb01362287409fbb2`.

| Entry | PE file offset | Body SHA-256 | Body bytes | PE/native instructions | Local CFG edges | Execution status |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `00945487` | `00545487` | `e9602fb435ba6e492a49997a9809e95763bc31dcb8f36acdd7a1bdd6620b72de` | 78 | 39 | 42 | Static local body |
| `009454d5` | `005454d5` | `8cc073e4161c512ba0dc2a7bb381d401f4f08e67cba8d2176b495fd552a36df1` | 44 | 23 | 25 | Static local body and bounded original-entry validation |

The [extractor](../scripts/extract_sort_helpers_28.py) verifies every PE opcode and operand against the saved native assembly, every local branch target, full reachability, call sites, direct memory widths and the exact old native names/body sizes. The [site evidence](../evidence/sort-helpers-28-sites.json) retains instruction addresses, local CFG edges, memory-access sites and hashes without distributing instruction bytes or bulk decompilation. Both bodies have full static local instruction coverage.

## `00945487` — select a record and swap it to the tail

Four DWORD arguments arrive at `[EBP+8,+0xc,+0x10,+0x14]`: base pointer, **inclusive** end pointer, element width and callback address. It returns by plain `RET`; the caller removes 16 argument bytes. EBP, EDI, EBX and ESI are saved/restored on their active paths. Volatile registers have no established semantic return value. There is no guard for a null callback, zero width, address wrap or mapped row range.

The unsigned `CMP EDI,EAX`/`JBE` at `00945491` exits when `end <= base`. Otherwise it begins a scan at `base+width`. At each candidate through `end`, the helper pushes the current best pointer then the candidate pointer; the indirect call at `009454ab` therefore receives `callback(candidate,best)` in cdecl stack order. The two `POP ECX` instructions remove those argument words. A **signed positive** callback result at `009454b2` selects the candidate as the new best. A zero or negative result keeps the previous best. This establishes call order and selection behavior, not the callback's own effects or comparison law.

After the scan, the helper calls `009454d5(best,end,width)` at `009454c0`, then subtracts width from end and repeats while the unsigned end pointer remains above base. Thus the direct record-byte mutations come from the swap callee; this local body directly reads/writes its stack argument slot `+0xc` as a scan cursor, plus stack traffic from saves and calls. Its single direct call is `009454d5` and its single indirect call is the callback. In the R27 sort, a small interval reaches this helper; the R26 comparator has separately validated bounded row comparisons, but its invariants and effects are not established for a connected sorter execution. This lane therefore retains the partition helper as static only.

## `009454d5` — forward bytewise swap

Three DWORD arguments are first pointer `[ESP+4]`, second pointer `[ESP+8]` and byte width `[ESP+12]` at entry. After saving ESI, the width is read at `[ESP+0x10]`. The function returns by plain `RET`; its caller removes 12 argument bytes. EBX and ESI are preserved. If pointers are equal, it avoids reading width and touches no data bytes. If width is zero with different pointers, it touches no data bytes. In the active case, each iteration reads a byte from the second pointer, reads one from the first, writes the second byte to the first pointer, then writes the original first byte to the second pointer. The byte reads and writes are **interleaved** and forward, so overlapping ranges do not have the semantics of swapping two pre-copied blocks. EAX and ECX finish one byte beyond their corresponding start pointers; EDX retains the upper three bytes of `width-1` and the last original first-side byte in its low byte. These volatile values are checked but not interpreted as an application return.

The [original-entry oracle](../evidence/sort-helpers-28-swap-oracle.json.gz) contains 640 deterministic synthetic cases: eight seeds, ten widths `0,1,2,3,4,7,8,15,16,31` and eight pointer separations `0,1,2,3,7,16,32,64`. They execute 47,768 x86 steps, covering all 23 instruction starts and all 25 local edges, including early returns and overlap. The [TypeScript reconstruction](../reconstruction/sort-swap-28.ts) and [checker](../reconstruction/check-sort-swap-28.ts) compare all nine general/stack/instruction registers at return, ordered data reads/writes with values, and whole mapped data and stack-page SHA-256 values. The oracle uses only synthetic memory; no original row contents are retained. The admitted API requires both byte ranges to fit entirely within the synthetic `0x300000..0x300fff` data page, even for early-return cases. It rejects stack/code aliasing, page crossing, widths above 31 and unsupported entry/stack states.

The [findings](../evidence/sort-helpers-28-findings.json) distinguish the static and executed scopes. The [name-only annotation proposal](../evidence/sort-helpers-28-annotations-proposal.json) supplies exact old names/body sizes and leaves prototypes/comments/structures unchanged. Only the coordinator may apply it to the canonical native database.

## Reproduce

From this checkout root with the pinned private PE and checkpoint-27 exports:

```text
python scripts/extract_sort_helpers_28.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_28 --preflight PRIVATE_PREFLIGHT_28 --output evidence/sort-helpers-28-sites.json
python scripts/emulate_sort_swap_28.py PATH_TO_PINNED_EXE --exports PRIVATE_EXPORTS_28 --preflight PRIVATE_PREFLIGHT_28 --sites evidence/sort-helpers-28-sites.json --output evidence/sort-helpers-28-swap-oracle.json.gz
python scripts/check_sort_helpers_28_negative.py
node reconstruction/check-sort-swap-28.ts
npm run check
```

Normal and `python -O` extractor outputs match byte-for-byte. Normal and `-O` oracle outputs also match byte-for-byte. The negative script rejects three mutated input classes in both modes; the TypeScript checker rejects tampered result/effect controls and malformed domains. Node 24 repository checks do not reopen native Ghidra, nor do these cases prove a complete sort.

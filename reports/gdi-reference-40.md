# R40: runnable GDI build has bounded penalty-code anchors

The installed `cm0102_GDI.exe` ran a private demo save and allowed direct window control and read-only WOW64 process inventory from the local session. It is a **different executable** from the pinned `cm0102.exe`. The [bounded comparison checker](../scripts/check_gdi_anchors_40.py) now ties six local instruction intervals in the two disk images to exact SHA-256 identities; its [receipt](../evidence/gdi-code-anchors-40.json) contains addresses, file offsets, lengths and digests, never instruction bytes.

| Local interval | Pinned virtual address | GDI virtual address | Exact bytes |
| --- | ---: | ---: | ---: |
| Action33 entry | `00702050` | `00701a80` | 64 |
| Keeper call through effect-call neighborhood | `00702416` | `00701e46` | 222 contiguous |
| Keeper callee entry | `00700420` | `006ffe50` | 64 |
| Effect callee entry | `006cfe10` | `006cf840` | 32 |
| Score-effect entry | `006d0980` | `006d03b0` | 24 |
| Small-bound RNG entry | `0090cfc0` | `0090c860` | 16 |

The pinned image is 7,192,576 bytes, SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. The GDI image is 7,188,480 bytes, SHA-256 `0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b`. Both have preferred image base `00400000`; the code intervals above are in executable `.text` and each pinned byte sequence has one exact occurrence in the GDI file. In particular, the 222-byte interval has a `-0x5d0` virtual-address shift. This establishes only local disk-code identity at those intervals. Other code, mapped data, call effects, process state, state initialization and match outcomes may differ. A GDI UI penalty is **not** an original pinned-executable action33 hit.

The private GDI process inventory succeeded without administrator intervention. A single idle-time WOW64 context snapshot of each of three threads recorded x87 control word `027f`; this is an idle observation, not the match-entry control word. A bounded read-only watch sampled the main thread 1,000 times during a replayed first half, checking EIP in the mapped 192-byte candidate interval beginning at `00701e46`. It did not hit. The watch suspends and resumes only that thread per probe, which can affect scheduling; exact code and live data were not published. The non-hit does not show that action33 was absent between samples.

The replay also demonstrates a save limitation. The same private pre-Midtjylland `holly4` checkpoint loaded successfully under GDI twice. One run ended Newcastle 2-1 Midtjylland with a Woltemade penalty at 75. The later run ended 4-0 with no penalty listed (Woltemade 12, 51; Mora 56; Tonali 85); referee and weather differed. The save therefore does not, on its own, provide a repeatable penalty test. The later replay was saved separately before restarting, and the latest post-Coventry checkpoint `holly13` was restored through the game UI. Private raw saves and process captures remain outside Git.

Next, a capture from a **real pinned-executable** match frame remains required for pinned-runtime state and outcome claims. For the controllable GDI build, an exact mapped-code interval can guide a narrower live capture, but it must retain the GDI identity and private state provenance. Capturing live pointers without their referents and lifetime, or treating a save as a deterministic RNG seed, would leave the current participant/lookup-state blocker unresolved.

To repeat the disk-code comparison locally, with both executables present:

```text
python scripts/check_gdi_anchors_40.py PINNED_EXE GDI_EXE
```

The checker fails on either wrong executable identity, a malformed PE32 section map, a non-executable code mapping, changed anchor bytes or a non-unique GDI match. It has no process access and does not read saves.

The local checker passed under Python 3.13.7 with and without `-O`. A wrong-executable input and a one-byte change at the 222-byte anchor were both rejected. The full retained research check passed under bundled Node 24.19.0; it checks existing fixtures and does not rerun this private binary comparison in CI.

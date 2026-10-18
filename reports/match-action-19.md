# Investigation 19: coordinate emission and immediate boundary events

R19-A maps `006cd770` and its direct callee `006cd490` as complete local static contracts. The first perturbs and commits match coordinates/heading, optionally visits slots, and delegates exterior-coordinate handling. The second conditionally writes status/side bytes and emits a commentary token. Callee execution, connected shot/match outcomes and runtime termination remain open.

The pinned PE SHA-256 is `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`; baseline is checkpoint 18, commit `0ab803b3adb19eb9ecdb70d4a31d759127376b78`. Addresses and field offsets below are hexadecimal; explicit decimal values and counts are labelled. Function/field identities remain research labels.

| Virtual entry | Body bytes / instructions | Branches / calls / RNG sites / non-frame stores | Raw file offset |
| --- | ---: | ---: | --- |
| `006cd770` | 685 / 216 | 36 / 19 / 13 / 11 | `2cd770` |
| `006cd490` | 346 / 102 | 9 / 6 / 0 / 11 | `2cd490` |

The [generated sites](../evidence/match-action-19-sites.json) record every branch successor, call, explicit state store, return, normal stack join and RNG bound origin. Capstone 5.0.7 decodes each complete original-PE body independently, then compares every address, mnemonic and operand with the pinned read-only Ghidra export. Both bodies are contiguous through their final RET; no missing switch arms, out-of-body branches or unreachable exported instructions occur. The three supplied R18 incoming calls to `006cd770`, and the call from there to `006cd490`, are independently decoded; this is not a caller census.

Notation: `m` is entry ECX; byte operations wrap modulo 256; `s8` means signed byte; `R` is `0090cfc0`. Descriptions of fields mean fresh loads at the documented points, rather than snapshots held across every call. The coordinate/heading names are mechanical research labels. Neither entry checks `m` for null.

## `006cd770`: perturb and commit coordinate state

Entry ECX=m; seven four-byte stack slots contain `(x,y,kind,side,flag,scan,last)` at entry ESP+4/+8/+c/+10/+14/+18/+1c. The first six are consumed through their low bytes, except that side's full slot is eventually forwarded to `006cd490`. Last is a full dword pointer. Side and x low bytes can be overwritten in the caller argument area. The single normal return is RET1c at `006cda1a`. ESI/EDI and EBX/EBP are saved/restored; no incoming EDX value is consumed. There is no normalized EAX result.

1. If dword `m+f582` is nonnull, call `006f0970` with that receiver and no stack arguments. Then write input x to byte `m+8ea7`, input y to byte `m+8ea8`, and, only if it differs from ff, write ff to byte `m+8eae`. If input side's low byte is ff, draw `R(2)` and replace only that argument byte with `(EAX==0)`; upper bits of the argument slot survive.
2. Select an exterior-x route only when flag==0, signed current x is outside decimal 2..6, and `R(4)!=0`. The exterior x becomes ff when current signed x<2, otherwise9; this changes the x argument byte, not the match coordinate yet. Set `b=s8(kind)+1`, draw `R(b)`, load the current y byte, subtract the result AL, then draw `R(b)` again and add AL. All coordinate arithmetic narrows to a byte. The SETGE/DEC/AND/ADD chain determines only the stored low-byte exterior x; full EAX is not a normalized coordinate.
3. Every other route enters the ordinary coordinate loop. Set b as above. Draw `R(b)`, load current x, subtract AL; draw `R(b)` and add AL, storing the candidate in the x argument byte. Draw `R(b)`, load current y, subtract AL; draw `R(b)` and add AL. If flag==0, accept immediately. Otherwise retry all four draws whenever signed candidate y<0 or y>decimal11. The current m.x/m.y are loaded again during each iteration; candidate x is not range checked. No retry cap exists locally. Thus thirteen direct RNG sites do not imply thirteen draws or any finite per-invocation maximum. Even termination is unproved for unrestricted inputs, RNG states or transitive behavior.
4. If kind==0, write0 to byte `m+8eaa`; otherwise draw `R(s8(kind)+1)` and write low8(EAX+1). Compare candidate-minus-current x/y after byte subtraction and signed extension. For zero displacement retain word `m+8ed8`; otherwise load word `b67c30+2*(24*s8(dx)+s8(dy))`. Write that heading word even when unchanged. This uses the same table address as R18's heading helper; original table values, initialization and valid index domain remain unreviewed.
5. Draw `R(4)`, then write AL to `m+8ea9`, candidate x to `m+8ea7`, candidate y to `m+8ea8`, and side byte to `m+8eab`, in that order. If side!=ff, increment byte `m+8d46+s8(side)`. Next, if signed byte `m+8d46+(side==0)>0`, subtract decimal10 modulo256. Side is not restricted to0/1; its first index uses sign extension and the second is a Boolean. These are the final direct non-frame stores in this body.
6. If scan!=0, visit two side groups, each containing decimal20 entries: receiver `q=m+4796+sideIndex*22d8+slotIndex*1be`. For each, require signed byte q+19>=0 and byte q+105==0 before drawing `R(3)`. Only result0 draws `R(2)` and calls `007160d0(q; full EAX)`. Traversal is side0 then side1, each in ascending slot order. Scan is reread at each side header. At most decimal40 entries and80 direct scan draws occur; callee RNG/effects remain separate. The register counter/stride remains fixed even if a callee changes match memory.
7. If last==0, current byte x!=4, or current y is neither ff nor0c, call `006cd490(m; full side slot)` immediately. Otherwise draw `R(4)`; result0 also selects that call. On a nonzero result, reread current y: for y==0c call `0070c040(last; 0x3f800000)` when byte last+27!=0, otherwise `0070a910`; for y==ff reverse the selection. The argument bits represent float32 1.0 but neither callee's complete input/behavior contract is proved here. If the reread y is neither value, skip both calls. Finally, skip `006cd490` only if the freshly loaded byte m+8eb2 is nonzero; otherwise call it. All routes join the one epilogue.

The initial `006f0970` call precedes the first coordinate stores; heading is stored before the mandatory final R(4); coordinate/side/counter commit precedes the optional scan; the scan precedes the last-pointer route; boundary classification is last. `006f0970`, `007160d0`, `0070c040`, `0070a910` and commentary remain transitive state/RNG/failure boundaries. The full side argument forwarded to `006cd490` retains the original upper bytes even after randomized side replacement, although that callee locally reads only its low byte.

R18 `0070d430` supplies kind3 or1 and scan1 at the three checked call sites. These calls establish concrete upstream context, but no live input domain or connected outcome proof. Other callers and all deeper effects remain unreviewed here.

## `006cd490`: classify exterior coordinates and emit immediate event

Entry ECX=m, low-byte side at entry ESP+4; all six returns use RET4. ESI is saved/restored, EBX/EDI/EBP are untouched. EDX is not an input. Only **AL** is defined: zero for current interior coordinates, one for all other normal returns. The high24 EAX bits are residual; the decompiler's apparent full-dword return must not become a normalized Boolean prototype.

If byte `m+8eb2` is nonzero, return AL=1 immediately without stores or calls. Otherwise, conditionally clear byte `m+8eae` to ff, then call `006f0970(dword(m+f582))` when that receiver is nonnull. Read coordinates after the call. Test signed x first: x<0 or x>=decimal9 takes the exterior-x route irrespective of y. For x in0..8, signed y in0..11 returns AL=0; negative y and y>=decimal12 select the table below.

| Coordinate route | Low-byte side predicate | New m+8eb2 | New m+8eae / event side | Token |
| --- | --- | ---: | ---: | --- |
| y<0, x in0..8 | side==1 | 4 | 0 | `1f77` |
| y<0, x in0..8 | side!=1 | 3 | 1 | `1f75` |
| y>=12, x in0..8 | side==1 | 3 | 0 | `1f75` |
| y>=12, x in0..8 | side!=1 | 4 | 1 | `1f77` |
| x<0 or x>=9 | any side | 2 | `(side==0)` | `1f76` |

Each event route snapshots commentary receiver dword `m+8f7a`, writes byte status `m+8eb2`, then byte `m+8eae`, then calls `006d6f70(receiver; token,m,-1,eventSide,-1,-1,0)`. The four y routes push eventSide as an immediate full dword0/1. The exterior-x route executes SETZ AL and pushes full EAX: only its low byte is `(side==0)`; high bits survive from prior computation/call state. The same low byte is stored to m+8eae. Every event route explicitly assigns AL=1 after the commentary call and ignores its result. No direct RNG occurs. There is no direct action-word, score or goal update in either body; deeper callees may perform additional work.

The status guard runs once at entry. Clearing the side and the optional `006f0970` call can precede the interior AL=0 return. Calling this function twice can therefore have different local writes/calls even with the same nominal coordinates; it is not a pure predicate. Token names and natural-language gameplay identities are not inferred from numeric tokens alone.

## Reproduction and limits

Run `scripts/extract_match_action_19.py PRIVATE_EXE --exports PRIVATE_EXPORTS_19 --preflight PRIVATE_PREFLIGHT_19 --output evidence/match-action-19-sites.json` with Capstone5.0.7. It checks the executable, manifest and preflight digests; every manifest file size/hash; both exact-old native names and absent/blank comments; all318 original instructions/1031 bytes; all45 branches,25 call sites,22 state store sites,13 RNG sites,7 normal returns and four supplied incoming calls. Normal stack joins restore entry ESP under the listed callee-cleanup assumptions, including every retry/scan backedge. This does not prove exception behavior or transitive cleanup.

The [validation receipt](../evidence/match-action-19-validation.json) distinguishes deterministic extraction, negative specimen check and Node24 research checks from execution validation. The [findings](../evidence/match-action-19-findings.json) and [optional exact-old names](../evidence/match-action-19-annotations.json) are authored metadata. No original code bytes, table payloads, bulk decompilation, native database, shared coverage/checkpoint changes, gameplay/UI code or new numerical oracle are included. Pointer validity, aliasing, original table domain, arbitrary signed kind bounds, retry termination, deeper callees and connected match behavior remain outside the demonstrated contract.

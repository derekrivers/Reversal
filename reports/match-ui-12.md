# Eleven-slot selection and match-screen dispatch, investigation 12

`00727e20` chooses the earliest index with the greatest signed16 helper score
among eleven candidate lookups. `00727f00` passes a key and two code pointers
to a shared manager. Neither owned body directly allocates or constructs a
screen. Dependency observations show mutable tactical mapping and manager
storage, so this research does not establish a pure rendering boundary.

This is static research against specimen SHA-256
`0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`,
worker baseline `a5972e1659afa4b2937490cdc57ebd8f4a5887d3` and read-only
checkpoint 11. Addresses are virtual addresses; `+` offsets are hexadecimal
byte offsets. The owned bodies are `00727e20..00727ef2` (211 bytes, file offset
`00327e20`) and `00727f00..00727f99` (154 bytes, file offset `00327f00`).
The `match_screens.cpp` anchor at `00a161d4` is navigation evidence; the
contracts below come from instructions. Names and object identities remain
research hypotheses.

## Owned selector contract: `00727e20`

The routine takes two raw32 stack arguments and returns with plain `RET`;
its observed caller cleans eight bytes. The first argument is a club/context
pointer candidate, checked for null. The second is forwarded unchanged as an
opaque row-selection option. ECX is loaded from global pointer `00de1d08` for
each lookup; it is not a receiver supplied to this routine. EBX and ESI are
preserved, as are EBP and EDI on the nonnull path. Only **AL** is a reliable
result contract; upper EAX bits must not be interpreted as an index or pointer.

| Stage | Exact sites | Supported effect |
| --- | --- | --- |
| Null argument | `00727e31/00727e33` | Diagnostics receive source line token `0x20e1`; DWORD `00b67a34=0` at `00727e8b`, AL=`ff` at `00727e91` if those calls return. |
| Start selection | `00727ea5` | Local winner byte=`ff`; EDI starts at zero. |
| Lookup | `00727eac..00727eb5` | `008968f0(ECX=global32[00de1d08], arg1, index, arg2)` for index 0 through 10. |
| Score nonnull result | `00727eba..00727ec2` | `006e1cf0(candidate, 0, arg1)`; null lookup skips scoring. |
| Replace winner | `00727ece..00727edc` | Sentinel accepts first candidate; otherwise `CMP AX,DI` and signed `JLE` skip lower/equal scores. Winner is stored as a byte, EDI receives raw EAX. |
| Complete scan | `00727ede..00727ee4` | All eleven lookups are attempted; return local winner in AL. No nonnull candidates returns `ff`. |

The comparison is signed16, even though EDI retains the complete helper EAX.
A negative first score is accepted. Equal scores keep the earliest index.
There is no early exit when a high score is seen. The score helper's selected
entry path takes its first argument when its second argument is zero
(`006e1d20/006e1d27`) and returns AX from CX (`006e1fcf`). Its x87 calculation,
classification calls and complete semantic meaning are outside this task.

The selector's only direct nonstack store is the null diagnostic write to
`00b67a34`. It neither dereferences an input field nor explicitly allocates,
retains or frees a candidate. Input and candidate pointers therefore appear
borrowed at this boundary. Their allocation ownership, extents and valid
lifetime are unproven, and callees can have effects.

## Separate dependency observations: tactical mapping and publication

**These instructions are outside both owned bodies.** They explain why a
claim of selector purity would be unsupported.

Lookup dependency `008968f0` uses the holder's DWORD `+601` as a mapping base.
With row `r` from `008982b0` and signed8 index `i`, its mapped DWORD is at
`base + 0x91*r + 2 + 4*i` (`00896972..00896989`). The owned caller supplies
only indices 0..10, within the dependency's signed8 accepted range 0..19.
An admitted ID resolves to `global32[00ae23bc] + 0x6e*ID`; this is a borrowed
global-array row candidate, not a new allocation (`00896996..008969a6`,
`00896a14`).

The lookup can invalidate that mapping DWORD to `ffffffff`. A null row
DWORD `+61` causes the store at `008969b1`; one classification/affiliation
failure path causes the store at `008969fe`. Exact helper semantics and
complete malformed-input behavior remain open. These are dependency writes,
not direct stores in `00727e20`.

Caller `00727c30` obtains EDI and EBX from `007ff010(0)` and `007ff010(2)`
on the manager at `00b74450` (`00727c3b/00727c47/00727c49`). Its mode-3
branch (`00727d70`) conditionally reaches the selector after signed8 checks
on `00897590` results (`00727d85/00727d87`, `00727d98/00727d9a`). It calls
`00727e20(EDI,EBX)` at `00727d9e` and then cleans eight bytes.

The caller compares returned AL with `ff` using a signed branch
(`00727da6/00727dac`). For index 0..10 it calls
`00897760(ECX=global32[00de1d08], EDI, index low byte, EBX)` at `00727dbb`.
The setter performs another row lookup and writes the selected **mapped ID**
to mapping row DWORD `+52` at `008977ed`. It does not store the index into
`+52`. The setter's row lookup stability and success in a real frame remain
unmeasured. Later caller stores set DWORD `00dd6be0=1` at `00727dcb` and
write a sign-extended resolved mode to DWORD `00dd6be4` at `00727e0c`.
These caller/setter writes are separate from the selector contract; they do
not establish a complete tactical action or simulation policy.

## Owned dispatch contract: `00727f00`

This routine takes one raw32 stack argument and returns through plain `RET`.
The owned code never dereferences the argument, so a nonzero manager filter
key is the narrow contract; a pointer to a particular screen is only a
hypothesis. A nonzero key produces this call at `00727f8e`:

```text
007fe4a0(ECX = 00b74450,
         key, 00727fa0, 00727fb0, 0, 0, 0)
```

The callee consumes all six arguments through `RET 0x18` (`007fe5f4`), and
the wrapper forwards its EAX. On the null path diagnostics use source line
token `0x2113`, clear DWORD `00b67a34` at `00727f67`, and return without an
explicit EAX status assignment. There is no supported common Boolean result
across the null and nonnull paths.

The wrapper has no direct normal-path field store, allocation, free or
receiver construction. `00b74450` is a fixed-address shared receiver used by
the selector's caller as well. Its broader identity is supported by manager
fields and the `scrman.cpp` anchor in a dependency; allocation and lifetime
ownership remain unknown.

## Separate dependency observations: manager storage and callbacks

`007fe4a0` saves the receiver's current-group WORD `+382a`, sets it to zero
and scans sixteen groups (`007fe4af/007fe4b6`, `007fe5c9..007fe5d8`).
WORD `+380a+2*g` gates processing. A nonzero key filters against DWORD
`+7d6+0x300*g` (`007fe4e4/007fe560`). Matching records pass the five remaining
arguments to `007fe600` (`007fe504/007fe580`). The traversal also moves
`0x30`-byte records through `0090ba90`; their complete copy semantics are
not mapped. It restores the saved current-group word (`007fe5e4`) and
normally returns EAX=1 (`007fe5ed`), even if no group matches. That result is
not evidence of successful screen construction or callback execution.

Selected `007fe600` sites show mutable manager storage and a `0x300`-byte
allocation (`007fe86d/007fe872`). On that path effective callback argument 1
is stored at node DWORD `+0` (`007fe89c`), and effective callback argument 2
at node DWORD `+8` (`007fe8b2`). A default-argument branch can replace the
passed values first when both group roots are zero and receiver DWORD
`+37d4` is nonzero (`007fe629..007fe67c`). An existing node's DWORD `+4`
code pointer may be invoked at `007fe86b`. This is not proof that either
newly passed callback runs immediately or that the allocation succeeds;
node destruction and callback scheduling remain open.

Callback lead `00727fa0` calls `0041c0d0(0)` at `00727fa2`.
The second lead `00727fb0` reads a separate returned object's DWORD `+e2`
at `00727fcf`, can call untraced `00718aa0` at `007280a0`, can write DWORD
`00b77c4a` at `007280b8`, and has selected return codes -4/-6/-11.
Incoming call site `006b4685` is preceded by writes of ESI and zero into
objects' DWORD `+e2/+e6` returned by `00765480`
(`006b466f/006b467b`). These connect the dispatch to existing state;
they do not identify the state as an owned live match or characterize the
callbacks completely.

No direct RNG or match-advance call is identified in the two owned call
lists. The mutable lookup, caller publication, indirect manager callback and
untraced callback callee prevent a transitive RNG-free or simulation-free
claim. Source anchors do not prove that rendering advances simulation, nor
that simulation is independent of every UI path.

## Evidence, proposals and checks

- [Compact original-PE sites](../evidence/match-ui-12-sites.json): body hashes,
  exact VA/file-offset distinction, all eleven owned call sites, selected
  field/branch/ABI sites and six private export hashes. All 112 owned
  instructions independently decoded by Capstone match the supplied Ghidra
  assembly; incoming references agree at `00727d9e` and `006b4685`.
- [Contract findings](../evidence/match-ui-12-findings.json): explicit owned
  contracts, separate dependency observations, ownership hypotheses and limits.
- [Annotation proposal](../evidence/match-ui-12-annotations.json): two candidate
  names, two function notes and two EOL comments. Old names and null old
  comments were verified by the coordinator's read-only checkpoint-11
  preflight; the proposal includes its receipt digest. No native write,
  prototype or structure change is made here.
- [Extractor](../scripts/extract_match_ui_12.py): pinned SHA and PE section
  mapping, Capstone 5.0.7 instruction alignment, complete owned native
  comparison, selected static width/branch invariants, and path-redacted
  output. Run with `--binary`, `--output` and optionally `--native-dir`
  containing the six private `.asm/.c/.refs` exports.

The extractor passed on 2026-10-18 and repeated generation was identical.
`npm run check` passed using bundled Node v24.19.0. JSON parsing, Python
syntax validation and `git diff --check` passed. Staged content was reviewed
for private payloads and scope. The work contains no original code bytes,
bulk decompilation, executable, native database or private absolute path.

There is no runtime trace, behavioral oracle, TypeScript port or complete
screen lifecycle contract. Existing repository checks validate retained
primitive fixtures and checkpoint metadata; they do not validate this UI
selection/dispatch behavior against execution. Next useful work is a bounded
synthetic-frame selector oracle accounting for invalid-ID writes, followed
by manager callback/ownership tracing and measurement of reachable simulation
or RNG effects.

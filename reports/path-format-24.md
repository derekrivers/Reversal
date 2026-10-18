# Investigation 24-C — path splitting and format wrapper

The pinned 7,192,576-byte PE32 x86 executable has SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses below are **virtual addresses** unless identified as file offsets. Original PE disassembly matches every instruction address, mnemonic and operand in the read-only checkpoint-23 Ghidra exports: **167 instructions / 409 bytes** in two complete local bodies. These are **static contracts**. Neither body has an original-instruction execution oracle or validated TypeScript counterpart.

| Body | PE file offset | Size / instructions | Local role |
| --- | --- | ---: | --- |
| `00944cff` | `00544cff` | 327 / 135 | Split a byte path into optional drive, directory, basename and extension outputs |
| `00944c9f` | `00544c9f` | 82 / 32 | Prepare a variadic formatter context and terminate or finalize its output |

## `00944cff`: five stack arguments

At entry, `[EBP+8]` is the source byte-string pointer and `[EBP+0xc,+0x10,+0x14,+0x18]` are optional drive, directory, basename and extension output pointers, respectively. It saves EBX, ESI and EDI and ends with a plain `RET` at `00944e45`; the caller removes argument bytes. It has no defined result value: EAX depends on the last path, copy call or pointer manipulation. There is no allocation, destination size argument or source-pointer validity check in this local body.

The source first goes to `_strlen` at `009488e0`. If its result is nonzero and source byte 1 is `':'`, the body calls `00948851` with `(drive,source,2)` when drive output is nonnull, sets `drive[2]=0`, then advances the working source by two bytes. Otherwise it writes `drive[0]=0` when provided. The test requires **only a nonempty string**, not an alphabetic drive letter, a following separator or a particular path grammar. A one-byte string cannot pass the colon test because its second byte is the terminator.

The scan begins at the post-drive pointer. It reads each byte, zero-extends it and tests bit `0x4` in the table at `00de4521+byte` (`00944d5c`). If set, it advances an extra byte before the common increment and does not interpret either byte as a separator or dot in that iteration. Otherwise `/` (`0x2f`) and `\` (`0x5c`) update the last separator pointer to **one byte after** the separator; `.` (`0x2e`) updates the last dot pointer. The last dot does not reset at separators, but the later unsigned pointer comparison rejects it as an extension if it precedes the selected basename. The scan stops on a NUL byte after advancing. A terminal lead byte may cause the scan to step past the NUL, so malformed multibyte strings are outside this contract.

If there is a last separator, the directory output, when nonnull, receives the source bytes **through that separator**, capped at 255 bytes, followed by a zero byte at the copied-count offset. The basename start becomes the byte after the separator. Without a separator, the directory output is set to an empty string if provided, and basename starts at the post-drive pointer. The path body uses `00948851` for the bounded transfer; the exact transferred bytes are subject to that callee's multibyte behavior described below.

If the last dot is at or after basename start, the optional basename output receives bytes before that dot (up to 255), and the optional extension output receives bytes **starting with the dot** through the source terminator (up to 255). If no such dot exists, basename receives the rest of the path (up to 255) and extension is set empty. A leading basename dot is accepted, yielding an empty basename and a dot-prefixed extension. Each nonnull output gets an explicit zero byte at the chosen copy count, or at its first byte on the empty branch. The 255 limit is local to each copy; it does not establish that a caller allocated 256 bytes. The source and output buffers must be valid and appropriately sized, and aliasing is not resolved here.

The `00948851` transfer target is **not generic `memcpy`**. A bounded original PE excerpt shows a `00de441c` mode test: zero delegates to `009466d0`, whose observed path copies until NUL and pads; nonzero follows a lead-byte-aware byte loop using the same `00de4521` bit, can zero a truncated lead byte, and pads unused count with zeros. Thus an output truncated at 255 bytes can differ from a raw 255-byte prefix. We have not established a full contract or execution oracle for either transitive callee. The local path body itself also invokes `_strlen`; `_strlen`, both copy paths, locale initialization and source bytes remain outside this unit's execution validation.

## `00944c9f`: variadic formatter boundary

This body takes a destination pointer at `[EBP+8]`, a format pointer at `[EBP+0xc]` and an address of caller-provided variadic arguments beginning at `[EBP+0x10]`. It builds a four-dword local context: current pointer and starting pointer both initialized from the destination, a remaining counter initialized to `0x7fffffff`, and a `0x42` field. It calls `00947c67(&context,format,&first_vararg)` at `00944cc8` with three caller-cleaned arguments. The exact format language, argument types, writes and meaning of `0x42` belong to that large transitive callee.

The wrapper saves `00947c67`'s EAX result in ESI, decrements the local remaining counter, and branches on the resulting **sign flag**. If not signed-negative, it writes one zero byte at the context's current pointer. If signed-negative, it calls `00947b52(0,&context)` instead. It restores the original formatter EAX into EAX and returns with a plain `RET` at `00944cf0`; the caller owns the wrapper's arguments. The finalizer's effects are not mapped here. No direct destination write is guaranteed on its branch, and the numeric meaning of the returned formatter value is unresolved. The very large initial count is **not proof of destination capacity**.

## Evidence and limits

[Compact sites](../evidence/path-format-24-sites.json) record both body digests, all 30 branch targets, all eight call sites, nine local output-zero sites, the scan table and copy cap. [The extractor](../scripts/extract_path_format_24.py) gates the original specimen, checkpoint-23 archive digest, export manifest/preflight digests, exact-old names and lengths, every exported file hash, full PE/native operands, calls, branches and key width/constant sites. The private exports and executable are not committed. [Negative evidence](../evidence/path-format-24-negative.json) confirms rejection of a changed PE byte, a wrong copy-cap expectation and self-consistently rehashed native export mutations at the scan table and formatter call. Normal and optimized Python (`-O`) yield byte-identical sites and negative receipts; neither path relies on `assert` for integrity.

The [annotation proposal](../evidence/path-format-24-annotations-proposal.json) is exact-old name-only, pending independent review and coordinator application. The connected diagnostic callers are context: these bodies do not prove diagnostic termination, UI behavior, a general path library, formatter equivalence or a full game path. A TypeScript path implementation would need an entry-to-return original-instruction oracle with faithful `00948851` and `_strlen` behavior, including locale flags and output memory; a formatter implementation would additionally need its deeper callee contract. Neither is claimed here.

```powershell
python scripts/extract_path_format_24.py <private-cm0102.exe> --exports <private-exports-24> --preflight <private-annotation-preflight-24.json> --output evidence/path-format-24-sites.json
python scripts/check_path_format_24_negative.py <private-cm0102.exe> --exports <private-exports-24> --preflight <private-annotation-preflight-24.json> --output evidence/path-format-24-negative.json
python -O scripts/extract_path_format_24.py <private-cm0102.exe> --exports <private-exports-24> --preflight <private-annotation-preflight-24.json> --output <private-temporary-output>
npm run check
```

# Investigation 07 — keeper response adjustment and floating-point precision

Target SHA-256: `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. Addresses below are virtual addresses. Working names and fields remain partial research annotations.

The penalty branch and common keeper postlude now have a connected numerical reconstruction. **The whole keeper function, complete penalty outcome and match remain unreconstructed.** Validity/position checks and acquisition of the prelude's grid-derived factor are still supplied as entry conditions.

## Verified boundary

The oracle has two entry modes:

- Postlude only: `00700a4f` through `00700b87`, stopping before the first register-pop instruction at `00700b88`.
- Penalty body: `007004d6..007004ec` followed by that same postlude, using the original branch between them.

Each entry mode has 2,048 inputs, repeated identically at 53-bit and 64-bit x87 precision: **8,192 cases**. All three paths occur in each mode/precision combination. TypeScript matches response, fallback flag, branch, ordered postlude RNG bounds and final exposed RNG state. The original RNG and `__ftol` instructions execute unchanged. No game process launches.

## State and ordered calculation

| Input | Original storage | Width / boundary |
| --- | --- | --- |
| Selected rating | Slot `+168/+16a`, retained in frame `+2c` | signed16; variant chosen by prelude |
| Base response | EDI at postlude entry | Low word later interpreted signed16 |
| Adjustment factor | Slot `+d1` | float32; tested within[-100,100] |
| Counter | Slot `+f` | unsigned8; semantic name unresolved |
| Grid-derived factor | Frame `+24` | float32; supplied, tested within[-20,20] |
| State factor | Match `+8eaa` | signed8; enum/source unresolved |
| Fallback rating | Slot `+3b` | signed16; source formula unresolved |

The penalty body first computes the previously checked two base draws. The postlude then makes two draws with bounds:

```text
firstBound  = trunc(2 * adjustmentFactor + counter + 10)
secondBound = trunc((2 - gridFactor) * signedStateFactor * 10)
```

If the first draw is greater than the second, it retains the signed16 base. Otherwise it sets the fallback output flag and compares `random(fallbackRating)` against `random(285)`:

- Greater: draw with `trunc(signedBase * binary64(0.7))`, then truncate `draw + signedBase * binary64(0.3)`.
- Otherwise: draw with signedBase itself.

The chosen value is cast to signed16 before the final expression:

```text
response = trunc(trunc(selectedRating / 6)
                 + signed16(chosenValue) * binary64(4/7)
                 + 20)
```

Every arithmetic ADD/MUL rounds at the selected x87 precision before later instructions. The constants are the exact values represented by the specimen's binary64 encodings. They are not exact rational 7/10, 3/10 or 4/7. Zero bounds preserve RNG state; negative bounds use the recovered signed helper behavior. Public guards reject unsupported raw values, non-finite/non-float32 factors and out-of-range factors before drawing.

## Precision is an explicit input

The first 64-bit-precision experiment exposed numerical mismatches with an ordinary JavaScript expression: rating 0/base 7 can return 23 in the original instructions versus 24 with JavaScript Number arithmetic. The finite arithmetic helper uses dyadic BigInt values and rounds each operation to the selected significand width with nearest/even; it is not a general x87 emulator. It does not model exception flags, exponent extremes, non-finite values, other rounding modes or division.

A static control-word inventory found 20 control-word instruction sites in the current inferred listing. In particular:

- `0094a698` calls `0094f5b0` with value`10000h`, mask`30000h`.
- `0094f5b0` forwards to `0094f57b`, which translates control flags via `0094f5c6/0094f658` and loads the resulting x87 control word.
- The requested precision maps to control bits`0200h`, meaning 53-bit precision.

This identifies a CRT precision request. It does **not** establish the complete startup path or prove the control word at every match entry. `KeeperInput.precisionBits` therefore requires 53 or 64 explicitly. Fixtures use `027fh/037fh`, respectively, and original `__ftol` temporarily selects truncation before restoring the word.

Among the 4,096 paired inputs, precision changes 661 responses and 90 postlude RNG-bound sequences. It changes no final RNG cursor/offset/CRT state in this particular fixture set; that observation is not a general guarantee about later simulation state.

## Preservation and continuation

The existing native database now includes the four measured postlude fields and the CRT precision-request working name. Its original contents and prior checkpoint metadata are preserved. A fresh archive extraction is reopened read-only to check annotations, code samples and canonical file hashes.

The checkpoint builder now uses the latest annotation receipt for a comment address when a later investigation supersedes it. This matches the native listing's single comment at that address; historical receipts/checkpoints remain unchanged.

Next, establish the keeper prelude's validity/position and grid inputs, and capture match-entry floating-point state. Then follow the keeper response back into `00702050`, including quality modifications, category selection, eligible-category gate and score/state writes. Commentary remains a shared-RNG consumer that must be accounted for before claiming a complete attempt.

# Investigation 06 — penalty keeper and shot-resolution boundaries

The pinned 3.9.68 specimen has SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86`. All addresses below are virtual addresses. These working labels and partial types are research annotations, not original source declarations.

Three independently tested instruction slices now explain more of the penalty path. They do **not** constitute a connected penalty attempt, a goal/save formula or a probability model.

| Boundary | Original instructions | Checked cases |
| --- | --- | ---: |
| Penalty shot category | `00703b25..00703be7` | 131,072 |
| Keeper base-response draws | `007004d6..007004ec` | 4,096 |
| Scoring-branch ratio gate | `00706cba..00706d26`, plus zero-denominator block | 4,056 |

## Keeper selection and base draws

Static callers identify `006ce110` as a goalkeeper-slot selector candidate. It manages cached pointers at match `+f59e/+f5a2`, searches 20 slots per side for tactical position value 1 and contains fallback/reassignment behavior. That entire selection routine remains untested.

`00700420` selects a signed16 rating from slot `+168` when its variant byte is zero, or `+16a` otherwise. After valid-keeper checks, action `0x33` computes:

```text
bound = sign16(rating + 220)
first = random(bound)
base = random(bound - first)
```

The base-only oracle starts at `007004d6` with the prelude's established register value and stops **before** `00700a4f`. It uses the original small-bound RNG and retained synthetic table. It covers signed wrap, negative bounds, zero bounds and cursor wrap; it does not establish the ratings' source attributes or their realistic game range.

The common postlude `00700a4f..00700b87` adds more RNG and x87 arithmetic. Static inputs include slot float `+d1`, unsigned byte `+f`, match signed byte `+8eaa`, fallback signed16 rating `+3b` and the selected rating. Constants include 10, 2, represented-double 0.7/0.3, represented-double 4/7 and 20. This stage is the next reconstruction target. Do not feed the base draw directly to the scoring gate as though it were the final keeper term.

## Shot category

Action `0x33` sets threshold 120. The verified classification receives a quality value **after earlier adjustments**, compares its signed low word and uses a byte selected upstream. We retain raw category numbers because their complete downstream effects remain unmapped.

| Signed quality / threshold difference | Variant byte zero | Variant byte nonzero |
| --- | --- | --- |
| Quality > 120 | Draw `random(quality)`; category14 if result<10, otherwise1 | Category15 if result<10, otherwise1 |
| Quality < 10 | 2 | 4 if `random(4)==0`, otherwise3 |
| Difference > 60 | 5 | 7 if `random(4)==0`, otherwise6 |
| Difference 26–60 | 8 | 9 |
| Difference 15–25 | 10 | 11 |
| Difference 0–14 | 12 | 13 |

Only categories 1, 14 and 15 enter the ratio gate. Other categories have further miss/woodwork/presentation branches; this table does not assign all their final outcomes.

The oracle sweeps all 65,536 raw words with variant0 and variant1 using the same synthetic initial RNG state at table wrap. Outputs store two bytes per case: category and consumed-draw count. Their final exposed RNG states are checked too. Exhaustive quality coverage is not exhaustive RNG-state or full-game coverage.

The earlier helper `00713e90` takes an action33 early exit returning byte2 and an output adjustment word0. This static link explains one skipped adjustment; it does not eliminate other quality modifications or validate the full helper.

## Scoring-branch gate

For eligible categories, the gate takes signed16 quality and keeper terms supplied after upstream modifications:

```text
sum = keeperTerm + quality
ratio = sum == 0 ? 0 : float32(quality * 100 / sum)
if sum != 0 and ratio <= 68 and matchState in {2, 8}:
    ratio = float32(ratio + 2)
entersScoringBranch = ratio > 71
```

Exactly 71 fails the gate. The state-specific addition cannot itself change this Boolean because it raises a ratio of at most68 to at most70. State2/8 meanings have not been assigned here. The stored float32 rounding matters; the comparison's constant71 is not a percentage chance. Negative and singular synthetic inputs test machine behavior without claiming those states occur in play.

The original instructions are stopped at the branch destination, before scoring, keeper statistics, subsequent presentation or score writes. A failed gate does not by itself identify a goalkeeper save.

## Validation and preserved database

`emulate_penalty_resolution.py` admits only the documented slices, their stop sentinels, the original small-bound RNG and CRT helper. It patches no instructions and supplies independent synthetic stack frames. `check-penalty-resolution.ts` compares all categories, keeper base values, exposed RNG state, float32 ratios and branch results. `npm run check` includes this comparison and the earlier retained numerical checks.

The current database retains 25 working function names, 12 labels, 8 partial structures and 84 fields. It includes two newly measured signed16 keeper rating fields. A fresh archive extraction is reopened read-only without reanalysis; the expected annotations, original code samples and canonical project files are checked. Checkpoint06 supersedes05; earlier checkpoints remain historical.

## Next connected path

Reconstruct the shared keeper postlude and its exact signed casts, x87 rounding and ordered random draws. Then establish all modifications between preparation, classification and the gate, follow the scoring/non-scoring branches to state writes and build a connected attempt oracle. Commentary consumes shared RNG and must be included when enabled. A complete shootout follows only after complete attempts are understood.

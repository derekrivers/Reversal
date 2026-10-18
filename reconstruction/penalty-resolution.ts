/** Independently verified instruction slices, not a complete penalty resolver.
 * Addresses refer to the hash-pinned 3.9.68 specimen. Keep category codes raw
 * until their downstream effects have been mapped.
 */
import { nextBounded, type RandomState } from './bounded-random.ts';

function word(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 65535) throw new RangeError('Expected raw uint16');
  return (value << 16) >> 16;
}
function byte(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 255) throw new RangeError('Expected raw uint8');
}

/** 007004d6..007004ec: two keeper draws before the shared postlude.
 * Entry preconditions (valid keeper/position) are the caller's responsibility.
 */
export function penaltyKeeperBase(ratingRaw: number, state: RandomState, table: readonly number[]): number {
  const bound = ((word(ratingRaw) + 220) << 16) >> 16;
  const first = nextBounded(bound, state, table);
  return nextBounded(bound - first, state, table);
}

/** 00703b25..00703be7: penalty threshold120, using already-adjusted quality.
 * variantRaw is the byte previously selected upstream, not a React choice.
 */
export function classifyPenaltyShot(qualityRaw: number, variantRaw: number, state: RandomState, table: readonly number[]): number {
  const quality = word(qualityRaw); byte(variantRaw);
  const variant = variantRaw === 0 ? 0 : 1;
  if (quality > 120) return nextBounded(quality, state, table) < 10 ? 14 + variant : 1;
  if (quality < 10) return variant ? 4 - Number(nextBounded(4, state, table) !== 0) : 2;
  const difference = 120 - quality;
  if (difference > 60) return variant ? 7 - Number(nextBounded(4, state, table) !== 0) : 5;
  if (difference > 25) return 8 + variant;
  if (difference > 14) return 10 + variant;
  return 12 + variant;
}

/** 00706cba..00706d26: gate reached only for category1,14,15.
 * quality/keeperTerm are signed16 values after upstream modifications.
 * Enters the scoring branch; does not perform scoring or classify saves.
 */
export function penaltyScoringGate(qualityRaw: number, keeperTermRaw: number, matchStateRaw: number): { ratio: number; entersScoringBranch: boolean } {
  const quality = word(qualityRaw), keeper = word(keeperTermRaw); byte(matchStateRaw);
  const denominator = keeper + quality;
  let ratio = denominator === 0 ? 0 : Math.fround(quality * 100 / denominator);
  if (denominator !== 0 && ratio <= 68 && (matchStateRaw === 2 || matchStateRaw === 8)) ratio = Math.fround(ratio + 2);
  return { ratio, entersScoringBranch: ratio > 71 };
}

/** 00700420 action33 body plus common postlude, with supplied prelude state.
 * Validity/position lookup, other action branches and the shot caller excluded.
 */
import { nextBounded,type RandomState } from './bounded-random.ts';
import { penaltyKeeperBase } from './penalty-resolution.ts';
import { extended as x,arithmetic,truncate } from './x87-finite.ts';
export type KeeperInput = {
  ratingRaw: number; fallbackRatingRaw: number; counterRaw: number;
  adjustmentFloat: number; distanceFloat: number; matchByteRaw: number;
  precisionBits: 53|64;
};
export type KeeperResult = { response: number; fallback: boolean; path: string; drawBounds: number[] };
function raw(value: number,max: number): void {
  if (!Number.isInteger(value) || value < 0 || value > max) throw new RangeError('Invalid raw integer');
}
function signed16(raw: number): number { return (raw << 16) >> 16; }
function validate(input: KeeperInput): void {
  if (input.precisionBits!==53 && input.precisionBits!==64) throw new RangeError('Expected explicit53 or64 bit precision');
  raw(input.ratingRaw,65535);raw(input.fallbackRatingRaw,65535);raw(input.counterRaw,255);raw(input.matchByteRaw,255);
  for (const [value,max] of [[input.adjustmentFloat,100],[input.distanceFloat,20]]) {
    if (!Number.isFinite(value) || Math.abs(value) > max || Math.fround(value) !== value) throw new RangeError('Expected bounded float32 input');
  }
}
export function adjustKeeperResponse(input: KeeperInput,baseRaw: number,state: RandomState,table: readonly number[]): KeeperResult {
  validate(input);raw(baseRaw,65535);
  return postlude(input,baseRaw,state,table);
}
function postlude(input: KeeperInput,baseRaw: number,state: RandomState,table: readonly number[]): KeeperResult {
  const {add,multiply}=arithmetic(input.precisionBits);
  const drawBounds: number[] = [];
  const draw = (bound: number) => { drawBounds.push(bound);return nextBounded(bound,state,table); };
  const base = signed16(baseRaw), ratingPart = Math.trunc(signed16(input.ratingRaw)/6);
  const firstBound = truncate(add(add(multiply(x(input.adjustmentFloat),x(2)),x(input.counterRaw)),x(10)));
  const matchByte = (input.matchByteRaw << 24) >> 24;
  const secondBound = truncate(multiply(multiply(add(x(2),x(-input.distanceFloat)),x(matchByte)),x(10)));
  const first = draw(firstBound), second = draw(secondBound);
  let value = base, fallback = false, path = 'retained';
  if (first <= second) {
    fallback = true;
    const candidate = draw(signed16(input.fallbackRatingRaw));
    const threshold = draw(285);
    if (candidate > threshold) {
      path = 'weighted';
      // The native constants are represented binary64 values, not exact 7/10 and3/10.
      const bound = truncate(multiply(x(base),x(0.7)));
      const weightedDraw = draw(bound);
      value = truncate(add(x(weightedDraw),multiply(x(base),x(0.3))));
    } else {
      path = 'redrawn';value = draw(base);
    }
  }
  const response = truncate(add(add(x(ratingPart),multiply(x(signed16(value)),x(0.5714285714285714))),x(20)));
  return { response,fallback,path,drawBounds };
}
/** Connected penalty base branch + postlude. Prelude values must be supplied.
 * Domain guards run before any draw so unsupported states leave RNG unchanged.
 */
export function penaltyKeeperResponse(input: KeeperInput,state: RandomState,table: readonly number[]): KeeperResult {
  validate(input);
  const base = penaltyKeeperBase(input.ratingRaw,state,table);
  return postlude(input,base&65535,state,table);
}

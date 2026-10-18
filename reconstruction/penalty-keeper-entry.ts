/** Original00700420 entry-to-return, restricted to action33 and bounded grid.
 * Caller supplies runtime-derived fields and lookup data; no game state loader.
 */
import { penaltyKeeperResponse } from './keeper-response.ts';
import type { RandomState } from './bounded-random.ts';
export type PenaltyKeeperEntry = {
  rating0Raw: number; rating1Raw: number; variantRaw: number;
  activityRaw: number; tacticalSlotRaw: number; side: number;
  keeperX: number; keeperY: number; matchX: number; matchY: number;
  fallbackRatingRaw: number; counterRaw: number; adjustmentFloat: number;
  matchByteRaw: number; precisionBits: 53|64;
};
function integer(value: number,max: number): void {
  if (!Number.isInteger(value)||value<0||value>max) throw new RangeError('Unsupported raw/grid value');
}
/**006c38c0 low-word contract. Upper EAX bits are not a semantic return value. */
export function tacticalPositionWord(slotRaw: number,side: number,positions: readonly (readonly number[])[]): number {
  integer(slotRaw,255);integer(side,1);
  if (positions.length!==2||positions.some(t=>t.length!==11||t.some(v=>!Number.isInteger(v)||v<0||v>65535))) throw new RangeError('Expected two11-word tactical tables');
  return slotRaw<=10 ? positions[side][slotRaw] : 0;
}
export function resolvePenaltyKeeper(input: PenaltyKeeperEntry,positions: readonly (readonly number[])[],grid: readonly number[],state: RandomState,randomTable: readonly number[]) {
  for(const value of [input.rating0Raw,input.rating1Raw,input.fallbackRatingRaw]) integer(value,65535);
  for(const value of [input.variantRaw,input.activityRaw,input.tacticalSlotRaw,input.counterRaw,input.matchByteRaw]) integer(value,255);
  integer(input.side,1);
  for(const value of [input.keeperX,input.matchX])integer(value,8);
  for(const value of [input.keeperY,input.matchY])integer(value,11);
  if(input.precisionBits!==53&&input.precisionBits!==64)throw new RangeError('Explicit53/64-bit precision required');
  if(!Number.isFinite(input.adjustmentFloat)||Math.abs(input.adjustmentFloat)>100||Math.fround(input.adjustmentFloat)!==input.adjustmentFloat)throw new RangeError('Expected float32 adjustment in[-100,100]');
  if(grid.length!==108||grid.some(v=>!Number.isFinite(v)||v<0||v>20||Math.fround(v)!==v))throw new RangeError('Expected bounded108-entry float32 grid');
  const position=tacticalPositionWord(input.tacticalSlotRaw,input.side,positions);
  const index=Math.abs(input.keeperY-input.matchY)*9+Math.abs(input.keeperX-input.matchX);
  const signedActivity=(input.activityRaw<<24)>>24;
  if(signedActivity>1||position!==1)return {response:0,positionFlag:0,fallbackFlag:0,eligible:false,gridIndex:index};
  const result=penaltyKeeperResponse({ratingRaw:input.variantRaw===0?input.rating0Raw:input.rating1Raw,
    fallbackRatingRaw:input.fallbackRatingRaw,counterRaw:input.counterRaw,adjustmentFloat:input.adjustmentFloat,
    distanceFloat:grid[index],matchByteRaw:input.matchByteRaw,precisionBits:input.precisionBits},state,randomTable);
  return {response:result.response,positionFlag:0,fallbackFlag:Number(result.fallback),eligible:true,gridIndex:index};
}

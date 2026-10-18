import { nextBounded,type RandomState } from './bounded-random.ts';

/** Calculation slices from 006be710 and action-kind 0x33 in 00700bd0.
 * Commentary is suppressed in the original oracle (sudden-death flag set).
 * This prepares the shared shot routine's quality argument, not a goal outcome.
 */
export type PenaltyPreparationInput = {
  oneOnOnesRaw: number;
  shotRatingRaw: number;
  remaining: number;
  opponentRemaining: number;
  score: number;
  opponentScore: number;
};
export function preparePenaltyAttempt(input:PenaltyPreparationInput,state:RandomState,table:readonly number[]) {
  for(const key of ['oneOnOnesRaw','score','opponentScore'] as const)
    if(!Number.isInteger(input[key])||input[key]<0||input[key]>255)throw new RangeError(`${key}: uint8 required`);
  for(const key of ['remaining','opponentRemaining'] as const)
    if(!Number.isInteger(input[key])||input[key]<0||input[key]>5)throw new RangeError(`${key}: 0..5 required`);
  if(!Number.isInteger(input.shotRatingRaw)||input.shotRatingRaw<0||input.shotRatingRaw>65535)throw new RangeError('shotRatingRaw: uint16 required');
  const rating=(input.shotRatingRaw<<16)>>16;
  if(Math.abs(rating*5)>65535)throw new RangeError('Shot rating needs unrecovered large-bound RNG branch');
  const oneOnOnes=(input.oneOnOnesRaw<<24)>>24;
  const firstDraw=nextBounded(oneOnOnes,state,table);
  const baseErrorBudget=(200-firstDraw*(input.remaining+4))*2;
  const pressure=input.remaining-1+input.score<input.opponentScore?'must-score':
    input.opponentRemaining+input.opponentScore<input.score+1?'score-to-win':'none';
  const pressureBound=pressure==='none'?0:Math.trunc(baseErrorBudget*(pressure==='must-score'?2.25:0.75));
  const pressureDraw=pressure==='none'?0:nextBounded(pressureBound,state,table);
  const errorBudget=baseErrorBudget+pressureDraw;
  const baseQuality=(150+nextBounded(rating*5,state,table))<<16>>16;
  const finalDraw=nextBounded(errorBudget,state,table);
  return {pressure,baseErrorBudget,pressureBound,errorBudget,baseQuality,quality:baseQuality-finalDraw,eventCode:0x1f7f};
}

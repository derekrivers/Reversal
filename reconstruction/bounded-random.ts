/** Narrow reconstruction of the observed 3.9.68 RNG path.
 * Inputs outside [-65535,65535] use a different original algorithm and are rejected.
 * State is explicit; this does not model full-game seeding or save/load behavior.
 */
export type RandomState = { cursorIndex: number; offset: number; crtState: number };

export function crtStep(state: RandomState): number {
  state.crtState = (Math.imul(state.crtState, 0x343fd) + 0x269ec3) >>> 0;
  return (state.crtState >>> 16) & 0x7fff;
}

export function nextBounded(bound: number, state: RandomState, table: readonly number[]): number {
  if (!Number.isInteger(bound) || bound < -65535 || bound > 65535) {
    throw new RangeError('Only the recovered small-argument branch is supported');
  }
  if (table.length !== 51000) throw new RangeError('Expected a 51000-word table');
  if (bound === 0) return 0;
  state.cursorIndex += 1;
  if (state.cursorIndex >= table.length) {
    state.cursorIndex = 0;
    state.offset = crtStep(state) & 0xffff;
  }
  // x86 ADD wraps at 32 bits, and IDIV uses a signed dividend.
  const dividend = (state.offset + table[state.cursorIndex]) | 0;
  const remainder = dividend % bound;
  return (bound < 0 ? -remainder : remainder) | 0;
}

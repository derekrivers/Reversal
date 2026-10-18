// Narrow reconstructions of 3.9.68 routines 006d5cd0 and 006d4250.
// The predicate's literal contract includes sentinel/unsupported targets.
// It must only be interpreted as golden-goal behavior in its observed callers.
export function eventIndex(code: number): number | null {
  const index = (code & 0x7fff) - 8000;
  return index >= 0 && index < 677 ? index : null;
}
export function eventPriority(code: number, priorities: Uint8Array): number {
  if (priorities.length !== 677) throw new RangeError('677 priorities required');
  const index = eventIndex(code);
  return index === null ? 0 : (priorities[index] << 24) >> 24;
}
export function stopAfterGoalRule(periodTarget: number, fixtureFlags: number): boolean {
  const target = periodTarget & 0xffff;
  return target !== 495 && target !== 990 && (fixtureFlags & 0x80) !== 0;
}

/** Timestamp conversion observed at 0x006d70c4..0x006d70ef.
 * This returns the stored byte, including signed16 input and uint8 wrap semantics.
 * It does not advance the match or add stoppage time.
 */
export function eventMinute(modeByte: number, rawClock: number): number {
  const raw = rawClock & 0xffff;
  if ((modeByte & 0xff) !== 0) return raw & 0xff;
  const signed = (raw << 16) >> 16;
  return Math.trunc(signed / 11) & 0xff;
}

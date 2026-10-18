/** The preinitialized, nonrecursive path through 0054cc30.
 * Input words and mapped disjoint memory must remain stable. This does not
 * implement the registration callback or recursive operand swap.
 */
export interface DateDifferenceMemory {
  read8(address: number): number;
  read16(address: number): number;
  read32(address: number): number;
  write16(address: number, value: number): void;
  write32(address: number, value: number): void;
}

function word(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff)
    throw new RangeError('WORD required');
}

function dword(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
    throw new RangeError('DWORD required');
}

function signedWord(value: number): number {
  return (value << 16) >> 16;
}

export function dateDifferenceDirect(
  receiver: number, output: number, argumentDay: number, argumentYear: number,
  previousFsHead: number, memory: DateDifferenceMemory,
): {eax:number; ecx:number; edx:number; espDelta:number} {
  dword(receiver);
  dword(output);
  dword(previousFsHead);
  word(argumentDay);
  word(argumentYear);
  if (receiver !== 0x200000 || output !== 0x210000)
    throw new RangeError('only disjoint mapped synthetic addresses supported');
  if ((memory.read8(0x00ae249d) & 1) === 0)
    throw new RangeError('registration callback path');
  const receiverYear = memory.read16(receiver + 2);
  word(receiverYear);
  // Original equal-year ordering reads the receiver day for the signed
  // ordering guard, then reads it again to calculate the difference.
  if (argumentYear > receiverYear) throw new RangeError('recursive path');
  if (argumentYear === receiverYear &&
      signedWord(argumentDay) > signedWord(memory.read16(receiver)))
    throw new RangeError('recursive path');
  const receiverDay = memory.read16(receiver);
  word(receiverDay);
  let days = signedWord(receiverDay) - signedWord(argumentDay);
  const borrowed = days < 0;
  if (borrowed) {
    const leap = receiverYear % 4 === 0 &&
      (receiverYear % 100 !== 0 || receiverYear % 400 === 0);
    days += leap ? 366 : 365;
  }
  memory.write16(0x00ae2428, days & 0xffff);
  // The native body writes the ordinal before rereading receiver+2. Keep
  // that order because mapped memory may be observed between those events.
  const yearAgain = memory.read16(receiver + 2);
  word(yearAgain);
  let years = (yearAgain - argumentYear) & 0xffff;
  if (borrowed)
    years = (years - 1) & 0xffff;
  memory.write16(0x00ae242a, years);
  const packed = memory.read32(0x00ae2428) >>> 0;
  memory.write32(output, packed);
  const high = memory.read32(0x00ae242c) >>> 0;
  memory.write32(output + 4, high);
  return {eax: output, ecx: previousFsHead, edx: packed, espDelta: 16};
}

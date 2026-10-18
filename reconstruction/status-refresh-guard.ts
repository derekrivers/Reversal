/** Call-free entry-to-RET4 exits of 0062c680 with preinitialized helper flags.
 * The refresh/update paths, helper initialization and callee effects are outside this domain.
 */
export interface RefreshGuardMemory {
  read8(address: number): number;
  read16(address: number): number;
  read32(address: number): number;
  write32(address: number, value: number): void;
}

function dword(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
    throw new RangeError('unsigned DWORD required');
}

export function statusRefreshCallFreeExit(
  receiver: number, player: number, initialEdx: number, initialEsp: number,
  memory: RefreshGuardMemory,
): {eax:number; ecx:number; edx:number; path:string} {
  dword(receiver);
  dword(player);
  dword(initialEdx);
  dword(initialEsp);
  const oldSeh = memory.read32(0) >>> 0;
  if (oldSeh !== 0) throw new RangeError('SEH head outside validated domain');
  memory.write32(0, (initialEsp-12) >>> 0);
  function finish(eax:number, edx:number, path:string) {
    memory.write32(0, oldSeh);
    return {eax, ecx:0, edx, path};
  }
  // Three separate reads are instruction effects even when all bits are already set.
  for (const bit of [1, 2, 4]) {
    if ((memory.read8(0x00b63d10) & bit) === 0)
      throw new RangeError('helper initialization enters a callee');
  }
  if (player === 0) return finish(4, initialEdx, 'null');
  const index = memory.read32(player) >>> 0;
  const count = memory.read32(0x00ae2364) >>> 0;
  if ((index | 0) >= (count | 0))
    return finish(index, count, 'count');
  const slot = memory.read32((player+0x61) >>> 0) >>> 0;
  if (slot === 0) return finish(index, count, 'slot-null');
  if (receiver === 0 || (index | 0) < 0)
    throw new RangeError('row address outside mapped domain');
  const table = memory.read32(receiver) >>> 0;
  const row = (table+Math.imul(index,31)) >>> 0;
  const first = memory.read32(row) >>> 0;
  memory.read32((row+4) >>> 0);
  const high = memory.read16(0x00ae2c92) & 0xffff;
  if ((first >>> 16) !== high) throw new RangeError('stamp mismatch enters update');
  const low = memory.read16(0x00ae2c90) & 0xffff;
  if ((first & 0xffff) !== low) throw new RangeError('stamp mismatch enters update');
  return finish(first, ((table & 0xffff0000) | high) >>> 0, 'cached');
}

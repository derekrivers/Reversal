/** Complete local 0062c3d0 contract on mapped, stable synthetic memory.
 * The caller supplies the runtime global and receiver storage. Invalid pointers,
 * aliases, concurrent mutation and any connected match behavior are outside scope.
 */
export interface ScalarMemory {
  read16(address: number): number;
  read32(address: number): number;
}

function dword(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('unsigned DWORD required');
}

export function queryMatchScalar(receiver: number, index: number, memory: ScalarMemory): {eax: number; edx: number} {
  dword(receiver); dword(index);
  const count = memory.read32(0x00ae2364) >>> 0;
  if ((index | 0) >= (count | 0)) return {eax: 0, edx: count};
  const displacement = Math.imul(index, 31) >>> 0;
  const table = memory.read32(receiver) >>> 0;
  const field = memory.read16((table + displacement + 12) >>> 0) & 0xffff;
  return {eax: (field << 16 >> 16) >>> 0, edx: displacement};
}

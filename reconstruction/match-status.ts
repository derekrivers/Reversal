/** The no-callee count-guard path through complete body 0062c400.
 * Caller supplies stable, disjoint mapped synthetic memory. Other paths call
 * diagnostic, row-refresh or conversion helpers and have no implementation here.
 */
export interface StatusMemory {
  read32(address: number): number;
}

function dword(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
    throw new RangeError('unsigned DWORD required');
}

export function matchStatusCountGuard(pointer: number, memory: StatusMemory): {eax:number; ecx:number} {
  dword(pointer);
  if (pointer === 0) throw new RangeError('null pointer enters diagnostic path');
  const index = memory.read32(pointer) >>> 0;
  const count = memory.read32(0x00ae2364) >>> 0;
  if ((index | 0) < (count | 0)) throw new RangeError('indexed path reaches callees');
  // MOV EAX,count then XOR AL,AL; the high 24 result bits are not forced to zero.
  return {eax: (count & 0xffffff00) >>> 0, ecx: index};
}

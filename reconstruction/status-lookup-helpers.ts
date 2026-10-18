/** Bounded original-entry contracts for 0062ec00, 0062ece0 and the
 * no-callee signed count guard in 0062ed70. Pointers denote disjoint stable
 * synthetic mapped memory. All values are unsigned x86 register DWORDs.
 */
export interface LookupMemory {
  read8(address: number): number;
  read32(address: number): number;
}

function dword(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff)
    throw new RangeError('unsigned DWORD required');
}

function byte(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xff)
    throw new RangeError('unsigned byte required');
}

export function statusByteTable(inputDword: number, memory: LookupMemory): {eax:number; ecx:number} {
  dword(inputDword);
  const signedByte = (inputDword << 24) >> 24;
  const ecx = Math.imul(signedByte,3) >>> 0;
  const at = (0x009e7ad9 + Math.imul(signedByte,13)) >>> 0;
  const value = memory.read8(at);
  byte(value);
  return {eax: ((signedByte & 0xffffff00) | value) >>> 0, ecx};
}

export interface StatusLookupRegisters {eax:number; ecx:number; edx:number}

export function statusByteCondition(pointer: number, object: number, initialEax: number,
                                    memory: LookupMemory): StatusLookupRegisters {
  dword(pointer); dword(object); dword(initialEax);
  let eax = initialEax >>> 0;
  let edx = pointer >>> 0;
  const ecx = object >>> 0;
  if (pointer === 0) return {eax: (eax & 0xffffff00) >>> 0, ecx, edx};
  eax = memory.read32(pointer) >>> 0;
  const count = memory.read32(0x00ae2364) >>> 0;
  if ((eax | 0) >= (count | 0)) return {eax: (eax & 0xffffff00) >>> 0, ecx, edx};
  const active = memory.read32((pointer + 0x61) >>> 0) >>> 0;
  if (active === 0) return {eax: (eax & 0xffffff00) >>> 0, ecx, edx};
  edx = Math.imul(eax,31) >>> 0;
  eax = (memory.read32(object) + edx) >>> 0;
  const sentinel = memory.read8((eax+0x12) >>> 0);
  byte(sentinel);
  if (sentinel >= 0x80) return {eax: (eax & 0xffffff00) >>> 0, ecx, edx};
  const value = memory.read8((eax+0x13) >>> 0);
  byte(value);
  const signedValue = (value << 24) >> 24;
  return {eax: (signedValue > 1 ? signedValue : 1) >>> 0, ecx, edx};
}

export function refreshedStatusRecordCountGuard(pointer: number, memory: LookupMemory): {eax:number; ecx:number} {
  dword(pointer);
  if (pointer === 0) throw new RangeError('null pointer enters diagnostics');
  const index = memory.read32(pointer) >>> 0;
  const count = memory.read32(0x00ae2364) >>> 0;
  if ((index | 0) < (count | 0)) throw new RangeError('refresh callee path outside contract');
  return {eax:0, ecx:index};
}

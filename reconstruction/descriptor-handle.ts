/** Local 0094fded contract; pinned PE SHA-256:
 * 0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86.
 * Addresses and results are unsigned DWORDs; storage is little endian.
 * Supported memory is synchronous, readable/writable, stable for this call and
 * nonaliasing between descriptor pages, table, bound and error globals. The
 * callbacks must throw for unavailable storage. No table lifetime/OS semantics.
 */
export interface DescriptorMemory {
  read8(address: number): number;
  read32(address: number): number;
  write32(address: number, value: number): void;
}

export function descriptorToHandle(descriptor: number, memory: DescriptorMemory): number {
  if (!Number.isInteger(descriptor) || descriptor < 0 || descriptor > 0xffffffff)
    throw new RangeError('descriptor must be an unsigned DWORD');
  const fail = (): number => {
    // The original AND is a read/modify/write, even when it already holds zero.
    memory.read32(0x00de2f90);
    memory.write32(0x00de2f90, 0);
    memory.write32(0x00de2f8c, 9);
    return 0xffffffff;
  };
  if (descriptor >= memory.read32(0x00de43e0)) return fail();
  // SAR (signed), followed by DWORD address wrapping, is intentional.
  const tableSlot = (0x00de42e0 + (descriptor >> 5) * 4) >>> 0;
  const page = memory.read32(tableSlot);
  const entry = (page + (descriptor & 31) * 8) >>> 0;
  if ((memory.read8((entry + 4) >>> 0) & 1) === 0) return fail();
  return memory.read32(entry);
}

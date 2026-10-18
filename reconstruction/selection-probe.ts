/** Bounded 00601070 no-callee lookup on stable, fully mapped synthetic memory.
 * Diagnostic paths, invalid pointers, aliasing and connected mode-5 selection are outside scope.
 */
export interface ProbeMemory {
  read8(address: number): number;
  read16(address: number): number;
  read32(address: number): number;
}

export interface ProbeResult {
  eax: number;
  ecx: number;
  edx: number;
  branchSchedule: number[][];
}

function u32(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('DWORD required');
  return value >>> 0;
}

export function probeSelectionRecord(receiver: number, field: number, suppliedRecord: number, memory: ProbeMemory): ProbeResult {
  u32(receiver); u32(field); u32(suppliedRecord);
  const schedule: number[][] = [];
  let record = suppliedRecord;
  schedule.push([0x601080, record === 0 ? 0x601082 : 0x6010cc]);
  if (record === 0) {
    const selected = memory.read16(0x00b77c7a) << 16 >> 16;
    record = memory.read32((0x00b74c26 + Math.imul(selected, 0x300)) >>> 0) >>> 0;
    schedule.push([0x601097, record === 0 ? 0x601099 : 0x6010cc]);
    if (record === 0) throw new RangeError('diagnostic fallback path is outside scope');
  }
  const identity = memory.read32(record) >>> 0;
  const base = memory.read32(0x00ae2364) >>> 0;
  const slot = (identity - base + 16) | 0;
  schedule.push([0x6010d9, slot < 0 ? 0x601196 : 0x6010df]);
  if (slot < 0) throw new RangeError('diagnostic negative slot outside scope');
  const count = memory.read32((receiver + 4) >>> 0) >>> 0;
  schedule.push([0x6010e5, slot > ((count - 1) | 0) ? 0x601196 : 0x6010eb]);
  if (slot > ((count - 1) | 0)) throw new RangeError('diagnostic high slot outside scope');
  const signedField = field << 24 >> 24;
  schedule.push([0x6010f4, signedField < 0 ? 0x601166 : 0x6010f6]);
  if (signedField < 0) throw new RangeError('diagnostic negative field outside scope');
  schedule.push([0x6010f9, signedField >= 50 ? 0x601166 : 0x6010fb]);
  if (signedField >= 50) throw new RangeError('diagnostic high field outside scope');
  const table = memory.read32(receiver) >>> 0;
  const stride = Math.imul(slot, 0xa6ef) >>> 0;
  const statusByte = memory.read8((table + stride + 0x9a69) >>> 0) & 255;
  schedule.push([0x60111b, statusByte === 1 ? 0x60111d : 0x60111f]);
  const status = statusByte === 1 ? 0 : statusByte << 24 >> 24;
  const recordAddress = (table + stride + 0x1e05 + Math.imul(status, 0x1ecd) + signedField * 4) >>> 0;
  const id = memory.read32(recordAddress) >>> 0;
  schedule.push([0x601143, id === 0xffffffff ? 0x6011f2 : 0x601149]);
  if (id === 0xffffffff) return {eax: 0, ecx: signedField >>> 0, edx: stride, branchSchedule: schedule};
  const outputBase = memory.read32(0x00ae23bc) >>> 0;
  return {eax: (outputBase + Math.imul(id, 110)) >>> 0, ecx: outputBase,
          edx: Math.imul(id, 5) >>> 0, branchSchedule: schedule};
}

/** R27-B: original 009488e0 on stable, mapped synthetic memory. */
export type Registers27 = Record<'eax'|'ecx'|'edx'|'esp'|'ebx'|'ebp'|'esi'|'edi', number>;
export type Read27 = ['read', 'source'|'stack', number, 1|4, number];

export function strlenRuntime27(source: Uint8Array, address: number,
  initial: Registers27, stackBefore: Uint8Array) {
  const u32 = (v: number) => Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
  if (!(source instanceof Uint8Array) || ![address, ...Object.values(initial)].every(u32) ||
      !(stackBefore instanceof Uint8Array) || stackBefore.length !== 36 ||
      source.length < 4 || source.length > 256 || source.indexOf(0) < 0 ||
      address + source.length > 0x100000000 || initial.esp < 16 ||
      initial.esp + 20 > 0x100000000 ||
      (address < initial.esp + 20 && initial.esp - 16 < address + source.length))
    throw new RangeError('unsupported synthetic mapped string/stack');
  const events: Read27[] = [];
  const read = (region: 'source'|'stack', offset: number, size: 1|4): number => {
    const bytes = region === 'source' ? source : stackBefore;
    const index = region === 'source' ? offset : offset + 16;
    if (index < 0 || index + size > bytes.length) throw new RangeError('unmapped read');
    let value = 0;
    for (let i = 0; i < size; i++) value += bytes[index+i] * 2**(8*i);
    events.push(['read', region, offset, size, value]);
    return value >>> 0;
  };
  let eax = initial.eax, ecx = read('stack', 4, 4), edx = initial.edx;
  if (ecx !== address) throw new RangeError('stack argument differs from source address');
  const ret = (end: number) => {
    eax = (end - address) >>> 0;
    ecx = read('stack', 4, 4);
    const eip = read('stack', 0, 4);
    return {length: eax, eip, events, stack: stackBefore.slice(),
      registers: {...initial, eax, ecx, edx, esp: (initial.esp+4) >>> 0} as Registers27};
  };
  let offset = 0;
  if (ecx & 3) {
    do {
      eax = ((eax & 0xffffff00) | read('source', offset, 1)) >>> 0;
      offset++; ecx = (ecx+1) >>> 0;
      if ((eax & 255) === 0) return ret(ecx-1);
    } while (ecx & 3);
    // ADD EAX,0 changes flags only; flags are outside the comparison.
  }
  for (;;) {
    eax = read('source', offset, 4);
    edx = (0x7efefeff + eax) >>> 0;
    eax = ((~eax) ^ edx) >>> 0;
    offset += 4; ecx = (ecx+4) >>> 0;
    if ((eax & 0x81010100) === 0) continue;
    eax = read('source', offset-4, 4);
    if ((eax & 255) === 0) return ret(ecx-4);
    if ((eax & 0xff00) === 0) return ret(ecx-3);
    if ((eax & 0xff0000) === 0) return ret(ecx-2);
    if ((eax & 0xff000000) === 0) return ret(ecx-1);
  }
}

/** R26-B: bounded 009466d0 runtime contract on disjoint, stable synthetic memory.
 * This models operand-sized accesses, including duplicate word reads and stack
 * spills. It does not model flags, faults, overlapping buffers or callers.
 */
export type Registers26 = Record<'eax'|'ecx'|'edx'|'esp'|'ebx'|'ebp'|'esi'|'edi', number>;
export type Event26 = ['read'|'write', 'source'|'dest'|'stack', number, number, number];

export function strncpyRuntime26(source: Uint8Array, destination: Uint8Array,
  count: number, sourceAddress: number, destinationAddress: number,
  initial: Registers26, stackBefore: Uint8Array) {
  const u32 = (v: number) => Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
  if (![count, sourceAddress, destinationAddress, initial.eax, initial.ecx,
        initial.edx, initial.esp, initial.ebx, initial.ebp, initial.esi, initial.edi].every(u32) ||
      count > 65 || count > destination.length || stackBefore.length !== 36 ||
      initial.esp < 16 || initial.esp+20 > 0x100000000 ||
      sourceAddress+source.length > 0x100000000 ||
      destinationAddress+destination.length > 0x100000000 ||
      (sourceAddress < destinationAddress+destination.length &&
       destinationAddress < sourceAddress+source.length) ||
      (source.buffer === destination.buffer &&
       source.byteOffset < destination.byteOffset+destination.length &&
       destination.byteOffset < source.byteOffset+source.length) ||
      (sourceAddress < initial.esp+20 && initial.esp-16 < sourceAddress+source.length) ||
      (destinationAddress < initial.esp+20 && initial.esp-16 < destinationAddress+destination.length))
    throw new RangeError('unsupported synthetic disjoint memory');
  const output = destination.slice(), stack = stackBefore.slice();
  const events: Event26[] = [];
  let eax = initial.eax, ecx = count, edx = initial.edx;
  let ebx = initial.ebx, esi = initial.esi, edi = initial.edi;
  let sp = 0, s = 0, d = 0;
  function read(region: 'source'|'stack', offset: number, size: 1|4): number {
    const memory = region === 'source' ? source : stack;
    const index = region === 'stack' ? offset+16 : offset;
    if (index < 0 || index+size > memory.length) throw new RangeError('unmapped read');
    let value = 0;
    for (let i = 0; i < size; i++) value += memory[index+i]*2**(i*8);
    events.push(['read', region, offset, size, value]);
    return value;
  }
  function write(region: 'dest'|'stack', offset: number, size: 1|4, value: number) {
    const memory = region === 'dest' ? output : stack;
    const index = region === 'stack' ? offset+16 : offset;
    if (index < 0 || index+size > memory.length) throw new RangeError('unmapped write');
    value = size === 1 ? value & 255 : value >>> 0;
    events.push(['write', region, offset, size, value]);
    for (let i = 0; i < size; i++) memory[index+i] = (value >>> (i*8)) & 255;
  }
  function push(value: number) { sp -= 4; write('stack', sp, 4, value); }
  function pop() { const value = read('stack', sp, 4); sp += 4; return value; }
  function finish(lateReturnLoad = false) {
    if (count !== 0) {
      if (!lateReturnLoad) eax = read('stack', 4, 4);
      ebx = pop(); esi = pop();
    }
    if (count === 0 || lateReturnLoad) eax = read('stack', 4, 4);
    edi = pop();
    const eip = pop();
    return {destination: output, stack, events, eip,
      registers: {eax, ecx, edx, esp: initial.esp+sp, ebx,
        ebp: initial.ebp, esi, edi} as Registers26};
  }
  if (read('stack', 12, 4) !== count || readStackUnlogged(4) !== destinationAddress ||
      readStackUnlogged(8) !== sourceAddress)
    throw new RangeError('stack arguments differ from admitted inputs');
  function readStackUnlogged(offset: number) {
    return new DataView(stack.buffer, stack.byteOffset, stack.byteLength).getUint32(offset+16, true);
  }
  push(edi);
  if (count === 0) return finish();
  push(esi); push(ebx); ebx = ecx;
  esi = read('stack', 8, 4); edi = read('stack', 4, 4);
  // The leading byte loop aligns the source. Its count test precedes its NUL test.
  if (sourceAddress & 3) {
    do {
      eax = ((eax & 0xffffff00) | read('source', s++, 1)) >>> 0;
      write('dest', d++, 1, eax); ecx--;
      if (ecx === 0) return finish();
      if ((eax & 255) === 0) {
        // Leading-byte NUL: align destination before dword zero padding.
        while ((destinationAddress+d) & 3) {
          write('dest', d++, 1, eax); ecx--;
          if (ecx === 0) return finish();
        }
        ebx = ecx; ecx >>>= 2;
        if (ecx === 0) {
          do { write('dest', d++, 1, eax); } while (--ebx !== 0);
          return finish(true);
        }
        return padWords();
      }
    } while ((sourceAddress+s) & 3);
    ebx = ecx;
  }
  ecx >>>= 2;
  if (ecx !== 0) {
    do {
      eax = read('source', s, 4);
      const sum = (0x7efefeff+eax) >>> 0;
      eax = ((~eax) ^ sum) >>> 0;
      edx = read('source', s, 4); s += 4;
      if (eax & 0x81010100) {
        let nul = -1;
        for (let i = 0; i < 4; i++) if (((edx >>> (8*i)) & 255) === 0) { nul = i; break; }
        if (nul !== -1) {
          if (nul === 0) edx = 0;
          else if (nul === 1) edx &= 0xff;
          else if (nul === 2) edx &= 0xffff;
          write('dest', d, 4, edx); d += 4;
          eax = 0; ecx--;
          if (ecx !== 0) return padWords();
          return padTail();
        }
      }
      write('dest', d, 4, edx); d += 4;
    } while (--ecx !== 0);
    ebx &= 3;
    if (ebx === 0) return finish();
  }
  // Short aligned input or the remainder after whole source words.
  do {
    eax = ((eax & 0xffffff00) | read('source', s++, 1)) >>> 0;
    write('dest', d++, 1, eax);
    if ((eax & 255) === 0) {
      while (--ebx !== 0) write('dest', d++, 1, eax);
      return finish(true);
    }
  } while (--ebx !== 0);
  return finish();

  function padWords(): ReturnType<typeof finish> {
    eax = 0;
    do { write('dest', d, 4, 0); d += 4; } while (--ecx !== 0);
    return padTail();
  }
  function padTail(): ReturnType<typeof finish> {
    ebx &= 3;
    if (ebx === 0) return finish();
    do { write('dest', d++, 1, eax); } while (--ebx !== 0);
    return finish(true);
  }
}

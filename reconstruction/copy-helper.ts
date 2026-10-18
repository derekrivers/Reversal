/** Complete call-free, nonzero-locale-mode path through 00948851.
 * Valid disjoint buffers and a clear direction flag are required. The mode-zero
 * _strncpy call is deliberately outside this reconstruction.
 */
export type CopyEvent = ['source'|'table'|'dest', number, number, number];

export function copyWithLeadByteTable(
  source: Uint8Array, destination: Uint8Array, count: number,
  table: Uint8Array, sourceAddress: number, destinationAddress: number,
  initialEcx: number,
): {destination: Uint8Array; events: CopyEvent[];
    eax: number; ecx: number; edx: number; espDelta: number} {
  if (table.length !== 256 || !Number.isInteger(count) || count < 0 ||
      count > destination.length || !Number.isInteger(sourceAddress) ||
      !Number.isInteger(destinationAddress) || !Number.isInteger(initialEcx))
    throw new RangeError('unsupported mapped buffer or count');
  const output = destination.slice();
  const events: CopyEvent[] = [];
  let src = 0, dst = 0, remaining = count;
  let ecx = initialEcx >>> 0;
  function read(): number {
    if (src >= source.length) throw new RangeError('unmapped source read');
    const value = source[src];
    events.push(['source', src, 1, value]);
    return value;
  }
  function put(size: 1|4, value: number): void {
    if (dst+size > output.length) throw new RangeError('unmapped destination write');
    events.push(['dest', dst, size, value]);
    for (let i = 0; i < size; i++) output[dst+i] = (value >>> (i*8)) & 255;
  }
  if (remaining !== 0) {
    ecx = sourceAddress >>> 0;
    while (true) {
      const first = read();
      remaining--;
      const flag = table[first];
      events.push(['table', first, 1, flag]);
      put(1, first);
      if (flag & 4) {
        dst++; src++; ecx = (ecx+1) >>> 0;
        if (remaining === 0) {
          events.push(['dest', dst-1, 1, 0]);
          output[dst-1] = 0;
          break;
        }
        const trail = read();
        remaining--;
        put(1, trail);
        dst++; src++; ecx = (ecx+1) >>> 0;
        if (trail === 0) {
          events.push(['dest', dst-2, 1, 0]);
          output[dst-2] = 0;
          break;
        }
      } else {
        dst++; src++; ecx = (ecx+1) >>> 0;
        if (first === 0) break;
      }
      if (remaining === 0) break;
    }
  }
  const edx = remaining === 0 ? 0xffffffff : remaining;
  if (remaining !== 0) {
    while (remaining >= 4) {
      put(4, 0);
      dst += 4;
      remaining -= 4;
    }
    while (remaining > 0) {
      put(1, 0);
      dst++;
      remaining--;
    }
    ecx = 0;
  }
  return {destination: output, events, eax: destinationAddress >>> 0,
          ecx, edx, espDelta: 4};
}

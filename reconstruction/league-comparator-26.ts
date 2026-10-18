/** R26-C: bounded 006834f0 comparator over stable mapped memory.
 * Callers supply valid row/shared/table pointers and disjoint writable stack.
 * Widths, read order and integer scratch-register effects follow the x86 body.
 * This models no sort caller, ranking meaning, concurrent mutation or EFLAGS.
 */
export type Registers = Record<'eax'|'ebx'|'ecx'|'edx'|'ebp'|'esi'|'edi'|'esp', number>;
export type Memory = {read(address:number, bytes:number):number;
  write(address:number, bytes:number, value:number):void};
const targets = [0x683550, 0x68356a, 0x683586, 0x683592, 0x683578];
const signed16 = (x:number) => (x << 16) >> 16;
const signed8 = (x:number) => (x << 24) >> 24;

export function leagueCompareStableMemory(memory:Memory, initial:Registers) {
  const r = {...initial};
  const read = (address:number, width:number) => memory.read(address>>>0, width)>>>0;
  const push = (value:number) => {
    r.esp = (r.esp-4)>>>0;
    memory.write(r.esp, 4, value>>>0);
  };
  const pop = () => {
    const value = read(r.esp, 4);
    r.esp = (r.esp+4)>>>0;
    return value;
  };
  const finish = (different:boolean) => {
    r.edi = pop(); r.esi = pop(); r.ebp = pop();
    r.eax = different ? (r.eax-r.ecx)>>>0 : 0;
    r.ebx = pop();
    return {registers:r, returnAddress:pop()};
  };
  push(r.ebx); push(r.ebp); push(r.esi);
  r.esi = read(r.esp+0x10, 4);
  push(r.edi);
  if (read(r.esi, 4) === 0) return finish(false);
  r.edx = read(r.esp+0x18, 4);
  if (read(r.edx, 4) === 0) return finish(false);
  const leftPrimary = read(r.esi+0x19, 2);
  r.ecx = ((r.ecx & 0xffff0000) | leftPrimary)>>>0;
  const rightPrimary = read(r.edx+0x19, 2);
  r.eax = ((r.eax & 0xffff0000) | rightPrimary)>>>0;
  if (leftPrimary !== rightPrimary) {
    r.eax = signed16(rightPrimary)>>>0;
    r.ecx = signed16(leftPrimary)>>>0;
    return finish(true);
  }
  r.eax = read(0xb679fc, 4);
  r.ebx = (-0xc5-r.eax)>>>0;
  r.edi = (r.eax+0xc5)>>>0;
  do {
    const rule = read(r.edi, 1);
    r.eax = ((r.eax & 0xffffff00) | rule)>>>0;
    if (rule === 0) return finish(false);
    r.eax = (signed8(rule)-1)>>>0;
    if (r.eax <= 4) {
      const target = read(0x6835a4+r.eax*4, 4);
      if (target !== targets[r.eax]) throw new Error('unpinned switch-table target');
      if (rule === 1) {
        r.eax = signed16(read(r.esi+0x17, 2))>>>0;
        r.ecx = signed16(read(r.esi+0x15, 2))>>>0;
        r.ebp = signed16(read(r.edx+0x17, 2))>>>0;
        r.ecx = (r.ecx-r.eax)>>>0;
        r.eax = signed16(read(r.edx+0x15, 2))>>>0;
        r.eax = (r.eax-r.ebp)>>>0;
        if (r.ecx !== r.eax) return finish(true);
      } else if (rule === 2 || rule === 5) {
        const offset = rule === 2 ? 0x15 : 0x31;
        r.ecx = signed16(read(r.esi+offset, 2))>>>0;
        r.eax = signed16(read(r.edx+offset, 2))>>>0;
        if (r.ecx !== r.eax) return finish(true);
      } else if (rule === 3) {
        r.ecx = signed8(read(r.esi+0x12, 1))>>>0;
        r.eax = signed8(read(r.edx+0x12, 1))>>>0;
        if (r.ecx !== r.eax) return finish(true);
      }
    }
    r.edi = (r.edi+1)>>>0;
    r.ecx = (r.ebx+r.edi)>>>0;
  } while ((r.ecx|0) < 4);
  return finish(false);
}

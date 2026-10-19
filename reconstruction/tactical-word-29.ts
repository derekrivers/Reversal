/** Bounded original-entry CPU state for 006c38f0; 006c38c0 is comparison context.
 * The caller supplies stable mapped memory for the stack, slot and table.
 * Only AX is a semantic return value; EAX's upper half is retained in the
 * invalid-index arm as an instruction effect.
 */
export type TacticalRegisters={eax:number;ebx:number;ecx:number;edx:number;
  esi:number;edi:number;ebp:number;esp:number;eip:number};
export interface TacticalMemory {
  read8(address:number):number;
  read16(address:number):number;
  read32(address:number):number;
}
export function tacticalWordEntry(entry:number,initial:TacticalRegisters,memory:TacticalMemory):TacticalRegisters {
  if(entry!==0x6c38f0&&entry!==0x6c38c0)throw new RangeError('unsupported entry');
  const result={...initial};
  const slot=memory.read32((initial.esp+4)>>>0)>>>0;
  result.edx=slot;
  const index=memory.read8((slot+0x19)>>>0)&255;
  result.eax=((initial.eax&0xffffff00)|index)>>>0;
  if(index<=10){
    const rawSide=memory.read8((slot+0x27)>>>0)&255;
    const side=rawSide<128?rawSide:rawSide-256;
    result.edx=side>>>0;
    result.eax=index; // MOVSX EAX,AL after the 0..10 guard
    const pointer=memory.read32((initial.ecx+(entry===0x6c38f0?0x8ec4:0x8ebc)+side*4)>>>0)>>>0;
    result.ecx=pointer;
    result.eax=memory.read16((pointer+index*2)>>>0)&0xffff; // MOV AX
  }else{
    result.eax=(result.eax&0xffff0000)>>>0; // XOR AX,AX
  }
  result.eip=memory.read32(initial.esp>>>0)>>>0; // RET 4
  result.esp=(initial.esp+8)>>>0;
  return result;
}

/** Bounded original-entry behavior of FUN_0068d020 over mapped memory. */
export interface MergeInitializerMemory {
  read32(address:number):number;
  write32(address:number,value:number):void;
  write16(address:number,value:number):void;
}

export function initializeMergeHeader(receiver:number,esp:number,memory:MergeInitializerMemory):
  {eax:number;ecx:number;esp:number;eip:number} {
  if(!Number.isInteger(receiver)||receiver<0||receiver>0xffffffff-13)
    throw new RangeError('receiver must address 14 bytes');
  if(!Number.isInteger(esp)||esp<0||esp>0xffffffff-3)
    throw new RangeError('stack pointer must address a return DWORD');
  // MOV EAX,ECX; XOR ECX,ECX; preserve the original store order and widths.
  memory.write32(receiver+2,0);
  memory.write32(receiver+6,0);
  memory.write32(receiver+10,0);
  memory.write16(receiver,0);
  const eip=memory.read32(esp)>>>0;
  return {eax:receiver,ecx:0,esp:(esp+4)>>>0,eip};
}

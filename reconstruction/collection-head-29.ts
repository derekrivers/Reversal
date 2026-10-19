/** Bounded original-entry behavior of FUN_0068d2e0 on mapped memory. */
export interface CollectionHeadMemory { read32(address:number):number; }

export function readCurrentCollectionPayload(receiver:number,esp:number,memory:CollectionHeadMemory):
  {eax:number;esp:number;eip:number} {
  if(!Number.isInteger(receiver)||receiver<0||receiver>0xffffffff-13)
    throw new RangeError('receiver must address its current pointer');
  if(!Number.isInteger(esp)||esp<0||esp>0xffffffff-3)
    throw new RangeError('stack pointer must address return DWORD');
  const cursor=memory.read32(receiver+10)>>>0;
  const eax=cursor===0?0:memory.read32(cursor)>>>0;
  const eip=memory.read32(esp)>>>0;
  return {eax,esp:(esp+4)>>>0,eip};
}

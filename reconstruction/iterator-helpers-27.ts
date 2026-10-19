/** Bounded original-entry behavior of 0068d1b0 and 0068d1d0.
 * The caller supplies mapped, stable memory. Null is a cursor value, not a
 * sentinel payload: a nonnull node with payload zero advances normally.
 */
export interface IteratorMemory {
  read32(address:number):number;
  write32(address:number,value:number):void;
}

export function advanceIterator(entry:number,receiver:number,memory:IteratorMemory):
  {eax:number;ecx:number;edx:number} {
  if(entry!==0x68d1b0&&entry!==0x68d1d0)throw new RangeError('unsupported entry');
  if(!Number.isInteger(receiver)||receiver<0||receiver>0xffffffff)
    throw new RangeError('receiver must be a DWORD');
  let edx=memory.read32((receiver+10)>>>0)>>>0;
  if(edx===0)return {eax:0,ecx:receiver,edx:0};
  const eax=memory.read32(edx)>>>0;
  edx=memory.read32((edx+(entry===0x68d1b0?6:10))>>>0)>>>0;
  memory.write32((receiver+10)>>>0,edx);
  return {eax,ecx:receiver,edx};
}

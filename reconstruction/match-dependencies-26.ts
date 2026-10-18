/** 0062e700 original-entry call-free paths, over stable disjoint synthetic memory.
 * Null player, non-0x51 status and live notification paths require unmapped callees.
 * Reads and writes retain original order; arithmetic wraps at 32 bits.
 */
export interface LifecycleMemory {
  read8(address:number):number;
  read32(address:number):number;
  write8(address:number,value:number):void;
  write32(address:number,value:number):void;
}
export function invalidateStatusCallFree(receiver:number,player:number,flag:number,
  initialEdx:number,memory:LifecycleMemory):{eax:number;ecx:number;edx:number;path:string} {
  for(const v of [receiver,player,flag,initialEdx])
    if(!Number.isInteger(v)||v<0||v>0xffffffff)throw new RangeError('DWORD required');
  if(player===0)throw new RangeError('null player enters diagnostic callees');
  let eax=memory.read32(player)>>>0;
  let ecx=memory.read32(0xae2364)>>>0;
  let edx=initialEdx;
  if((eax|0)>=(ecx|0))return {eax,ecx,edx,path:'count'};
  edx=memory.read32(receiver)>>>0;
  ecx=Math.imul(eax,31)>>>0;
  eax=memory.read32((ecx+edx+14)>>>0)>>>0;
  ecx=(ecx+edx)>>>0;
  if(eax===0xffffffff)return {eax,ecx,edx,path:'sentinel'};
  edx=memory.read32((receiver+4)>>>0)>>>0;
  const record=(Math.imul(eax,48)+edx)>>>0;
  if(memory.read8(record)!==0x51)throw new RangeError('status enters update callee');
  eax=flag;
  if(eax!==0){
    eax=memory.read32((player+0x39)>>>0)>>>0;
    if(eax!==0)throw new RangeError('live notification enters callee');
  }
  memory.write8(record,0xff);
  eax=memory.read32(player)>>>0;
  edx=Math.imul(eax,31)>>>0;
  eax=memory.read32(receiver)>>>0;
  memory.write32((edx+eax+14)>>>0,0xffffffff);
  return {eax,ecx,edx,path:'invalidate'};
}

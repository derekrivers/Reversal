/** Bounded call-free local contract of 006ce110. Memory is a mapped x86 little-endian view. */
export interface KeeperMemory29 {
  read8(address:number):number;
  read16(address:number):number;
  read32(address:number):number;
  write8(address:number,value:number):void;
  write32(address:number,value:number):void;
}

const signed8=(value:number)=>(value<<24)>>24;

export function selectKeeperSlot29(match:number,selector:number,memory:KeeperMemory29):number {
  if(!Number.isInteger(match)||match<0||match>0xffffffff||!Number.isInteger(selector)||selector<0||selector>255)
    throw new RangeError('invalid x86 match pointer or selector byte');
  const cacheOffsets=[0xf59e,0xf5a2];
  const slotBases=[0x4796,0x6a6e];
  for(let side=0;side<2;side++){
    const cache=(match+cacheOffsets[side])>>>0;
    const cached=memory.read32(cache)>>>0;
    if(cached!==0 && signed8(memory.read8((cached+0x19)>>>0))<0)memory.write32(cache,0);
    if(memory.read32(cache)!==0)continue;
    const base=(match+slotBases[side])>>>0;
    let reserve=0;
    for(let i=0;i<20;i++){
      const slot=(base+i*0x1be)>>>0;
      if(memory.read32(cache)===0){
        const index=signed8(memory.read8((slot+0x19)>>>0));
        if(index>=0 && index<=10){
          const tableIndex=signed8(memory.read8((slot+0x27)>>>0));
          const table=memory.read32((match+0x8ebc+tableIndex*4)>>>0)>>>0;
          if(memory.read16((table+index*2)>>>0)===1)memory.write32(cache,slot);
        }
      }
      const reserveIndex=signed8(memory.read8((slot+0x1a)>>>0));
      if(reserveIndex>=0 && reserveIndex<=10){
        const tableIndex=signed8(memory.read8((slot+0x27)>>>0));
        const table=memory.read32((match+0x8ebc+tableIndex*4)>>>0)>>>0;
        if(memory.read16((table+reserveIndex*2)>>>0)===1 &&
           memory.read8((slot+0x19)>>>0)===0xfe &&
           memory.read8((slot+0x20)>>>0)===0xff)reserve=slot;
      }
    }
    if(memory.read32(cache)!==0)continue;
    for(let i=0;i<20;i++){
      const slot=(base+i*0x1be)>>>0;
      const activeIndex=signed8(memory.read8((slot+0x19)>>>0));
      if(activeIndex<0)continue;
      let replacement=0;
      if(reserve!==0){
        const oldIndex=memory.read8((slot+0x19)>>>0);
        replacement=memory.read8((reserve+0x1a)>>>0);
        memory.write8((reserve+0x1a)>>>0,oldIndex);
      }
      memory.write32(cache,slot);
      const tableIndex=signed8(memory.read8((slot+0x27)>>>0));
      const table=memory.read32((match+0x8ebc+tableIndex*4)>>>0)>>>0;
      if(memory.read16((table+signed8(replacement)*2)>>>0)===1)
        memory.write8((slot+0x19)>>>0,replacement);
      break;
    }
  }
  return memory.read32((match+(selector===1?0xf5a2:0xf59e))>>>0)>>>0;
}

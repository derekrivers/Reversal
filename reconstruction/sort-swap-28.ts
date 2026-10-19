/** Original-entry bounded behavior of the call-free 009454d5 byte swap.
 * The oracle fixes entry/stack, a synthetic return sentinel and one data page.
 * Both byte ranges must fit that page; widths up to 31 are admitted.
 */
export interface SwapMemory {
  read8(address:number):number;
  write8(address:number,value:number):void;
}
export interface SwapRegisters {
  eax:number;ebx:number;ecx:number;edx:number;esi:number;edi:number;ebp:number;esp:number;eip:number;
}
export function swapBytes28(first:number,second:number,width:number,initial:SwapRegisters,memory:SwapMemory):SwapRegisters {
  for(const [name,value] of Object.entries({first,second,width}))
    if(!Number.isInteger(value)||value<0||value>0xffffffff)throw new RangeError(`${name} must be a DWORD`);
  if(width>31)throw new RangeError('width outside validated domain');
  if(first<0x300000||second<0x300000||first+width>0x301000||second+width>0x301000||
     first>=0x301000||second>=0x301000)
    throw new RangeError('byte range outside validated data page');
  for(const name of ['eax','ebx','ecx','edx','esi','edi','ebp','esp','eip'] as const)
    if(!Object.hasOwn(initial,name)||!Number.isInteger(initial[name])||initial[name]<0||initial[name]>0xffffffff)
      throw new RangeError(`invalid ${name}`);
  if(initial.eip!==0x9454d5||initial.esp!==0x400800)
    throw new RangeError('outside validated entry/stack domain');
  const final={...initial,eax:first,ecx:second,esp:(initial.esp+4)>>>0,eip:0x700000};
  if(first===second)return final;
  let edx=(width-1)>>>0;
  if(width===0)return {...final,edx};
  let eax=first,ecx=second;
  for(let i=0;i<width;i++){
    const bl=memory.read8(ecx) & 255;
    const dl=memory.read8(eax) & 255;
    memory.write8(eax,bl);
    eax=(eax+1)>>>0;
    memory.write8(ecx,dl);
    ecx=(ecx+1)>>>0;
    edx=(edx&0xffffff00)|dl;
  }
  return {...final,eax,ecx,edx};
}

/** Bounded machine-state reconstruction: 006f09b0 and 00702050..0070210b.
 * Caller supplies mapped synthetic memory, empty x87 and original register state.
 * The grid is data: this module never substitutes a distance formula for its load.
 */
export type GridState31={registers:Record<string,number>;eflags:number;fpcw:number;fpsw:number;fptag:number;
 active_x87:{physical:number;significand:string;exponent:number}[];rng:Record<string,number>;rng_cells:Record<string,number>};
export interface GridMemory31{read(address:number,size:number):number;write(address:number,size:number,value:number):void;}
const hex=(n:number)=>n.toString(16).padStart(8,'0'),u=(n:number)=>n>>>0,s8=(n:number)=>(n<<24)>>24;
function parity(n:number){let ones=0;for(let k=0;k<8;k++)ones+=(n>>>k)&1;return ones%2===0?4:0;}
function addFlags(old:number,a:number,b:number,result:number){
 return u((old&~0x8d5)|(u(a)+u(b)>0xffffffff?1:0)|parity(result)|((a^b^result)&0x10)|
  (result===0?0x40:0)|(result&0x80000000?0x80:0)|((~(a^b)&(a^result)&0x80000000)?0x800:0));
}

export class GridMachine31{
 state:GridState31;readonly memory:GridMemory31;pc=0;events:(string|number)[][]=[];trace:string[]=[];calls:unknown[]=[];
 constructor(state:GridState31,memory:GridMemory31){
  if(![0x27f,0x37f].includes(state.fpcw)||state.fpsw!==0||state.fptag!==65535||state.active_x87.length)
   throw new RangeError('requires empty x87 at explicit 53/64-bit precision');
  this.state=structuredClone(state);this.memory=memory;
 }
 get r(){return this.state.registers;}
 at(pc:number){this.pc=pc;this.trace.push(hex(pc));}
 read(address:number,size:number){const value=this.memory.read(u(address),size);this.events.push([hex(this.pc),'read',hex(u(address)),size,value]);return value;}
 write(address:number,size:number,value:number){value=size===1?value&255:size===2?value&65535:u(value);this.memory.write(u(address),size,value);this.events.push([hex(this.pc),'write',hex(u(address)),size,value]);}
 push(value:number){this.r.esp=u(this.r.esp-4);this.write(this.r.esp,4,value);}
 pop(){const value=this.read(this.r.esp,4);this.r.esp=u(this.r.esp+4);return value;}
 byte(name:string,value:number){this.r[name]=u((this.r[name]&0xffffff00)|(value&255));}
 word(name:string,value:number){this.r[name]=u((this.r[name]&0xffff0000)|(value&65535));}
 snapshot(){return structuredClone(this.state);}
}

/** The original narrowing is s8(abs(s8(a)-s8(b))), including wrapped deltas. */
export function gridIndex31(x:number,y:number,targetX:number,targetY:number){
 for(const v of [x,y,targetX,targetY])if(!Number.isInteger(v)||v<0||v>255)throw new RangeError('raw byte required');
 return 9*s8(Math.abs(s8(y)-s8(targetY)))+s8(Math.abs(s8(x)-s8(targetX)));
}

export function runGridHelper31(m:GridMachine31){
 if(m.state.fpsw!==0||m.state.fptag!==65535||m.state.active_x87.length)throw new RangeError('helper requires empty, clear x87 state');
 const r=m.r;
 m.at(0x6f09b0);r.eax=u(s8(m.read(r.ecx+0x103,1)));
 m.at(0x6f09b7);r.edx=u(s8(m.read(r.esp+8,1)));
 m.at(0x6f09bc);r.eax=u(r.eax-r.edx);
 m.at(0x6f09be);m.push(r.esi);
 m.at(0x6f09bf);r.edx=r.eax&0x80000000?0xffffffff:0;
 m.at(0x6f09c0);r.eax=u(r.eax^r.edx);
 m.at(0x6f09c2);r.eax=u(r.eax-r.edx);
 m.at(0x6f09c4);r.eax=u(s8(r.eax));
 m.at(0x6f09c7);r.esi=u(r.eax*9);
 m.at(0x6f09ca);r.eax=u(s8(m.read(r.ecx+0x102,1)));
 m.at(0x6f09d1);r.ecx=u(s8(m.read(r.esp+8,1)));
 m.at(0x6f09d6);r.eax=u(r.eax-r.ecx);
 m.at(0x6f09d8);r.edx=r.eax&0x80000000?0xffffffff:0;
 m.at(0x6f09d9);r.eax=u(r.eax^r.edx);
 m.at(0x6f09db);r.eax=u(r.eax-r.edx);
 m.at(0x6f09dd);r.edx=u(s8(r.eax));
 m.at(0x6f09e0);const old=r.esi;r.esi=u(r.esi+r.edx);m.state.eflags=addFlags(m.state.eflags,old,r.edx,r.esi);
 if(r.esi>=108)throw new RangeError('grid index outside admitted 108 entries');
 m.at(0x6f09e2);const bits=m.read(0xa15e44+4*r.esi,4),exponent=(bits>>>23)&255,fraction=bits&0x7fffff;
 if(exponent===255||(exponent===0&&fraction!==0))throw new RangeError('only finite normal float32 or signed zero admitted');
 m.state.active_x87=[{physical:7,significand:exponent?((BigInt(fraction)|0x800000n)<<40n).toString(16).padStart(16,'0'):'0000000000000000',
  exponent:(bits>>>31)*32768+(exponent?exponent-127+16383:0)}];
 m.state.fpsw=0x3800;m.state.fptag=exponent?0x3fff:0x7fff;
 m.at(0x6f09e9);r.esi=m.pop();
 m.at(0x6f09ea);const target=m.pop();r.esp=u(r.esp+8);
 return {target,bits};
}

export function runAction33GridPrefix31(m:GridMachine31){
 const r=m.r;
 m.at(0x702050);r.esp=u(r.esp-0x684);
 m.at(0x702056);m.push(r.ebx);
 m.at(0x702057);m.push(r.ebp);
 m.at(0x702058);m.push(r.esi);
 m.at(0x702059);r.esi=r.ecx;
 m.at(0x70205b);r.ebp=0;
 m.at(0x70205d);m.push(r.edi);
 m.at(0x70205e);r.eax=m.read(r.esi+0x19e,4);
 m.at(0x702064);r.ecx=m.read(r.eax+0x4786,4);
 m.at(0x70206a);r.edx=m.read(r.eax+0x4782,4);
 m.at(0x702070);m.byte('eax',m.read(r.esi+0x27,1));
 m.at(0x702073);m.write(r.esp+0x60,4,r.ecx);
 m.at(0x702077);const side=r.eax&255;m.state.eflags=u((m.state.eflags&~0x8d5)|parity(side)|(side===0?0x40:0)|(side&128?0x80:0));
 m.at(0x702079);m.write(r.esp+0x5c,4,r.edx);
 m.at(0x70207d);
 if(side===0){m.at(0x70207f);m.push(11);m.at(0x702081);}else{m.at(0x702083);m.push(r.ebp);}
 m.at(0x702084);m.push(4);
 m.at(0x702086);r.ecx=r.esi;
 m.at(0x702088);const call={site:'00702088',target:'006f09b0',before:m.snapshot(),arguments:[4,side===0?11:0],after:{} as GridState31};
 m.push(0x70208d);const loaded=runGridHelper31(m);if(loaded.target!==0x70208d)throw new Error('wrong helper return');call.after=m.snapshot();m.calls.push(call);
 m.at(0x70208d);m.word('eax',m.read(r.esi+0x39,2));
 m.at(0x702091);m.byte('ecx',m.read(r.esi+0x102,1));
 m.at(0x702097);m.byte('edx',m.read(r.esi+0x103,1));
 m.at(0x70209d);r.edi=m.read(r.esp+0x69c,4);
 m.at(0x7020a4);m.write(r.esp+0x58,2,r.eax);
 m.at(0x7020a9);m.write(r.esp+0x30,1,0);
 m.at(0x7020ae);m.write(r.esp+0x44,1,0);
 m.at(0x7020b3);m.word('eax',m.read(r.esi+0x198,2));
 m.at(0x7020ba);m.write(r.esp+0x50,1,r.ecx);
 m.at(0x7020be);r.ecx=m.read(r.esi+0x19e,4);
 m.at(0x7020c4);m.write(r.esp+0x80,4,loaded.bits);m.state.fpsw=0;m.state.fptag=65535;m.state.active_x87=[];
 m.at(0x7020cb);m.push(r.esi);
 m.at(0x7020cc);m.write(r.esp+0x68,4,0xf0);
 m.at(0x7020d4);m.write(r.esp+0x38,4,r.edi);
 m.at(0x7020d8);m.write(r.esp+0x58,1,r.edx);
 for(const [pc,offset,value] of [[0x7020dc,0x15,0],[0x7020e1,0x19,0],[0x7020e6,0x1b,0],[0x7020eb,0x2c,6],[0x7020f0,0x1c,0],[0x7020f5,0x1e,0],[0x7020fa,0x1d,0]]){
  m.at(pc);m.write(r.esp+offset,1,value);
 }
 m.at(0x7020ff);m.write(r.esp+0x6c,4,r.ebp);
 m.at(0x702103);m.write(r.esp+0x90,2,r.eax);
 return 0x70210b;
}

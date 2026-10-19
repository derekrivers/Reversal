/** Bounded continuation of the R31-A original-produced resolver state.
 * Bit 04 clear reaches pre-00702193; bit 04 set reaches pre-0071614b.
 * Original static scalar constants: 1680.0, 9.0 and 2.5; grid remains supplied data.
 */
import {GridMachine31,runAction33GridPrefix31} from './action33-grid-31.ts';
const u=(v:number)=>v>>>0,s8=(v:number)=>(v<<24)>>24,s16=(v:number)=>(v<<16)>>16;
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function flags(m:GridMachine31,a:number,b:number,value:number,bits=32,subtract=false,preserveCarry=false){
 const mask=bits===8?255:0xffffffff,sign=bits===8?128:0x80000000;
 a=(a&mask)>>>0;b=(b&mask)>>>0;value=(value&mask)>>>0;
 const carry=preserveCarry?(m.state.eflags&1):(subtract?(a<b?1:0):(a+b>mask>>>0?1:0));
 const overflow=(subtract?(a^b):( ~(a^b)))&(a^value)&sign;
 m.state.eflags=u((m.state.eflags&~0x8d5)|carry|parity(value)|((a^b^value)&16)|(value===0?64:0)|(value&sign?128:0)|(overflow?2048:0));
}
function logical(m:GridMachine31,value:number,bits=32){const v=bits===8?value&255:u(value);m.state.eflags=u((m.state.eflags&~0x8d5)|parity(v)|(v===0?64:0)|(v&(bits===8?128:0x80000000)?128:0));}
function sub(m:GridMachine31,name:string,value:number){const a=m.r[name];m.r[name]=u(a-value);flags(m,a,value,m.r[name],32,true);}
function call(m:GridMachine31,site:number,target:number,args:number[],next:number,body:()=>number){
 m.at(site);const record={site:site.toString(16).padStart(8,'0'),target:target.toString(16).padStart(8,'0'),before:m.snapshot(),arguments:args,after:null as null|ReturnType<GridMachine31['snapshot']>};
 m.calls.push(record);m.push(next);const result=body();
 if(result===next)record.after=m.snapshot();return result;
}
function sideGetter(m:GridMachine31){m.at(0x714d30);m.byte('eax',m.read(m.r.ecx+0x27,1));m.at(0x714d33);return m.pop();}
function flagGetter(m:GridMachine31){
 m.at(0x5b57c0);m.r.eax=u(s8(m.read(m.r.esp+4,1)));
 m.at(0x5b57c5);m.byte('eax',m.read(u(m.r.eax+m.r.ecx+0x5b4),1));
 m.at(0x5b57cc);const target=m.pop();m.r.esp=u(m.r.esp+4);return target;
}
function tacticalBase(m:GridMachine31,second=false){
 const r=m.r,pcs=second?[0x71612c,0x716130,0x716133,0x716135,0x716138,0x71613b,0x716141,0x716144]:[0x7160fe,0x716101,0x716104,0x716106,0x716109,0x71610c,0x716112,0x716115];
 m.at(pcs[0]);r.ecx=u(r.eax*5);
 if(second){m.at(0x71612f);m.push(r.edx);}
 m.at(pcs[1]);r.ecx=u(r.ecx<<5);
 m.at(pcs[2]);sub(m,'ecx',r.eax);
 m.at(pcs[3]);r.ecx=u(r.eax+4*r.ecx);
 m.at(pcs[4]);r.edx=u(r.ecx*5);
 m.at(pcs[5]);r.ecx=m.read(r.esi+0x19e,4);
 m.at(pcs[6]);r.eax=u(r.eax+2*r.edx);
 m.at(pcs[7]);r.ecx=u(r.eax+r.ecx+0x91e2);
}
function candidate(m:GridMachine31){
 const r=m.r;
 m.at(0x7160f0);m.push(r.ebx);m.at(0x7160f1);m.push(r.ebp);m.at(0x7160f2);m.push(r.esi);
 m.at(0x7160f3);r.esi=r.ecx;m.at(0x7160f5);m.push(r.edi);
 m.at(0x7160f6);m.byte('eax',m.read(r.esi+0x19,1));m.at(0x7160f9);m.push(r.eax);
 m.at(0x7160fa);r.eax=u(s8(m.read(r.esi+0x27,1)));tacticalBase(m);
 const result=call(m,0x71611c,0x5b57c0,[m.memory.read(r.esp,4)],0x716121,()=>flagGetter(m));
 if(result!==0x716121)throw new Error('flag getter return');
 m.at(0x716121);logical(m,r.eax&4,8);m.at(0x716123);
 if(r.eax&4){
  m.at(0x716125);r.eax=u(s8(m.read(r.esi+0x27,1)));
  m.at(0x716129);m.byte('edx',m.read(r.esi+0x19,1));tacticalBase(m,true);
  return 0x71614b;
 }
 m.at(0x716194);r.edi=m.pop();m.at(0x716195);r.esi=m.pop();m.at(0x716196);r.ebp=m.pop();
 m.at(0x716197);r.eax=0;logical(m,0);m.at(0x716199);r.ebx=m.pop();m.at(0x71619a);return m.pop();
}
function opponentScan(m:GridMachine31){
 const r=m.r;
 m.at(0x6d59b0);m.push(r.ebx);m.at(0x6d59b1);m.push(r.ebp);m.at(0x6d59b2);r.ebp=m.read(r.esp+12,4);
 m.at(0x6d59b6);m.push(r.esi);m.at(0x6d59b7);r.esi=r.ecx;m.at(0x6d59b9);m.push(r.edi);m.at(0x6d59ba);r.ecx=r.ebp;
 if(call(m,0x6d59bc,0x714d30,[],0x6d59c1,()=>sideGetter(m))!==0x6d59c1)throw new Error('side getter return');
 m.at(0x6d59c1);const side=r.eax&255;m.byte('eax',-side);flags(m,0,side,r.eax,8,true);
 m.at(0x6d59c3);r.eax=side?0xffffffff:0;
 m.at(0x6d59c5);r.edi=20;m.at(0x6d59ca);r.eax=u(r.eax+1);m.at(0x6d59cb);r.ecx=r.eax;
 m.at(0x6d59cd);r.eax=u(8*r.ecx);m.at(0x6d59d4);r.eax=u(r.eax-r.ecx);
 m.at(0x6d59d6);r.eax=u(r.eax<<5);m.at(0x6d59d9);r.eax=u(r.eax-r.ecx);
 m.at(0x6d59db);m.byte('ebx',0);logical(m,0,8);m.at(0x6d59dd);r.eax=u(r.eax*5);m.at(0x6d59e0);r.esi=u(r.esi+r.eax*8+0x4796);
 do{
  m.at(0x6d59e7);m.byte('eax',m.read(r.esi+0x19,1));m.at(0x6d59ea);logical(m,r.eax,8);m.at(0x6d59ec);
  if(s8(r.eax)>=0){
   m.at(0x6d59ee);r.ecx=r.esi;
   const result=call(m,0x6d59f0,0x7160f0,[],0x6d59f5,()=>candidate(m));if(result===0x71614b)return result;
   if(result!==0x6d59f5)throw new Error('candidate return');
   m.at(0x6d59f5);flags(m,r.eax,r.ebp,u(r.eax-r.ebp),32,true);m.at(0x6d59f7);
   if(r.eax===r.ebp){m.at(0x6d59f9);const old=r.ebx;m.byte('ebx',r.ebx+1);flags(m,old,1,r.ebx,8,false,true);}
  }
  m.at(0x6d59fb);const old=r.esi;r.esi=u(r.esi+0x1be);flags(m,old,0x1be,r.esi);
  m.at(0x6d5a01);const count=r.edi;r.edi=u(r.edi-1);flags(m,count,1,r.edi,32,true,true);m.at(0x6d5a02);
 }while(r.edi!==0);
 m.at(0x6d5a04);r.edi=m.pop();m.at(0x6d5a05);r.esi=m.pop();m.at(0x6d5a06);m.byte('eax',r.ebx);
 m.at(0x6d5a08);r.ebp=m.pop();m.at(0x6d5a09);r.ebx=m.pop();m.at(0x6d5a0a);const result=m.pop();r.esp=u(r.esp+4);return result;
}
function clockDivision(m:GridMachine31,second=false){
 const r=m.r,pc=second?[0x702149,0x702150,0x702152,0x702154,0x702156,0x702159]:[0x70211f,0x702126,0x702128,0x70212a,0x70212c,0x70212f];
 m.at(pc[0]);r.edx=u(s16(m.read(r.ecx+0x8ed0,2)));
 m.at(pc[1]);const product=BigInt(r.eax|0)*BigInt(r.edx|0);r.eax=Number(BigInt.asUintN(32,product));r.edx=Number(BigInt.asUintN(32,product>>32n));
 m.at(pc[2]);r.edx=u((r.edx|0)>>1);m.at(pc[3]);r.eax=r.edx;m.at(pc[4]);r.eax=r.eax>>>31;
 m.at(pc[5]);const old=r.edx;r.edx=u(r.edx+r.eax);flags(m,old,r.eax,r.edx);
}
function f80(value:number){
 const buffer=new ArrayBuffer(8),v=new DataView(buffer);v.setFloat64(0,value,true);const bits=v.getBigUint64(0,true),exp=Number((bits>>52n)&2047n);
 return {physical:7,significand:exp?(((bits&0xfffffffffffffn)|0x10000000000000n)<<11n).toString(16).padStart(16,'0'):'0000000000000000',exponent:Number(bits>>63n)*32768+(exp?exp-1023+16383:0)};
}
// GridMachine31 only needs <=4-byte integers. The two admitted qword scalar reads
// are recorded without passing a lossy 64-bit integer through Number.
function constant64(m:GridMachine31,address:number,expected:string){
 const low=m.memory.read(address,4),high=m.memory.read(address+4,4),value=high.toString(16).padStart(8,'0')+low.toString(16).padStart(8,'0');
 if(value!==expected)throw new RangeError('unsupported static scalar');m.events.push([m.pc.toString(16).padStart(8,'0'),'read',address.toString(16).padStart(8,'0'),8,value]);
}
export function runAction33OpponentContinuation32(m:GridMachine31){
 if(![0x27f,0x37f].includes(m.state.fpcw)||m.state.fpsw!==0||m.state.fptag!==65535||m.state.active_x87.length)throw new RangeError('continuation requires empty x87 at explicit 53/64-bit precision');
 const r=m.r,result=call(m,0x70210b,0x6d59b0,[m.memory.read(r.esp,4)],0x702110,()=>opponentScan(m));
 if(result===0x71614b)return result;if(result!==0x702110)throw new Error('opponent scan return');
 m.at(0x702110);r.ecx=m.read(r.esi+0x19e,4);m.at(0x702116);m.write(r.esp+0x25,1,r.eax);
 m.at(0x70211a);r.eax=0x2e8ba2e9;clockDivision(m);
 m.at(0x702131);r.eax=0x2e8ba2e9;m.at(0x702136);m.write(r.esp+0x16,1,r.edx);
 m.at(0x70213a);m.byte('edx',m.read(r.esi+0x27,1));m.at(0x70213d);m.write(r.ecx+0x8d4e,1,r.edx);
 m.at(0x702143);r.ecx=m.read(r.esi+0x19e,4);clockDivision(m,true);
 m.at(0x70215b);m.write(r.ecx+0x8d4c,2,r.edx);m.at(0x702162);r.ecx=m.read(r.esi+0x19e,4);
 m.at(0x702168);const momentum=m.read(r.ecx+0x4786,4)|0;
 m.at(0x70216e);constant64(m,0x96d810,'409a400000000000');m.state.fpsw=momentum<1680?0x100:momentum===1680?0x4000:0;
 m.at(0x702174);m.word('eax',m.state.fpsw);m.at(0x702176);logical(m,(r.eax>>>8)&1,8);m.at(0x702179);
 if(!(r.eax&0x100)){m.at(0x70217b);m.write(r.esp+0x18,1,1);}
 m.at(0x702180);const bits=m.read(r.esp+0x80,4),v=new DataView(new ArrayBuffer(4));v.setUint32(0,bits,true);const distance=v.getFloat32(0,true);
 if(!Number.isFinite(distance)||(distance!==0&&(distance<1||distance>16)))throw new RangeError('requires distance zero or in [1,16]');
 m.at(0x702187);if(m.read(0x96d754,4)!==0x41100000)throw new RangeError('unsupported multiplier');
 m.at(0x70218d);constant64(m,0x968e18,'4004000000000000');
 // Zero and float32 values in [1,16] times 9 plus 2.5 are exact in both
 // admitted 53/64-bit precision modes (fewer than 32 significant binary bits).
 const value=distance*9+2.5;m.state.active_x87=[f80(value)];m.state.fptag=0x3fff;m.state.fpsw|=0x3800;
 return 0x702193;
}
export function runAction33OpponentPrefix32(m:GridMachine31){
 if(runAction33GridPrefix31(m)!==0x70210b)throw new Error('grid prefix boundary');
 return runAction33OpponentContinuation32(m);
}

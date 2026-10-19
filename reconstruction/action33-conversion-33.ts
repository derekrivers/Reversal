/** R33-A: R32-A's original-produced ST0 through pre-00702222.
 * Finite, positive conversion domain only. FPCW is explicit synthetic state.
 * x87 status matches the pinned Unicorn oracle; hardware exception flags are
 * not established by this comparison. No resolver return or outcome is supplied.
 */
import {GridMachine31,runGridHelper31} from './action33-grid-31.ts';
import {runAction33OpponentPrefix32} from './action33-opponent-32.ts';
const u=(v:number)=>v>>>0,s8=(v:number)=>(v<<24)>>24,hex=(v:number)=>v.toString(16).padStart(8,'0');
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function logical(m:GridMachine31,value:number,bits=32){const v=bits===8?value&255:u(value);m.state.eflags=u((m.state.eflags&~0x8d5)|parity(v)|(v===0?64:0)|(v&(bits===8?128:0x80000000)?128:0));}
function comparison(m:GridMachine31,a:number,b:number){a&=255;b&=255;const v=(a-b)&255;m.state.eflags=u((m.state.eflags&~0x8d5)|(a<b?1:0)|parity(v)|((a^b^v)&16)|(v===0?64:0)|(v&128?128:0)|((a^b)&(a^v)&128?2048:0));}
function call(m:GridMachine31,site:number,target:number,args:number[],next:number,body:()=>number){
 m.at(site);const record={site:hex(site),target:hex(target),before:m.snapshot(),arguments:args,after:null as null|ReturnType<GridMachine31['snapshot']>};
 m.calls.push(record);m.push(next);const result=body();if(result!==next)throw new Error('unexpected conversion continuation return');record.after=m.snapshot();
}
function qwordStore(m:GridMachine31,address:number,value:bigint){
 const bits=BigInt.asUintN(64,value);m.memory.write(address,4,Number(bits&0xffffffffn));m.memory.write(address+4,4,Number(bits>>32n));
 m.events.push([hex(m.pc),'write',hex(address),8,bits.toString(16).padStart(16,'0')]);
}
function scalar64(m:GridMachine31,address:number,expected:string){
 const value=hex(m.memory.read(address+4,4))+hex(m.memory.read(address,4));
 if(value!==expected)throw new RangeError('unsupported additive scalar');m.events.push([hex(m.pc),'read',hex(address),8,value]);
}
export type ConversionObservation33={site:string;fpcw:number;fpsw:number;fptag:number;active_x87:GridMachine31['state']['active_x87']};
function observe(m:GridMachine31,observations:ConversionObservation33[]){
 const {fpcw,fpsw,fptag,active_x87}=m.snapshot();observations.push({site:hex(m.pc),fpcw,fpsw,fptag,active_x87});
}

/** Actual runtime ABI: no integer argument; consumes ST0; returns signed64 EDX:EAX.
 * The retained caller only produces [2.5,146.5]. No overflow, NaN or exception
 * response is inferred. All four incoming RC settings are admitted for this body.
 */
export function runConversionBody33(m:GridMachine31,observations:ConversionObservation33[]=[]){
 const {active_x87:active,fpcw,fpsw,fptag}=m.state;
 if(![0x27f,0x37f].includes(fpcw&~0xc00)||fptag!==0x3fff||(fpsw&0x3800)!==0x3800||(fpsw&~0x7d00)!==0||active.length!==1||active[0].physical!==7)
  throw new RangeError('conversion requires one normal ST0 and masked 53/64-bit control word');
 const a=active[0],exponent=a.exponent-16383,significand=BigInt('0x'+a.significand);
 if(exponent<1||exponent>7||significand<0x8000000000000000n||significand>0xffffffffffffffffn)
  throw new RangeError('conversion ST0 outside positive caller domain');
 const scale=BigInt(62-exponent);
 if(significand<(5n<<scale)||significand>(293n<<scale))throw new RangeError('conversion ST0 outside positive caller domain');
 const integer=significand>>BigInt(63-exponent),r=m.r;
 m.at(0x945640);m.push(r.ebp);m.at(0x945641);r.ebp=r.esp;m.at(0x945643);r.esp=u(r.esp-12);
 m.at(0x945646);m.at(0x945647);observe(m,observations);m.write(r.ebp-2,2,m.state.fpcw);m.at(0x94564a);
 m.at(0x94564b);m.word('eax',m.read(r.ebp-2,2));m.at(0x94564f);r.eax=u(r.eax|0xc00);logical(m,r.eax>>>8,8);
 m.at(0x945652);m.write(r.ebp-4,2,r.eax);m.at(0x945656);m.state.fpcw=m.read(r.ebp-4,2);
 m.at(0x945659);observe(m,observations);qwordStore(m,r.ebp-12,integer);m.state.fpsw&=~0x3800;m.state.fptag=65535;m.state.active_x87=[];
 m.at(0x94565c);m.state.fpcw=m.read(r.ebp-2,2);m.at(0x94565f);observe(m,observations);r.eax=m.read(r.ebp-12,4);m.at(0x945662);r.edx=m.read(r.ebp-8,4);
 m.at(0x945665);r.esp=r.ebp;r.ebp=m.pop();m.at(0x945666);return m.pop();
}
export function runConversionCall33(m:GridMachine31,observations:ConversionObservation33[]=[]){
 call(m,0x702193,0x945640,[],0x702198,()=>runConversionBody33(m,observations));return 0x702198;
}

/** Reuse R31-A's load/index/ABI implementation. Its entry guard requires clear
 * status, so the adapter saves the comparison bits, temporarily clears modeled
 * FPSW for that call, then combines them with its new TOP. This is model logic;
 * the original emulator state is never modified at a checkpoint or call.
 */
function secondGrid(m:GridMachine31){
 if(m.state.fptag!==65535||m.state.active_x87.length||(m.state.fpsw&~0x4500)!==0)
  throw new RangeError('unsupported second-grid x87 state');
 const status=m.state.fpsw;m.state.fpsw=0;
 const result=runGridHelper31(m);m.state.fpsw|=status;return result;
}

export function runAction33ConversionContinuation33(m:GridMachine31,observations:ConversionObservation33[]=[]){
 if(![0x27f,0x37f].includes(m.state.fpcw))throw new RangeError('caller continuation requires nearest 53/64-bit precision');
 const r=m.r;runConversionCall33(m,observations);
 m.at(0x702198);r.ecx=u(s8(r.eax));m.at(0x70219b);r.eax=0x66666667;
 m.at(0x7021a0);const product=BigInt(r.eax|0)*BigInt(r.ecx|0);r.eax=Number(BigInt.asUintN(32,product));r.edx=Number(BigInt.asUintN(32,product>>32n));
 m.at(0x7021a2);r.edx=u((r.edx|0)>>1);m.at(0x7021a4);r.ecx=r.edx;m.at(0x7021a6);r.eax=r.edx;
 m.at(0x7021a8);r.ecx>>>=31;m.at(0x7021ab);r.eax=u(r.eax+r.ecx);m.at(0x7021ad);m.byte('edx',5);
 m.at(0x7021af);m.word('eax',s8(r.eax)*s8(r.edx));m.at(0x7021b1);m.write(r.esp+0x1b,1,r.eax);
 m.at(0x7021b5);m.byte('eax',m.read(r.esp+0x698,1));m.at(0x7021bc);comparison(m,r.eax,0x39);m.at(0x7021be);
 if((r.eax&255)!==0x39){m.at(0x7021c0);comparison(m,r.eax,3);m.at(0x7021c2);}
 if((r.eax&255)===0x39||(r.eax&255)===3){m.at(0x7021c4);m.write(r.esp+0x28,1,5);}
 m.at(0x7021c9);comparison(m,r.eax,0x33);m.at(0x7021cb);
 if((r.eax&255)!==0x33)throw new RangeError('only action33 caller continuation admitted');
 m.at(0x7021cd);m.write(r.esp+0x64,4,0x78);
 m.at(0x7021d5);m.byte('eax',m.read(r.esi+0x27,1));m.at(0x7021d8);logical(m,r.eax,8);m.at(0x7021da);
 if(!(r.eax&255)){m.at(0x7021dc);m.push(11);m.at(0x7021de);}else{m.at(0x7021e0);m.push(r.ebp);}
 m.at(0x7021e1);m.push(4);m.at(0x7021e3);r.ecx=r.esi;
 let bits=0;call(m,0x7021e5,0x6f09b0,[m.memory.read(r.esp,4),m.memory.read(r.esp+4,4)],0x7021ea,()=>{const result=secondGrid(m);bits=result.bits;return result.target;});
 m.at(0x7021ea);r.eax=u(r.esp+0x7c);m.at(0x7021ee);m.byte('edx',m.read(r.esi+0x103,1));m.at(0x7021f4);m.push(r.eax);m.at(0x7021f5);m.push(r.ecx);
 m.at(0x7021f6);m.byte('ecx',m.read(r.esi+0x27,1));m.at(0x7021f9);m.byte('eax',m.read(r.esi+0x102,1));
 m.at(0x7021ff);m.byte('ecx',r.ecx-1);m.at(0x702201);const carry=(r.ecx&255)!==0;m.byte('ecx',-(r.ecx&255));m.at(0x702203);m.byte('ecx',carry?255:0);
 m.at(0x702205);scalar64(m,0x967890,'3ff0000000000000');const v=new DataView(new ArrayBuffer(4));v.setUint32(0,bits,true);const distance=v.getFloat32(0,true);
 if(!Number.isFinite(distance)||(distance!==0&&(distance<1||distance>16)))throw new RangeError('second grid outside admitted domain');
 // float32 + 1 is exact in both admitted x87 precisions; the store rounds to
 // float32 nearest/even. Status follows the pinned emulator observation only.
 v.setFloat32(0,distance+1,true);m.at(0x70220b);m.write(r.esp,4,v.getUint32(0,true));m.state.fpsw&=~0x3800;m.state.fptag=65535;m.state.active_x87=[];
 m.at(0x70220e);r.ecx&=11;logical(m,r.ecx);m.at(0x702211);m.push(r.ecx);m.at(0x702212);m.push(4);
 m.at(0x702214);m.word('ecx',s8(m.read(r.esp+0x6a8,1)));m.at(0x70221d);m.push(r.edx);m.at(0x70221e);m.push(r.eax);m.at(0x70221f);m.push(r.ecx);m.at(0x702220);r.ecx=r.esi;
 return 0x702222;
}
export function runAction33ConversionPrefix33(m:GridMachine31){
 const stop=runAction33OpponentPrefix32(m);return stop===0x702193?runAction33ConversionContinuation33(m):stop;
}

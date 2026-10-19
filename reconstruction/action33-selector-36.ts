/** R36-A: bounded 006ce110 machine ABI on the original-produced R35-A frame.
 * Reserve-candidate paths are excluded; the caller stops before R(2) or its
 * null-keeper diagnostic. No resolver return or outcome is supplied.
 */
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33RngPrefix35} from './action33-rng-35.ts';
const u=(v:number)=>v>>>0,s8=(v:number)=>(v<<24)>>24,hex=(v:number)=>v.toString(16).padStart(8,'0');
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function arithmetic(m:GridMachine31,a:number,b:number,bits=32,subtract=false,preserveCarry=false){
 const mask=bits===8?255:bits===16?65535:0xffffffff,sign=bits===8?128:bits===16?32768:0x80000000;
 a=u(a&mask);b=u(b&mask);const v=u((subtract?a-b:a+b)&mask);
 const carry=preserveCarry?m.state.eflags&1:subtract?(a<b?1:0):(a+b>u(mask)?1:0);
 const overflow=(subtract?a^b:~(a^b))&(a^v)&sign;
 m.state.eflags=u((m.state.eflags&~0x8d5)|carry|parity(v)|((a^b^v)&16)|(v===0?64:0)|(v&sign?128:0)|(overflow?2048:0));
 return v;
}
function logical(m:GridMachine31,value:number,bits=32){
 const v=bits===8?value&255:u(value);
 m.state.eflags=u((m.state.eflags&~0x8d5)|parity(v)|(v===0?64:0)|(v&(bits===8?128:0x80000000)?128:0));
}

/** The two scan blocks have identical instructions separated by 0xe9 bytes.
 * Both run on every call; argument selection happens only after both blocks.
 */
function scanSide(m:GridMachine31,side:number){
 const r=m.r,delta=side*0xe9,cache=r.ecx+(side?0xf5a2:0xf59e),at=(pc:number)=>m.at(pc+delta);
 at(0x6ce12d);const cached=m.read(cache,4);arithmetic(m,cached,r.ebp,32,true);
 at(0x6ce133);if(cached!==r.ebp)return;
 at(0x6ce139);r.esi=u(r.ecx+(side?0x6a6e:0x4796));
 at(0x6ce13f);r.edi=20;
 at(0x6ce144);r.eax=r.esi;
 do{
  at(0x6ce146);r.edx=m.read(cache,4);
  at(0x6ce14c);logical(m,r.edx);
  at(0x6ce14e);
  if(r.edx===0){
   at(0x6ce150);m.byte('edx',m.read(r.eax+0x19,1));
   at(0x6ce153);logical(m,r.edx,8);
   at(0x6ce155);
   if(s8(r.edx)>=0){
    at(0x6ce157);arithmetic(m,r.edx,10,8,true);
    at(0x6ce15a);
    if(s8(r.edx)<=10){
     at(0x6ce15c);r.ebx=u(s8(m.read(r.eax+0x27,1)));
     at(0x6ce160);r.edx=u(s8(r.edx));
     at(0x6ce163);r.ebx=m.read(r.ecx+4*r.ebx+0x8ebc,4);
     at(0x6ce16a);const position=m.read(r.ebx+2*r.edx,2);arithmetic(m,position,1,16,true);
     at(0x6ce16f);
     if(position===1){at(0x6ce171);m.write(cache,4,r.eax);}
    }
   }
  }
  at(0x6ce177);m.byte('edx',m.read(r.eax+0x1a,1));
  at(0x6ce17a);logical(m,r.edx,8);
  at(0x6ce17c);if(s8(r.edx)>=0)throw new RangeError('unsupported reserve-candidate branch at '+hex(0x6ce17e+delta));
  at(0x6ce1a6);r.eax=arithmetic(m,r.eax,0x1be);
  at(0x6ce1ab);r.edi=arithmetic(m,r.edi,1,32,true,true);
  at(0x6ce1ac);
 }while(r.edi!==0);
 at(0x6ce1ae);r.eax=m.read(cache,4);
 at(0x6ce1b4);logical(m,r.eax);
 at(0x6ce1b6);if(r.eax!==0)return;
 at(0x6ce1b8);m.byte('ebx',0);logical(m,0,8);
 at(0x6ce1ba);r.eax=r.esi;
 at(0x6ce1bc);m.byte('edx',0);logical(m,0,8);
 for(;;){
  at(0x6ce1be);const active=m.read(r.eax+0x19,1);arithmetic(m,active,0,8,true);
  at(0x6ce1c2);if(s8(active)>=0)break;
  at(0x6ce1c4);m.byte('edx',arithmetic(m,r.edx,1,8,false,true));
  at(0x6ce1c6);r.eax=arithmetic(m,r.eax,0x1be);
  at(0x6ce1cb);arithmetic(m,r.edx,20,8,true);
  at(0x6ce1ce);
  if(s8(r.edx)>=20){at(0x6ce1d0);return;}
 }
 at(0x6ce1d2);logical(m,r.ebp);
 at(0x6ce1d4);if(r.ebp!==0)throw new RangeError('unsupported reserve replacement at '+hex(0x6ce1d6+delta));
 at(0x6ce1df);m.write(cache,4,r.eax);
 at(0x6ce1e5);r.edx=u(s8(m.read(r.eax+0x27,1)));
 at(0x6ce1e9);r.esi=u(s8(r.ebx));
 at(0x6ce1ec);r.edx=m.read(r.ecx+4*r.edx+0x8ebc,4);
 at(0x6ce1f3);const position=m.read(r.edx+2*r.esi,2);arithmetic(m,position,1,16,true);
 at(0x6ce1f8);if(position!==1)return;
 at(0x6ce1fa);m.write(r.eax+0x19,1,r.ebx);
}

export function runAction33Selector36(m:GridMachine31){
 const r=m.r;
 m.at(0x6ce110);r.eax=m.read(r.ecx+0xf59e,4);
 m.at(0x6ce116);m.push(r.ebx);m.at(0x6ce117);m.push(r.ebp);
 m.at(0x6ce118);r.ebp=0;logical(m,0);
 m.at(0x6ce11a);m.push(r.esi);
 m.at(0x6ce11b);arithmetic(m,r.eax,r.ebp,32,true);
 m.at(0x6ce11d);m.push(r.edi);
 m.at(0x6ce11e);
 if(r.eax!==0){
  m.at(0x6ce120);m.byte('edx',m.read(r.eax+0x19,1));
  m.at(0x6ce123);logical(m,r.edx,8);
  m.at(0x6ce125);if(s8(r.edx)<0){m.at(0x6ce127);m.write(r.ecx+0xf59e,4,r.ebp);}
 }
 scanSide(m,0);
 m.at(0x6ce1fd);r.eax=m.read(r.ecx+0xf5a2,4);
 m.at(0x6ce203);r.ebp=0;logical(m,0);
 m.at(0x6ce205);arithmetic(m,r.eax,r.ebp,32,true);
 m.at(0x6ce207);
 if(r.eax!==0){
  m.at(0x6ce209);m.byte('edx',m.read(r.eax+0x19,1));
  m.at(0x6ce20c);logical(m,r.edx,8);
  m.at(0x6ce20e);if(s8(r.edx)<0){m.at(0x6ce210);m.write(r.ecx+0xf5a2,4,r.ebp);}
 }
 scanSide(m,1);
 m.at(0x6ce2e6);m.byte('eax',m.read(r.esp+0x14,1));
 m.at(0x6ce2ea);r.edi=m.pop();m.at(0x6ce2eb);r.esi=m.pop();m.at(0x6ce2ec);r.ebp=m.pop();
 m.at(0x6ce2ed);arithmetic(m,r.eax,1,8,true);
 m.at(0x6ce2ef);r.ebx=m.pop();
 m.at(0x6ce2f0);
 if((r.eax&255)===1){
  m.at(0x6ce2f2);r.eax=m.read(r.ecx+0xf5a2,4);m.at(0x6ce2f8);
 }else{
  m.at(0x6ce2fb);r.eax=m.read(r.ecx+0xf59e,4);m.at(0x6ce301);
 }
 const target=m.pop();r.esp=u(r.esp+4);return target;
}

export function runAction33SelectorSuffix36(m:GridMachine31){
 const r=m.r;
 m.at(0x70230c);
 const call={site:'0070230c',target:'006ce110',before:m.snapshot(),arguments:[m.memory.read(r.esp,4)],after:null as null|ReturnType<GridMachine31['snapshot']>};
 m.calls.push(call);m.push(0x702311);
 if(runAction33Selector36(m)!==0x702311)throw new Error('selector return mismatch');
 call.after=m.snapshot();
 m.at(0x702311);r.ebx=r.eax;
 m.at(0x702313);arithmetic(m,r.ebx,r.ebp,32,true);
 m.at(0x702315);m.write(r.esp+0x48,4,r.ebx);
 m.at(0x702319);
 if(r.ebx===r.ebp){
  m.at(0x70231b);r.ecx=u(r.esp+0x494);
  m.at(0x702322);r.edx=u(r.esp+0x294);
  m.at(0x702329);m.push(r.ecx);m.at(0x70232a);m.push(r.edx);
  m.at(0x70232b);m.push(r.ebp);m.at(0x70232c);m.push(r.ebp);
  m.at(0x70232d);m.push(0xa16058);return 0x702332;
 }
 m.at(0x70238e);r.eax=u(s8(m.read(r.esp+0x698,1)));
 if(r.eax!==0x33)throw new RangeError('unsupported action before 00702396');
 m.at(0x702396);r.eax=arithmetic(m,r.eax,0xffffffea);
 m.at(0x702399);arithmetic(m,r.eax,0x24,32,true);
 m.at(0x70239c);
 m.at(0x70239e);r.edx=0;logical(m,0);
 m.at(0x7023a0);m.byte('edx',m.read(r.eax+0x70a5a8,1));
 if(r.edx!==4)throw new RangeError('unsupported action33 byte dispatch');
 m.at(0x7023a6);if(m.read(0x70a594+4*r.edx,4)!==0x7023e1)throw new RangeError('unsupported action33 target dispatch');
 m.at(0x7023e1);m.push(2);return 0x7023e3;
}

export function runAction33SelectorPrefix36(m:GridMachine31){
 if(runAction33RngPrefix35(m)!==0x70230c)throw new RangeError('R35-A clear prefix required');
 return runAction33SelectorSuffix36(m);
}

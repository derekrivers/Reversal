/** R39-A: original-produced R38-A frame through the null participant diagnostic.
 * Both effect and lookup calls remain pending; 0062ed99 is never executed.
 * Undefined integer flags retain the pinned Unicorn 2.1.4 representation.
 */
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33KeeperPrefix38,runKeeperRandom38} from './action33-keeper-38.ts';
const u=(v:number)=>v>>>0,s8=(v:number)=>(v<<24)>>24,hex=(v:number)=>u(v).toString(16).padStart(8,'0');
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function integer(m:GridMachine31,a:number,b:number,subtract=false,bits=32){
 const mask=(v:number)=>bits===8?v&255:u(v);a=mask(a);b=mask(b);
 const v=mask(subtract?a-b:a+b),sign=bits===8?128:0x80000000;
 m.state.eflags=u((m.state.eflags&~0x8d5)|(subtract?a<b?1:0:a+b>2**bits-1?1:0)|parity(v)|((a^b^v)&16)|
  (v===0?64:0)|(v&sign?128:0)|(((subtract?a^b:~(a^b))&(a^v)&sign)?2048:0));return v;
}
function logical(m:GridMachine31,v:number){
 m.state.eflags=u((m.state.eflags&~0x8d5)|parity(v)|(v===0?64:0)|(v&0x80000000?128:0));
}
function enter(m:GridMachine31,site:number,target:number,argc:number){
 m.at(site);const call={site:hex(site),target:hex(target),before:m.snapshot(),
  arguments:Array.from({length:argc},(_,i)=>m.memory.read(m.r.esp+4*i,4)),after:null as null|ReturnType<GridMachine31['snapshot']>};
 m.calls.push(call);m.push(site+5);return call;
}
function random(m:GridMachine31,site:number){
 const call=enter(m,site,0x90cfc0,1);
 if(runKeeperRandom38(m)!==site+5)throw new Error('unexpected RNG return target');
 call.after=m.snapshot();
}
export function runAction33EffectSuffix39(m:GridMachine31){
 const r=m.r;
 if(m.memory.read(r.esp,4)!==r.esi||!r.esi||m.memory.read(r.esi+0x69,4)!==0||m.memory.read(0xb63d28,4)!==0)
  throw new RangeError('effect requires unchanged nonnull shooter with null participant and lookup');
 if(m.state.fptag!==65535||m.state.active_x87.length)throw new RangeError('effect requires empty x87');
 enter(m,0x7024b4,0x6cfe10,5);
 m.at(0x6cfe10);r.esp=integer(m,r.esp,24,true);
 m.at(0x6cfe13);m.push(r.ebx);m.at(0x6cfe14);m.push(r.ebp);m.at(0x6cfe15);m.push(r.esi);m.at(0x6cfe16);m.push(r.edi);
 m.at(0x6cfe17);r.edi=r.ecx;m.at(0x6cfe19);m.push(102);
 m.at(0x6cfe1b);m.write(r.esp+0x16,1,255);m.at(0x6cfe20);m.write(r.esp+0x17,1,255);
 m.at(0x6cfe25);m.write(r.esp+0x1c,4,0x40800000);m.at(0x6cfe2d);m.write(r.esp+0x20,4,0x40800000);
 random(m,0x6cfe35);m.at(0x6cfe3a);m.push(r.eax);random(m,0x6cfe3b);
 m.at(0x6cfe40);m.byte('ebx',r.eax);m.at(0x6cfe42);r.esp=integer(m,r.esp,8);
 m.at(0x6cfe45);integer(m,r.ebx,50,true,8);m.at(0x6cfe48);m.write(r.esp+0x14,1,r.ebx);m.at(0x6cfe4c);
 if(s8(r.ebx)>50){
  m.at(0x6cfe4e);m.push(3);random(m,0x6cfe50);m.at(0x6cfe55);r.esp=integer(m,r.esp,4);
  m.at(0x6cfe58);logical(m,r.eax);m.at(0x6cfe5a);
  if(r.eax!==0){
   m.at(0x6cfe5c);m.push(76);random(m,0x6cfe5e);m.at(0x6cfe63);m.push(r.eax);random(m,0x6cfe64);
   m.at(0x6cfe69);m.byte('ebx',r.eax);m.at(0x6cfe6b);r.esp=integer(m,r.esp,8);m.at(0x6cfe6e);m.write(r.esp+0x14,1,r.ebx);
  }
 }
 m.at(0x6cfe72);m.push(102);random(m,0x6cfe74);m.at(0x6cfe79);m.push(r.eax);random(m,0x6cfe7a);
 m.at(0x6cfe7f);r.esp=integer(m,r.esp,8);m.at(0x6cfe82);integer(m,r.eax,50,true,8);
 m.at(0x6cfe84);m.write(r.esp+0x15,1,r.eax);m.at(0x6cfe88);
 if(s8(r.eax)>50){
  m.at(0x6cfe8a);m.push(3);random(m,0x6cfe8c);m.at(0x6cfe91);r.esp=integer(m,r.esp,4);
  m.at(0x6cfe94);logical(m,r.eax);m.at(0x6cfe96);
  if(r.eax!==0){
   m.at(0x6cfe98);m.push(76);random(m,0x6cfe9a);m.at(0x6cfe9f);m.push(r.eax);random(m,0x6cfea0);
   m.at(0x6cfea5);r.esp=integer(m,r.esp,8);m.at(0x6cfea8);m.write(r.esp+0x15,1,r.eax);
  }
 }
 m.at(0x6cfeac);r.esi=m.read(r.esp+0x2c,4);m.at(0x6cfeb0);logical(m,r.esi);m.at(0x6cfeb2);
 if(r.esi===0)throw new RangeError('unsupported null shooter branch');
 m.at(0x6cfeb8);r.eax=m.read(r.esi+0x69,4);m.at(0x6cfebb);r.ecx=m.read(0xb63d28,4);
 m.at(0x6cfec1);m.push(r.eax);enter(m,0x6cfec2,0x62ed70,1);
 m.at(0x62ed70);r.esp=integer(m,r.esp,0x200,true);m.at(0x62ed76);m.push(r.esi);m.at(0x62ed77);m.push(r.edi);
 m.at(0x62ed78);r.edi=m.read(r.esp+0x20c,4);m.at(0x62ed7f);r.esi=r.ecx;
 m.at(0x62ed81);logical(m,r.edi);m.at(0x62ed83);
 if(r.edi!==0)throw new RangeError('unsupported nonnull participant branch');
 m.at(0x62ed85);r.eax=u(r.esp+8);m.at(0x62ed89);r.ecx=u(r.esp+0x108);
 m.at(0x62ed90);m.push(r.eax);m.at(0x62ed91);m.push(r.ecx);m.at(0x62ed92);m.push(r.edi);m.at(0x62ed93);m.push(r.edi);
 m.at(0x62ed94);m.push(0x9e7f28);return 0x62ed99;
}
export function runAction33EffectPrefix39(m:GridMachine31){
 const stop=runAction33KeeperPrefix38(m);
 if(stop===0x702332)return stop;
 if(stop!==0x7024b4)throw new RangeError('R38-A effect boundary required');
 return runAction33EffectSuffix39(m);
}

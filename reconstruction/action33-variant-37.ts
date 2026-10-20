/** R37-B: the connected action33 R(2) call, including CRT wrap, followed by
 * the caller's keeper arguments. Stops before 00702416; no keeper return.
 * Undefined integer flags follow pinned Unicorn 2.1.4 observations only.
 */
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33SelectorPrefix36} from './action33-selector-36.ts';
const u=(v:number)=>v>>>0,hex=(v:number)=>v.toString(16).padStart(8,'0');
const TABLE=0xaa2454,END=0xad4130,CURSOR=0xde1f60,OFFSET=0xde1f5c,LIMIT=0xde2798,SEED=0xad6c30;
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function logic(m:GridMachine31,v:number){m.state.eflags=u((m.state.eflags&~0x8d5)|parity(v)|(v===0?64:0)|(v&0x80000000?128:0));}
function arithmetic(m:GridMachine31,a:number,b:number,subtract=false){
 const v=u(subtract?a-b:a+b),carry=subtract?a<b:a+b>0xffffffff;
 m.state.eflags=u((m.state.eflags&~0x8d5)|(carry?1:0)|parity(v)|((a^b^v)&16)|(v===0?64:0)|
  (v&0x80000000?128:0)|(((subtract?a^b:~(a^b))&(a^v)&0x80000000)?2048:0));return v;
}
function cell(m:GridMachine31,address:number,value:number){
 m.write(address,4,value);m.state.rng_cells[hex(address)]=u(value);
 if(address===CURSOR)m.state.rng.cursorIndex=(u(value)-TABLE)/4;
 else if(address===OFFSET)m.state.rng.offset=u(value);
 else if(address===SEED)m.state.rng.crtState=u(value);
}
function call(m:GridMachine31,site:number,target:number,argc:number,body:()=>number){
 m.at(site);const c={site:hex(site),target:hex(target),before:m.snapshot(),
  arguments:Array.from({length:argc},(_,i)=>m.memory.read(m.r.esp+4*i,4)),after:null as null|ReturnType<GridMachine31['snapshot']>};
 m.calls.push(c);m.push(site+5);if(body()!==site+5)throw new Error('unexpected original return target');c.after=m.snapshot();
}

export function runVariantCrt37(m:GridMachine31){
 const r=m.r;
 m.at(0x946a04);r.eax=m.read(SEED,4);
 m.at(0x946a09);const product=BigInt(r.eax|0)*214013n;r.eax=u(Math.imul(r.eax,214013));
 const overflow=product!==BigInt(r.eax|0);logic(m,r.eax);m.state.eflags=u(m.state.eflags|(overflow?0x801:0));
 m.at(0x946a0f);r.eax=arithmetic(m,r.eax,2531011);
 m.at(0x946a14);cell(m,SEED,r.eax);
 m.at(0x946a19);const carry=(r.eax>>>15)&1;r.eax=u((r.eax|0)>>16);logic(m,r.eax);m.state.eflags|=carry;
 m.at(0x946a1c);r.eax&=32767;logic(m,r.eax);
 m.at(0x946a21);return m.pop();
}

/** Fixed bound 2 only; state and table accesses are actual ordered operations.
 * The previously established scalar RNG remains separately tested.
 */
export function runVariantRandom37(m:GridMachine31){
 const r=m.r;
 for(const address of [CURSOR,OFFSET,LIMIT,SEED])if(m.memory.read(address,4)!==m.state.rng_cells[hex(address)])
  throw new RangeError('RNG memory/state cells disagree');
 if(m.memory.read(LIMIT,4)!==END||m.state.rng.cursorIndex< -1||m.state.rng.cursorIndex>50999||
  !Number.isInteger(m.state.rng.cursorIndex)||m.state.rng.offset<0||m.state.rng.offset>65535||
  m.memory.read(CURSOR,4)!==TABLE+4*m.state.rng.cursorIndex||m.memory.read(OFFSET,4)!==m.state.rng.offset||
  m.memory.read(SEED,4)!==m.state.rng.crtState)throw new RangeError('unsupported variant RNG state');
 m.at(0x90cfc0);m.push(r.ecx);m.at(0x90cfc1);m.push(r.esi);
 m.at(0x90cfc2);r.esi=m.read(r.esp+12,4);m.at(0x90cfc6);logic(m,r.esi);
 m.at(0x90cfc8);if(r.esi!==2)throw new RangeError('variant bound must be 2');
 m.at(0x90cfcf);r.ecx=m.read(CURSOR,4);m.at(0x90cfd5);r.eax=m.read(LIMIT,4);
 m.at(0x90cfda);r.ecx=arithmetic(m,r.ecx,4);m.at(0x90cfdd);arithmetic(m,r.ecx,r.eax,true);
 m.at(0x90cfdf);cell(m,CURSOR,r.ecx);m.at(0x90cfe5);
 if(r.ecx>r.eax){
  m.at(0x90cfe7);cell(m,CURSOR,TABLE);
  call(m,0x90cff1,0x946a04,0,()=>runVariantCrt37(m));
  m.at(0x90cff6);r.ecx=m.read(CURSOR,4);m.at(0x90cffc);r.eax&=65535;logic(m,r.eax);
  m.at(0x90d001);cell(m,OFFSET,r.eax);m.at(0x90d006);
 }else{m.at(0x90d008);r.eax=m.read(OFFSET,4);}
 m.at(0x90d00d);arithmetic(m,r.esi,65535,true);m.at(0x90d013);
 m.at(0x90d015);arithmetic(m,r.esi,0xffff0001,true);m.at(0x90d01b);
 m.at(0x90d01d);r.eax=arithmetic(m,r.eax,m.read(r.ecx,4));
 m.at(0x90d01f);r.edx=r.eax&0x80000000?0xffffffff:0;
 m.at(0x90d020);const dividend=r.eax|0;r.eax=u(Math.trunc(dividend/2));r.edx=u(dividend%2);
 m.at(0x90d022);logic(m,r.esi);m.at(0x90d024);
 m.at(0x90d028);r.eax=r.edx;
 m.at(0x90d02a);r.esi=m.pop();m.at(0x90d02b);r.ecx=m.pop();m.at(0x90d02c);return m.pop();
}

export function runAction33VariantSuffix37(m:GridMachine31){
 const r=m.r;
 call(m,0x7023e3,0x90cfc0,1,()=>runVariantRandom37(m));
 m.at(0x7023e8);r.esp=arithmetic(m,r.esp,4);
 m.at(0x7023eb);m.write(r.esp+0x1c,1,r.eax);
 m.at(0x7023ef);r.edx=m.read(r.esp+0x698,4);
 m.at(0x7023f6);r.eax=u(r.esp+0x14);m.at(0x7023fa);r.ecx=u(r.esp+0x20);
 m.at(0x7023fe);m.push(r.eax);m.at(0x7023ff);r.eax=m.read(r.esp+0x20,4);
 m.at(0x702403);m.push(r.ecx);m.at(0x702404);m.byte('ecx',m.read(r.esi+0x103,1));
 m.at(0x70240a);m.push(r.edx);m.at(0x70240b);m.byte('edx',m.read(r.esi+0x102,1));
 m.at(0x702411);m.push(r.eax);m.at(0x702412);m.push(r.ecx);m.at(0x702413);m.push(r.edx);
 m.at(0x702414);r.ecx=r.ebx;return 0x702416;
}

export function runAction33VariantPrefix37(m:GridMachine31){
 const stop=runAction33SelectorPrefix36(m);
 if(stop===0x702332)return stop;
 if(stop!==0x7023e3)throw new RangeError('R36-A variant boundary required');
 return runAction33VariantSuffix37(m);
}

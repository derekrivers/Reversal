/** R34-A original-entry action 33 adjustment and caller through pre-00702241.
 * The distinct bit-04 path, RNG execution and later 007022fd checkpoint are
 * outside this bounded machine-state continuation.
 */
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33ConversionPrefix33} from './action33-conversion-33.ts';

const u=(v:number)=>v>>>0,hex=(v:number)=>v.toString(16).padStart(8,'0');
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function sub16Flags(old:number,a:number,b:number){
 const result=(a-b)&0xffff;
 return u((old&~0x8d5)|(a<b?1:0)|parity(result)|((a^b^result)&16)|(result===0?64:0)|
  (result&0x8000?128:0)|((a^b)&(a^result)&0x8000?2048:0));
}
function add16Flags(old:number,a:number,b:number){
 const result=(a+b)&0xffff;
 return u((old&~0x8d5)|(a+b>0xffff?1:0)|parity(result)|((a^b^result)&16)|
  (result===0?64:0)|(result&0x8000?128:0)|((~(a^b)&(a^result)&0x8000)?2048:0));
}

/** The action word at [entry ESP+4] is 0x33 in the admitted resolver cases.
 * Original 00713e90 takes the 00713eef short return branch. The four-argument
 * 006cb6c0 path and nested conversion are unreachable for this action word.
 */
export function runAction33Adjustment34(m:GridMachine31){
 const r=m.r;
 m.at(0x713e90);m.push(r.ebx);
 m.at(0x713e91);r.ebx=m.read(r.esp+0x20,4);
 m.at(0x713e95);m.push(r.esi);
 m.at(0x713e96);r.esi=r.ecx;
 m.at(0x713e98);m.word('ecx',m.read(r.esp+12,2));
 m.at(0x713e9d);m.push(r.edi);
 m.at(0x713e9e);m.state.eflags=sub16Flags(m.state.eflags,r.ecx&65535,0x5b);
 m.at(0x713ea2);m.byte('eax',2);
 m.at(0x713ea4);m.write(r.ebx,2,0);
 const compares:[[number,number,number],...Array<[number,number,number]>]=[
  [0x713ea9,0x713eaf,0x5b],[0x713eaf,0x713eb3,0x5c],
  [0x713eb9,0x713ebd,0x3d],[0x713ec3,0x713ec7,0x36],
  [0x713ecd,0x713ed1,0x34],[0x713ed7,0x713edb,0x37],
  [0x713ee1,0x713ee5,0x5a],[0x713eeb,0x713eef,0x33]];
 // The first pair represents JZ after the initial comparison; the second
 // pair is the next CMP/JZ. Keep the instruction order explicit below.
 m.at(0x713ea9);
 for(const [cmp,jump,value] of compares.slice(1,-1)){
  m.at(cmp);m.state.eflags=sub16Flags(m.state.eflags,r.ecx&65535,value);m.at(jump);
  if((r.ecx&65535)===value)throw new RangeError('unsupported adjustment action');
 }
 m.at(0x713eeb);m.state.eflags=sub16Flags(m.state.eflags,r.ecx&65535,0x33);
 m.at(0x713eef);if((r.ecx&65535)!==0x33)throw new RangeError('action 33 required');
 m.at(0x713fba);r.edi=m.pop();
 m.at(0x713fbb);r.esi=m.pop();
 m.at(0x713fbc);r.ebx=m.pop();
 m.at(0x713fbd);const target=m.pop();r.esp=u(r.esp+0x1c);return target;
}

export function runAction33AdjustmentPrefix34(m:GridMachine31){
 if(runAction33ConversionPrefix33(m)!==0x702222)throw new RangeError('clear action 33 path required');
 const r=m.r,call={site:'00702222',target:'00713e90',before:m.snapshot(),arguments:[] as number[],after:null as null|ReturnType<GridMachine31['snapshot']>};
 for(let i=0;i<7;i++)call.arguments.push(m.memory.read(r.esp+4*i,4));
 m.calls.push(call);
 m.at(0x702222);m.push(0x702227);
 if(runAction33Adjustment34(m)!==0x702227)throw new Error('adjustment return mismatch');
 call.after=m.snapshot();
 m.at(0x702227);m.write(r.esp+0x10,1,r.eax);
 m.at(0x70222b);r.eax=u((m.read(r.esp+0x7c,2)<<16)>>16);
 m.at(0x702230);r.edx=(r.eax&0x80000000)?0xffffffff:0;
 m.at(0x702231);r.eax=u(r.eax-r.edx);m.state.eflags=sub16Flags(m.state.eflags,r.eax&65535,0);
 m.at(0x702233);r.eax=u((r.eax|0)>>1); // Zero for the admitted 0x33 helper output.
 m.at(0x702235);r.eax=u(-r.eax);m.state.eflags=sub16Flags(m.state.eflags,0,r.eax&65535);
 m.at(0x702237);const address=r.esi+0x39,old=m.read(address,2),result=(old+(r.eax&65535))&65535;
 m.write(address,2,result);m.state.eflags=add16Flags(m.state.eflags,old,r.eax&65535);
 m.at(0x70223b);r.edx=u((m.read(r.esp+0x7c,2)<<16)>>16);
 m.at(0x702240);m.push(r.edx);
 return 0x702241;
}

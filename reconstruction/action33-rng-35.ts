/** R35-A: original-entry action33 through the zero-bound draw and guarded
 * selector-call preparation. Stops before 0070230c; no selector ABI or outcome.
 */
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33AdjustmentPrefix34} from './action33-adjustment-34.ts';

const u=(v:number)=>v>>>0;
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function logicFlags(old:number,v:number,width=32){
 return u((old&~0x8d5)|parity(v)|(v===0?64:0)|(v&(width===8?128:0x80000000)?128:0));
}
function subFlags(old:number,a:number,b:number){
 const v=u(a-b);
 return u((old&~0x8d5)|(a<b?1:0)|parity(v)|((a^b^v)&16)|(v===0?64:0)|
  (v&0x80000000?128:0)|((a^b)&(a^v)&0x80000000?2048:0));
}
function addFlags(old:number,a:number,b:number){
 const v=u(a+b);
 return u((old&~0x8d5)|(a+b>0xffffffff?1:0)|parity(v)|((a^b^v)&16)|(v===0?64:0)|
  (v&0x80000000?128:0)|(~(a^b)&(a^v)&0x80000000?2048:0));
}

/** The actual 0090cfc0 zero-bound branch. Its two saved registers and plain
 * RET leave argument cleanup to the caller. No RNG cell/table access occurs.
 * EFLAGS matches the pinned Unicorn observations; logical-operation AF is
 * architecturally undefined and is not a general hardware-status claim.
 */
export function runZeroBoundRandom35(m:GridMachine31){
 const r=m.r;
 m.at(0x90cfc0);m.push(r.ecx);
 m.at(0x90cfc1);m.push(r.esi);
 m.at(0x90cfc2);r.esi=m.read(r.esp+12,4);
 m.at(0x90cfc6);m.state.eflags=logicFlags(m.state.eflags,r.esi);
 m.at(0x90cfc8);if(r.esi!==0)throw new RangeError('unsupported nonzero RNG bound at 0090cfcf');
 m.at(0x90cfca);r.eax=0;m.state.eflags=logicFlags(m.state.eflags,0);
 m.at(0x90cfcc);r.esi=m.pop();
 m.at(0x90cfcd);r.ecx=m.pop();
 m.at(0x90cfce);return m.pop();
}

export function runAction33RngSuffix35(m:GridMachine31){
 const r=m.r,call={site:'00702241',target:'0090cfc0',before:m.snapshot(),
  arguments:[m.memory.read(r.esp,4)],after:null as null|ReturnType<GridMachine31['snapshot']>};
 m.at(0x702241);m.calls.push(call);m.push(0x702246);
 if(runZeroBoundRandom35(m)!==0x702246)throw new Error('RNG return mismatch');
 call.after=m.snapshot();
 m.at(0x702246);m.write(r.esp+0x80,4,r.eax);
 m.at(0x70224d);m.state.eflags=subFlags(m.state.eflags,r.edi,r.eax);r.edi=u(r.edi-r.eax);
 m.at(0x70224f);r.eax=m.read(r.esi+0x19e,4);
 m.at(0x702255);m.state.eflags=addFlags(m.state.eflags,r.esp,4);r.esp=u(r.esp+4);
 m.at(0x702258);m.write(r.esp+0x69c,4,r.edi);
 m.at(0x70225f);const contact=m.read(r.eax+0xf5aa,4);m.state.eflags=subFlags(m.state.eflags,r.esi,contact);
 m.at(0x702265);if(r.esi===contact)throw new RangeError('unsupported contact branch at 0070226b');
 return 0x7022fd;
}

export function prepareAction33Selector35(m:GridMachine31){
 const r=m.r;
 m.at(0x7022fd);m.byte('edx',m.read(r.esi+0x27,1));
 m.at(0x702300);r.ecx=m.read(r.esi+0x19e,4);
 m.at(0x702306);m.state.eflags=logicFlags(m.state.eflags,r.edx&255,8);
 m.at(0x702308);m.byte('eax',(r.edx&255)===0?1:0);
 m.at(0x70230b);m.push(r.eax);
 return 0x70230c;
}

export function runAction33RngPrefix35(m:GridMachine31){
 if(runAction33AdjustmentPrefix34(m)!==0x702241)throw new RangeError('clear action33 path required');
 if(runAction33RngSuffix35(m)!==0x7022fd)throw new Error('RNG caller boundary mismatch');
 return prepareAction33Selector35(m);
}

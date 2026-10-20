/** R38-A: original-produced action33 keeper call and caller to pre-006cfe10.
 * Bounded finite x87, original stack/operand order and shared small-bound RNG.
 * Undefined integer flags follow Unicorn 2.1.4, not a hardware-wide contract.
 */
import {GridMachine31} from './action33-grid-31.ts';
import {runAction33VariantPrefix37,runVariantCrt37} from './action33-variant-37.ts';
import {arithmetic,extended,truncate,type Extended} from './x87-finite.ts';
const u=(v:number)=>v>>>0,s8=(v:number)=>(v<<24)>>24,s16=(v:number)=>(v<<16)>>16,hex=(v:number)=>u(v).toString(16).padStart(8,'0');
const TABLE=0xaa2454,END=0xad4130,CURSOR=0xde1f60,OFFSET=0xde1f5c,LIMIT=0xde2798,SEED=0xad6c30;
function parity(v:number){let n=0;for(let k=0;k<8;k++)n+=(v>>>k)&1;return n%2===0?4:0;}
function mask(v:number,bits:number){return bits===8?v&255:bits===16?v&65535:u(v);}
function logical(m:GridMachine31,value:number,bits=32){
 const v=mask(value,bits),sign=bits===32?0x80000000:1<<(bits-1);
 m.state.eflags=u((m.state.eflags&~0x8d5)|parity(v)|(v===0?64:0)|(v&sign?128:0));return v;
}
function integer(m:GridMachine31,a:number,b:number,subtract=false,bits=32){
 a=mask(a,bits);b=mask(b,bits);const v=mask(subtract?a-b:a+b,bits),sign=bits===32?0x80000000:1<<(bits-1);
 m.state.eflags=u((m.state.eflags&~0x8d5)|(subtract?a<b?1:0:a+b>2**bits-1?1:0)|parity(v)|((a^b^v)&16)|
  (v===0?64:0)|(v&sign?128:0)|(((subtract?a^b:~(a^b))&(a^v)&sign)?2048:0));return v;
}
function multiply(m:GridMachine31,value:number){
 const product=BigInt(m.r.eax|0)*BigInt(value|0),low=Number(BigInt.asUintN(32,product));
 m.r.eax=low;m.r.edx=Number(BigInt.asUintN(32,product>>32n));logical(m,low);
 if(product!==BigInt(low|0))m.state.eflags|=0x801;
}
function shift31(m:GridMachine31){const v=m.r.eax;m.r.eax=v>>>31;logical(m,m.r.eax);m.state.eflags|=((v>>>30)&1)|(v&0x80000000?2048:0);}
function call(m:GridMachine31,site:number,target:number,argc:number,body:()=>number){
 m.at(site);const c={site:hex(site),target:hex(target),before:m.snapshot(),
  arguments:Array.from({length:argc},(_,i)=>m.memory.read(m.r.esp+4*i,4)),after:null as null|ReturnType<GridMachine31['snapshot']>};
 m.calls.push(c);m.push(site+5);if(body()!==site+5)throw new Error('unexpected original return target');c.after=m.snapshot();
}
function cell(m:GridMachine31,address:number,value:number){
 m.write(address,4,value);m.state.rng_cells[hex(address)]=u(value);
 if(address===CURSOR)m.state.rng.cursorIndex=(u(value)-TABLE)/4;
 else if(address===OFFSET)m.state.rng.offset=u(value);else if(address===SEED)m.state.rng.crtState=u(value);
}

/** The exact nonzero signed-small-bound path, plus its zero-bound early return.
 * This consumes the same actual cells and synthetic table as the caller.
 */
export function runKeeperRandom38(m:GridMachine31){
 const r=m.r,bound=m.memory.read(r.esp+4,4)|0;
 if(bound< -65535||bound>65535)throw new RangeError('unsupported keeper RNG bound');
 for(const address of [CURSOR,OFFSET,LIMIT,SEED])if(m.memory.read(address,4)!==m.state.rng_cells[hex(address)])throw new RangeError('RNG memory/state cells disagree');
 if(m.memory.read(LIMIT,4)!==END||!Number.isInteger(m.state.rng.cursorIndex)||m.state.rng.cursorIndex< -1||m.state.rng.cursorIndex>50999||
  m.state.rng.offset<0||m.state.rng.offset>65535||m.memory.read(CURSOR,4)!==TABLE+4*m.state.rng.cursorIndex||
  m.memory.read(OFFSET,4)!==m.state.rng.offset||m.memory.read(SEED,4)!==m.state.rng.crtState)throw new RangeError('unsupported keeper RNG state');
 m.at(0x90cfc0);m.push(r.ecx);m.at(0x90cfc1);m.push(r.esi);m.at(0x90cfc2);r.esi=m.read(r.esp+12,4);
 m.at(0x90cfc6);logical(m,r.esi);m.at(0x90cfc8);
 if(!r.esi){m.at(0x90cfca);r.eax=logical(m,0);m.at(0x90cfcc);r.esi=m.pop();m.at(0x90cfcd);r.ecx=m.pop();m.at(0x90cfce);return m.pop();}
 m.at(0x90cfcf);r.ecx=m.read(CURSOR,4);m.at(0x90cfd5);r.eax=m.read(LIMIT,4);
 m.at(0x90cfda);r.ecx=integer(m,r.ecx,4);m.at(0x90cfdd);integer(m,r.ecx,r.eax,true);
 m.at(0x90cfdf);cell(m,CURSOR,r.ecx);m.at(0x90cfe5);
 if(r.ecx>r.eax){
  m.at(0x90cfe7);cell(m,CURSOR,TABLE);call(m,0x90cff1,0x946a04,0,()=>runVariantCrt37(m));
  m.at(0x90cff6);r.ecx=m.read(CURSOR,4);m.at(0x90cffc);r.eax=logical(m,r.eax&65535);
  m.at(0x90d001);cell(m,OFFSET,r.eax);m.at(0x90d006);
 }else{m.at(0x90d008);r.eax=m.read(OFFSET,4);}
 m.at(0x90d00d);integer(m,r.esi,65535,true);m.at(0x90d013);m.at(0x90d015);integer(m,r.esi,0xffff0001,true);m.at(0x90d01b);
 m.at(0x90d01d);r.eax=integer(m,r.eax,m.read(r.ecx,4));m.at(0x90d01f);r.edx=r.eax&0x80000000?0xffffffff:0;
 m.at(0x90d020);const dividend=r.eax|0;r.eax=u(Math.trunc(dividend/bound));r.edx=u(dividend%bound);
 m.at(0x90d022);logical(m,r.esi);m.at(0x90d024);if(bound<0){m.at(0x90d026);r.edx=integer(m,0,r.edx,true);}
 m.at(0x90d028);r.eax=r.edx;m.at(0x90d02a);r.esi=m.pop();m.at(0x90d02b);r.ecx=m.pop();m.at(0x90d02c);return m.pop();
}

type Value={value:Extended;negativeZero:boolean};
function val(n:number):Value{return {value:extended(n),negativeZero:Object.is(n,-0)};}
function negative(v:Value){return v.value.coefficient<0n||(v.value.coefficient===0n&&v.negativeZero);}
/** Active physical payloads and TOP are represented; empty physical payloads
 * and FIP/FDP remain outside the inherited machine representation.
 */
class KeeperFloat38{
 readonly m:GridMachine31;
 constructor(m:GridMachine31){this.m=m;if(![0x27f,0x37f].includes(m.state.fpcw)||(m.state.fpsw&~0x4500)||m.state.fptag!==65535||m.state.active_x87.length)throw new RangeError('keeper requires empty nearest 53/64-bit x87');}
 get top(){return (this.m.state.fpsw>>>11)&7;}
 get math(){return arithmetic((this.m.state.fpcw&0x300)===0x200?53:64);}
 get(i=0):Value{
  const n=(this.top+i)&7,a=this.m.state.active_x87.find(v=>v.physical===n);if(!a)throw new RangeError('empty keeper x87 operand');
  const c=BigInt('0x'+a.significand),negative=!!(a.exponent&32768);return {value:{coefficient:negative?-c:c,exponent:(a.exponent&32767)-16383-63},negativeZero:c===0n&&negative};
 }
 set(v:Value,i=0){
  const n=(this.top+i)&7,c=v.value.coefficient,mag=c<0n?-c:c,length=mag===0n?0:mag.toString(2).length;
  if(length>64)throw new RangeError('unrounded keeper x87 significand');
  const e=length?v.value.exponent+length-1+16383:0;
  if(e<0||e>=32767)throw new RangeError('non-normal keeper x87 result');
  const payload={physical:n,significand:(mag<<BigInt(64-length)).toString(16).padStart(16,'0'),exponent:e+(negative(v)?32768:0)};
  this.m.state.active_x87=this.m.state.active_x87.filter(a=>a.physical!==n).concat(payload).sort((a,b)=>a.physical-b.physical);
  this.m.state.fptag=(this.m.state.fptag&~(3<<(n*2)))|((length?0:1)<<(n*2));
 }
 push(v:Value){const n=(this.top+7)&7;if(this.m.state.active_x87.some(a=>a.physical===n))throw new RangeError('keeper x87 overflow');this.m.state.fpsw=(this.m.state.fpsw&~0x3800)|(n<<11);this.set(v);}
 pop(){const n=this.top,v=this.get();this.m.state.active_x87=this.m.state.active_x87.filter(a=>a.physical!==n);this.m.state.fptag|=3<<(n*2);this.m.state.fpsw=(this.m.state.fpsw&~0x3800)|(((n+1)&7)<<11);return v;}
 combine(a:Value,b:Value,mul=false):Value{
  const value=mul?this.math.multiply(a.value,b.value):this.math.add(a.value,b.value);
  return {value,negativeZero:value.coefficient===0n&&(mul?negative(a)!==negative(b):negative(a)&&negative(b))};
 }
 add(v:Value){this.set(this.combine(this.get(),v));}
 mul(v:Value){this.set(this.combine(this.get(),v,true));}
 pair(mul=false){const result=this.combine(this.get(1),this.get(),mul);this.pop();this.set(result);}
 number(v=this.get()){return Number(v.value.coefficient)*2**v.value.exponent||(v.negativeZero?-0:0);}
 load32(address:number){const bits=this.m.read(address,4),b=new DataView(new ArrayBuffer(4));b.setUint32(0,bits,true);const n=b.getFloat32(0,true);if(!Number.isFinite(n)||Math.abs(n)>100)throw new RangeError('unsupported keeper float32');return val(n);}
 load64(address:number){
  const lo=this.m.memory.read(address,4),hi=this.m.memory.read(address+4,4),b=new DataView(new ArrayBuffer(8));b.setUint32(0,lo,true);b.setUint32(4,hi,true);
  this.m.events.push([hex(this.m.pc),'read',hex(address),8,hex(hi)+hex(lo)]);const n=b.getFloat64(0,true);if(!Number.isFinite(n))throw new RangeError('unsupported keeper float64');return val(n);
 }
 store32(address:number){const b=new DataView(new ArrayBuffer(4));b.setFloat32(0,this.number(),true);this.m.write(address,4,b.getUint32(0,true));this.pop();}
 store64(address:number){const b=new DataView(new ArrayBuffer(8));b.setFloat64(0,this.number(),true);qword(this.m,address,b.getBigUint64(0,true));}
}
function qword(m:GridMachine31,address:number,value:bigint){const bits=BigInt.asUintN(64,value);m.memory.write(address,4,Number(bits&0xffffffffn));m.memory.write(address+4,4,Number(bits>>32n));m.events.push([hex(m.pc),'write',hex(address),8,bits.toString(16).padStart(16,'0')]);}
function conversion(m:GridMachine31,f:KeeperFloat38){
 const r=m.r;if(m.state.active_x87.length!==1)throw new RangeError('keeper ftol requires one value');const converted=truncate(f.get().value);
 m.at(0x945640);m.push(r.ebp);m.at(0x945641);r.ebp=r.esp;m.at(0x945643);r.esp=integer(m,r.esp,0xfffffff4);
 m.at(0x945646);m.at(0x945647);m.write(r.ebp-2,2,m.state.fpcw);m.at(0x94564a);m.at(0x94564b);m.word('eax',m.read(r.ebp-2,2));
 m.at(0x94564f);r.eax=u(r.eax|0xc00);logical(m,r.eax>>>8,8);m.at(0x945652);m.write(r.ebp-4,2,r.eax);
 m.at(0x945656);m.state.fpcw=m.read(r.ebp-4,2);m.at(0x945659);qword(m,r.ebp-12,BigInt(converted));f.pop();
 m.at(0x94565c);m.state.fpcw=m.read(r.ebp-2,2);m.at(0x94565f);r.eax=m.read(r.ebp-12,4);m.at(0x945662);r.edx=m.read(r.ebp-8,4);
 m.at(0x945665);r.esp=r.ebp;r.ebp=m.pop();m.at(0x945666);return m.pop();
}
function tactical(m:GridMachine31){
 const r=m.r;m.at(0x6c38c0);r.edx=m.read(r.esp+4,4);m.at(0x6c38c4);m.byte('eax',m.read(r.edx+0x19,1));
 m.at(0x6c38c7);logical(m,r.eax,8);m.at(0x6c38c9);let rejected=s8(r.eax)<0;
 if(!rejected){m.at(0x6c38cb);integer(m,r.eax,10,true,8);m.at(0x6c38cd);rejected=s8(r.eax)>10;}
 if(rejected){m.at(0x6c38e4);m.word('eax',logical(m,0,16));m.at(0x6c38e7);const target=m.pop();r.esp=u(r.esp+4);return target;}
 m.at(0x6c38cf);r.edx=u(s8(m.read(r.edx+0x27,1)));if(r.edx>1)throw new RangeError('unsupported keeper side');
 m.at(0x6c38d3);r.eax=u(s8(r.eax));m.at(0x6c38d6);r.ecx=m.read(r.ecx+4*r.edx+0x8ebc,4);
 m.at(0x6c38dd);m.word('eax',m.read(r.ecx+2*r.eax,2));m.at(0x6c38e1);const target=m.pop();r.esp=u(r.esp+4);return target;
}

export function runKeeperBody38(m:GridMachine31){
 const r=m.r,f=new KeeperFloat38(m),random=(site:number)=>call(m,site,0x90cfc0,1,()=>runKeeperRandom38(m));
 const ftol=(site:number)=>call(m,site,0x945640,0,()=>conversion(m,f));
 if(m.memory.read(r.esp+16,1)!==0x33)throw new RangeError('keeper action33 only');
 m.at(0x700420);r.eax=m.read(r.esp+24,4);m.at(0x700424);r.esp=integer(m,r.esp,8,true);
 m.at(0x700427);m.push(r.ebx);m.at(0x700428);m.push(r.ebp);m.at(0x700429);r.ebp=m.read(r.esp+0x24,4);
 m.at(0x70042d);m.push(r.esi);m.at(0x70042e);m.push(r.edi);m.at(0x70042f);r.esi=r.ecx;
 m.at(0x700431);m.write(r.ebp,1,0);m.at(0x700435);m.write(r.eax,1,0);m.at(0x700438);m.byte('eax',m.read(r.esp+0x24,1));
 m.at(0x70043c);logical(m,r.eax,8);m.at(0x70043e);
 if(r.eax&255){m.at(0x700440);m.word('ecx',m.read(r.esi+0x16a,2));m.at(0x700447);m.write(r.esp+0x2c,2,r.ecx);m.at(0x70044c);}
 else{m.at(0x70044e);m.word('edx',m.read(r.esi+0x168,2));m.at(0x700455);m.write(r.esp+0x2c,2,r.edx);}
 m.at(0x70045a);r.eax=m.read(r.esp+0x2c,4);m.at(0x70045e);r.ecx=m.read(r.esi+0x19e,4);
 m.at(0x700464);r.edx=u(s8(m.read(r.ecx+0x8ea8,1)));m.at(0x70046b);r.edi=u(r.eax+220);
 m.at(0x700471);r.eax=u(s8(m.read(r.esi+0x103,1)));m.at(0x700478);r.eax=integer(m,r.eax,r.edx,true);
 m.at(0x70047a);r.edx=r.eax&0x80000000?0xffffffff:0;m.at(0x70047b);r.eax=logical(m,r.eax^r.edx);m.at(0x70047d);r.eax=integer(m,r.eax,r.edx,true);
 m.at(0x70047f);r.edx=u(s8(m.read(r.ecx+0x8ea7,1)));m.at(0x700486);r.eax=u(s8(r.eax));m.at(0x700489);r.ebx=u(r.eax*9);
 m.at(0x70048c);r.eax=u(s8(m.read(r.esi+0x102,1)));m.at(0x700493);r.eax=integer(m,r.eax,r.edx,true);
 m.at(0x700495);r.edx=r.eax&0x80000000?0xffffffff:0;m.at(0x700496);r.eax=logical(m,r.eax^r.edx);m.at(0x700498);r.eax=integer(m,r.eax,r.edx,true);
 m.at(0x70049a);r.eax=u(s8(r.eax));m.at(0x70049d);r.ebx=integer(m,r.ebx,r.eax);
 if(r.ebx>=108)throw new RangeError('keeper grid index outside 108 entries');
 m.at(0x70049f);m.byte('eax',m.read(r.esi+0x2b,1));m.at(0x7004a2);integer(m,r.eax,1,true,8);
 m.at(0x7004a4);f.push(f.load32(0xa15e44+4*r.ebx));m.at(0x7004ab);f.store32(r.esp+0x24);m.at(0x7004af);
 let rejected=s8(r.eax)>1;
 if(!rejected){m.at(0x7004b5);logical(m,r.ecx);m.at(0x7004b7);rejected=r.ecx===0;}
 if(!rejected){
  m.at(0x7004bd);m.push(r.esi);call(m,0x7004be,0x6c38c0,1,()=>tactical(m));
  m.at(0x7004c3);integer(m,r.eax,1,true,16);m.at(0x7004c7);rejected=(r.eax&65535)!==1;
 }
 if(rejected){
  m.at(0x700b92);r.edi=m.pop();m.at(0x700b93);r.esi=m.pop();m.at(0x700b94);r.ebp=m.pop();
  m.at(0x700b95);m.word('eax',logical(m,0,16));m.at(0x700b98);r.ebx=m.pop();m.at(0x700b99);r.esp=integer(m,r.esp,8);
  m.at(0x700b9c);const target=m.pop();r.esp=u(r.esp+24);return target;
 }
 m.at(0x7004cd);m.byte('ebx',m.read(r.esp+0x28,1));m.at(0x7004d1);integer(m,r.ebx,0x33,true,8);m.at(0x7004d4);
 if((r.ebx&255)!==0x33)throw new RangeError('keeper action33 route required');
 m.at(0x7004d6);r.edi=u(s16(r.edi));m.at(0x7004d9);m.push(r.edi);random(0x7004da);
 m.at(0x7004df);r.edi=integer(m,r.edi,r.eax,true);m.at(0x7004e1);m.push(r.edi);random(0x7004e2);
 m.at(0x7004e7);r.esp=integer(m,r.esp,8);m.at(0x7004ea);r.edi=r.eax;m.at(0x7004ec);
 m.at(0x700a4f);f.push(f.load32(r.esi+0xd1));m.at(0x700a55);r.eax=logical(m,0);m.at(0x700a57);r.edx=m.read(r.esi+0x19e,4);
 m.at(0x700a5d);m.byte('eax',m.read(r.esi+0xf,1));m.at(0x700a60);f.add(f.get());m.at(0x700a62);m.write(r.esp+0x28,4,r.eax);
 m.at(0x700a66);m.byte('ebx',m.read(r.edx+0x8eaa,1));m.at(0x700a6c);f.push(val(m.read(r.esp+0x28,4)|0));m.at(0x700a70);f.pair();
 m.at(0x700a72);f.add(f.load64(0x9688b0));ftol(0x700a78);m.at(0x700a7d);m.push(r.eax);random(0x700a7e);
 m.at(0x700a83);f.push(f.load32(r.esp+0x28));m.at(0x700a87);const distance=f.get();f.set(f.combine(f.load64(0x968950),{value:{...distance.value,coefficient:-distance.value.coefficient},negativeZero:!negative(distance)}));
 m.at(0x700a8d);r.ecx=u(s8(r.ebx));m.at(0x700a90);m.write(r.esp+0x28,4,r.ecx);m.at(0x700a94);r.ebp=r.eax;
 m.at(0x700a96);f.push(val(m.read(r.esp+0x28,4)|0));m.at(0x700a9a);f.pair(true);m.at(0x700a9c);f.mul(f.load64(0x9688b0));
 ftol(0x700aa2);m.at(0x700aa7);m.push(r.eax);random(0x700aa8);m.at(0x700aad);r.esp=integer(m,r.esp,8);
 m.at(0x700ab0);integer(m,r.ebp,r.eax,true);m.at(0x700ab2);
 if((r.ebp|0)>(r.eax|0)){
  m.at(0x700ab4);r.ecx=u(s16(m.read(r.esp+0x2c,2)));m.at(0x700ab9);r.eax=0x2aaaaaab;m.at(0x700abe);multiply(m,r.ecx);
  m.at(0x700ac0);r.eax=r.edx;m.at(0x700ac2);shift31(m);m.at(0x700ac5);r.edx=integer(m,r.edx,r.eax);m.at(0x700ac7);r.ecx=u(s16(r.edi));
  m.at(0x700aca);m.write(r.esp+0x24,4,r.edx);m.at(0x700ace);f.push(val(m.read(r.esp+0x24,4)|0));m.at(0x700ad2);m.write(r.esp+0x24,4,r.ecx);
  m.at(0x700ad6);f.push(val(m.read(r.esp+0x24,4)|0));m.at(0x700ada);
 }else{
  m.at(0x700adf);r.edx=m.read(r.esp+0x30,4);m.at(0x700ae3);m.write(r.edx,1,1);m.at(0x700ae6);r.eax=u(s16(m.read(r.esi+0x3b,2)));
  m.at(0x700aea);m.push(r.eax);random(0x700aeb);m.at(0x700af0);m.push(285);m.at(0x700af5);r.esi=r.eax;random(0x700af7);
  m.at(0x700afc);r.esp=integer(m,r.esp,8);m.at(0x700aff);integer(m,r.esi,r.eax,true);m.at(0x700b01);
  if((r.esi|0)>(r.eax|0)){
   m.at(0x700b03);r.ecx=u(s16(r.edi));m.at(0x700b06);m.write(r.esp+0x24,4,r.ecx);m.at(0x700b0a);f.push(val(m.read(r.esp+0x24,4)|0));
   m.at(0x700b0e);f.store64(r.esp+0x10);m.at(0x700b12);f.mul(f.load64(0x968e40));ftol(0x700b18);m.at(0x700b1d);m.push(r.eax);random(0x700b1e);
   m.at(0x700b23);m.write(r.esp+0x28,4,r.eax);m.at(0x700b27);r.esp=integer(m,r.esp,4);m.at(0x700b2a);f.push(val(m.read(r.esp+0x24,4)|0));
   m.at(0x700b2e);f.push(f.load64(r.esp+0x10));m.at(0x700b32);f.mul(f.load64(0x968e80));m.at(0x700b38);f.pair();ftol(0x700b3a);m.at(0x700b3f);
  }else{m.at(0x700b41);r.edx=u(s16(r.edi));m.at(0x700b44);m.push(r.edx);random(0x700b45);m.at(0x700b4a);r.esp=integer(m,r.esp,4);}
  m.at(0x700b4d);r.ecx=u(s16(m.read(r.esp+0x2c,2)));m.at(0x700b52);r.esi=r.eax;m.at(0x700b54);r.eax=0x2aaaaaab;m.at(0x700b59);multiply(m,r.ecx);
  m.at(0x700b5b);r.eax=r.edx;m.at(0x700b5d);shift31(m);m.at(0x700b60);r.edx=integer(m,r.edx,r.eax);m.at(0x700b62);r.ecx=u(s16(r.esi));
  m.at(0x700b65);m.write(r.esp+0x24,4,r.edx);m.at(0x700b69);f.push(val(m.read(r.esp+0x24,4)|0));m.at(0x700b6d);m.write(r.esp+0x24,4,r.ecx);
  m.at(0x700b71);f.push(val(m.read(r.esp+0x24,4)|0));
 }
 m.at(0x700b75);f.mul(f.load64(0x96d698));m.at(0x700b7b);f.pair();m.at(0x700b7d);f.add(f.load64(0x968ea8));ftol(0x700b83);
 m.at(0x700b88);r.edi=m.pop();m.at(0x700b89);r.esi=m.pop();m.at(0x700b8a);r.ebp=m.pop();m.at(0x700b8b);r.ebx=m.pop();
 m.at(0x700b8c);r.esp=integer(m,r.esp,8);m.at(0x700b8f);const target=m.pop();r.esp=u(r.esp+24);return target;
}

export function runAction33KeeperSuffix38(m:GridMachine31){
 const r=m.r;call(m,0x702416,0x700420,6,()=>runKeeperBody38(m));
 m.at(0x70241b);m.byte('ecx',m.read(r.esp+0x14,1));m.at(0x70241f);m.write(r.esp+0x38,4,r.eax);
 m.at(0x702423);logical(m,r.ecx,8);m.at(0x702425);
 if(!(r.ecx&255)){
  m.at(0x702427);integer(m,r.eax,375,true,16);m.at(0x70242b);
  if(s16(r.eax)>375){m.at(0x70242d);m.write(r.esp+0x1a,1,1);m.at(0x702432);}
  else{m.at(0x702434);integer(m,r.eax,260,true,16);m.at(0x702438);if(s16(r.eax)>260){m.at(0x70243a);m.write(r.esp+0x19,1,1);}}
 }
 m.at(0x70243f);r.ecx=m.read(r.esi+0x19e,4);m.at(0x702445);let bypass=m.read(r.ecx+0x8ea9,1);integer(m,bypass,4,true,8);m.at(0x70244c);
 if(bypass!==4){
  m.at(0x70244e);bypass=m.read(r.esp+0x6a4,1);integer(m,bypass,4,true,8);m.at(0x702456);
  if(bypass!==4){m.at(0x702458);m.byte('eax',m.read(r.esp+0x698,1));m.at(0x70245f);integer(m,r.eax,0x33,true,8);m.at(0x702461);if((r.eax&255)!==0x33)throw new RangeError('caller action33 bypass required');}
 }
 m.at(0x702498);r.edi=logical(m,0);m.at(0x70249a);m.word('ecx',s8(m.read(r.esp+0x30,1)));m.at(0x7024a0);m.push(0);m.at(0x7024a2);m.push(r.ecx);
 m.at(0x7024a3);r.ecx=m.read(r.esi+0x19e,4);m.at(0x7024a9);m.push(r.edi);m.at(0x7024aa);m.push(109);m.at(0x7024ac);m.push(r.esi);m.at(0x7024ad);m.write(r.esp+0x8c,4,r.edi);
 return 0x7024b4;
}
export function runAction33KeeperPrefix38(m:GridMachine31){
 const stop=runAction33VariantPrefix37(m);if(stop===0x702332)return stop;
 if(stop!==0x702416)throw new RangeError('R37-B keeper boundary required');return runAction33KeeperSuffix38(m);
}

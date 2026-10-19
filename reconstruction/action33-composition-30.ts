/** Semantic composition of 007022fd..007024b4, supplied with its original checkpoint.
 * Earlier resolver work, machine stack accesses and 006cfe10 are outside this API.
 */
import {selectKeeperSlot29,type KeeperMemory29} from './keeper-selector-29.ts';
import {nextBounded,type RandomState} from './bounded-random.ts';
import {penaltyKeeperBase} from './penalty-resolution.ts';
import {adjustKeeperResponse} from './keeper-response.ts';
import {tacticalPositionWord} from './penalty-keeper-entry.ts';

export type CompositionCall30={site:string;target:string;receiver:number|null;args:number[]};
export type CompositionDraw30={site:string;bound:number;value:number;initial:RandomState;final:RandomState};
export type CompositionAccess30=[string,string,number,number];
export type CompositionInput30={match:number;shooter:number;action:number;mode:number;
  zeroLocalByte:number;marker260:number;marker375:number;precisionBits:53|64};
const hex=(a:number)=>a.toString(16).padStart(8,'0');
const signed16=(v:number)=>(v<<16)>>16;
const signed8=(v:number)=>(v<<24)>>24;
function uint(v:number,max=0xffffffff):void{
  if(!Number.isInteger(v)||v<0||v>max)throw new RangeError('unsupported unsigned value');
}

type ObservedDraw={initial:RandomState;final:RandomState;word:number|null};
/** Observe actual shared-helper executions, without replacing their RNG calls.
 * nextBounded validates table.length once before any state access, including R(0).
 * Its second length access follows cursor mutation; numeric table access ends R(n).
 * Bounds are supplied by the base expression or postlude's own drawBounds result.
 */
class RandomObserver {
  readonly state:RandomState;
  readonly table:readonly number[];
  private active:{initial:RandomState;advanced:boolean}|null=null;
  private rows:ObservedDraw[]=[];
  private raw:RandomState;
  constructor(raw:RandomState,table:readonly number[]){
    this.raw=raw;
    this.state=new Proxy(raw,{set:(target,key,value)=>{
      if(key==='cursorIndex'&&this.active)this.active.advanced=true;
      Reflect.set(target,key,value);return true;
    }});
    this.table=new Proxy(table,{get:(target,key)=>{
      if(key==='length'){
        if(this.active&&!this.active.advanced)this.finish(null);
        if(!this.active)this.active={initial:{...this.raw},advanced:false};
      }
      const value=Reflect.get(target,key);
      if(typeof key==='string'&&/^\d+$/.test(key))this.finish(value);
      return value;
    }});
  }
  private finish(word:number|null):void{
    if(!this.active)throw new Error('unmatched shared RNG table access');
    this.rows.push({initial:this.active.initial,final:{...this.raw},word});this.active=null;
  }
  observe<T>(run:()=>T):{value:T;rows:ObservedDraw[]}{
    if(this.active||this.rows.length)throw new Error('nested RNG observation');
    const value=run();if(this.active)this.finish(null);
    const rows=this.rows;this.rows=[];return {value,rows};
  }
}
function drawRecord(site:string,bound:number,row:ObservedDraw):CompositionDraw30{
  if(!row)throw new Error('missing observed RNG invocation');
  let value=0;
  if(bound===0){
    if(row.word!==null||JSON.stringify(row.initial)!==JSON.stringify(row.final))throw new Error('R(0) advanced');
  }else{
    if(row.word===null)throw new Error('nonzero draw did not read table');
    const remainder=((row.final.offset+row.word)|0)%bound;
    value=(bound<0?-remainder:remainder)|0;
  }
  return {site,bound,value,initial:row.initial,final:row.final};
}

export function composeAction33Segment30(input:CompositionInput30,memory:KeeperMemory29,
  state:RandomState,table:readonly number[],grid:readonly number[]){
  uint(input.match);uint(input.shooter);
  if(input.match>0xffff0000||input.shooter>0xfffffe41)throw new RangeError('nonwrapping mapped records required');
  if(input.action!==0x33||input.mode!==3||input.zeroLocalByte!==0||input.marker260!==0||input.marker375!==0)
    throw new RangeError('requires the admitted action33/mode3 caller checkpoint');
  if(input.precisionBits!==53&&input.precisionBits!==64)throw new RangeError('explicit x87 precision required');
  uint(state.cursorIndex,50999);uint(state.offset,65535);uint(state.crtState);
  if(table.length!==51000||table.some(v=>!Number.isInteger(v)||v<0||v>32767))throw new RangeError('synthetic small RNG table required');
  const calls:CompositionCall30[]=[],draws:CompositionDraw30[]=[],selectorMemory:CompositionAccess30[]=[];
  const call=(site:string,target:string,receiver:number|null,args:number[])=>calls.push({site,target,receiver,args});
  const observed:KeeperMemory29={
    read8(a){const v=memory.read8(a);selectorMemory.push(['read',hex(a),1,v]);return v;},
    read16(a){const v=memory.read16(a);selectorMemory.push(['read',hex(a),2,v]);return v;},
    read32(a){const v=memory.read32(a);selectorMemory.push(['read',hex(a),4,v]);return v;},
    write8(a,v){memory.write8(a,v);selectorMemory.push(['write',hex(a),1,v&255]);},
    write32(a,v){memory.write32(a,v);selectorMemory.push(['write',hex(a),4,v>>>0]);}
  };
  const side=memory.read8(input.shooter+0x27);
  if(side>1||memory.read32(input.shooter+0x19e)!==input.match)throw new RangeError('unsupported shooter context');
  const selector=side===0?1:0;
  call('0070230c','006ce110',input.match,[selector]);
  const keeper=selectKeeperSlot29(input.match,selector,observed);
  if(keeper===0)throw new RangeError('unsupported null-keeper diagnostic at 00702332');
  const random=new RandomObserver(state,table);
  const append=(row:CompositionDraw30)=>{draws.push(row);call(row.site,'0090cfc0',null,[row.bound]);};
  const variantRun=random.observe(()=>nextBounded(2,random.state,random.table));
  if(variantRun.rows.length!==1)throw new Error('variant RNG invocation count');
  const variantDraw=drawRecord('007023e3',2,variantRun.rows[0]);
  if(variantDraw.value!==variantRun.value)throw new Error('variant RNG observation mismatch');
  append(variantDraw);const variant=variantRun.value&255;
  call('00702416','00700420',keeper,[memory.read8(input.shooter+0x102),memory.read8(input.shooter+0x103),variant,0x33]);
  if(memory.read32(keeper+0x19e)!==input.match)throw new RangeError('unsupported selected keeper context');
  const keeperSide=memory.read8(keeper+0x27),index=memory.read8(keeper+0x19);
  const positions=[0,1].map(s=>{
    const pointer=memory.read32(input.match+0x8ebc+s*4);
    return Array.from({length:11},(_,i)=>memory.read16(pointer+i*2));
  });
  const activity=memory.read8(keeper+0x2b);
  let position=0;
  if(signed8(activity)<=1){
    call('007004be','006c38c0',input.match,[keeper]);
    position=tacticalPositionWord(index,keeperSide,positions);
  }
  let response=0,fallbackFlag=0,eligible=false,path='rejected';
  const keeperX=memory.read8(keeper+0x102),keeperY=memory.read8(keeper+0x103);
  const matchX=memory.read8(input.match+0x8ea7),matchY=memory.read8(input.match+0x8ea8);
  for(const v of [keeperX,matchX])uint(v,8);for(const v of [keeperY,matchY])uint(v,11);
  if(grid.length!==108||grid.some(v=>!Number.isFinite(v)||v<0||v>20||Math.fround(v)!==v))throw new RangeError('bounded float32 grid required');
  const gridIndex=Math.abs(keeperY-matchY)*9+Math.abs(keeperX-matchX);
  if(signed8(activity)<=1&&position===1){
    eligible=true;
    const ratingRaw=memory.read16(keeper+(variant===0?0x168:0x16a));
    const ratingBound=signed16((signed16(ratingRaw)+220)&65535);
    const base=random.observe(()=>penaltyKeeperBase(ratingRaw,random.state,random.table));
    if(base.rows.length!==2)throw new Error('base RNG invocation count');
    const first=drawRecord('007004da',ratingBound,base.rows[0]);append(first);
    const second=drawRecord('007004e2',ratingBound-first.value,base.rows[1]);
    if(second.value!==base.value)throw new Error('base RNG observation mismatch');append(second);
    const bits=memory.read32(keeper+0xd1),view=new DataView(new ArrayBuffer(4));view.setUint32(0,bits,true);
    const post=random.observe(()=>adjustKeeperResponse({ratingRaw,fallbackRatingRaw:memory.read16(keeper+0x3b),
      counterRaw:memory.read8(keeper+0xf),adjustmentFloat:view.getFloat32(0,true),distanceFloat:grid[gridIndex],
      matchByteRaw:memory.read8(input.match+0x8eaa),precisionBits:input.precisionBits},base.value&65535,random.state,random.table));
    const result=post.value;
    const sites=['00700a7e','00700aa8',...(result.fallback?['00700aeb','00700af7',result.path==='weighted'?'00700b1e':'00700b45']:[])];
    if(post.rows.length!==result.drawBounds.length||sites.length!==post.rows.length)throw new Error('postlude RNG invocation count');
    const postDraws=post.rows.map((row,i)=>drawRecord(sites[i],result.drawBounds[i],row));
    if(result.fallback!==(postDraws[0].value<=postDraws[1].value))throw new Error('fallback observation mismatch');
    if(result.fallback&&((postDraws[2].value>postDraws[3].value)!==(result.path==='weighted')))
      throw new Error('redraw observation mismatch');
    postDraws.forEach(append);
    response=result.response;fallbackFlag=Number(result.fallback);path=result.path;
  }
  const responseWord=response&65535,signed=signed16(responseWord);
  const marker375=Number(!fallbackFlag&&signed>375),marker260=Number(!fallbackFlag&&signed<=375&&signed>260);
  return {keeper,variant,responseWord,positionFlag:0,fallbackFlag,marker260,marker375,eligible,path,gridIndex,
    outgoingArgumentDwords:[input.shooter,0x6d,0,input.match&0xffff0000,0].map(v=>v>>>0),
    selectorMemory,calls,draws};
}

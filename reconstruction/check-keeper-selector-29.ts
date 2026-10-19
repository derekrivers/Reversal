import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {selectKeeperSlot29,type KeeperMemory29} from './keeper-selector-29.ts';

const MATCH=0x200000,TABLE=0x300000,BASES=[0x4796,0x6a6e],CACHES=[0xf59e,0xf5a2];
const hex=(n:number)=>n.toString(16).padStart(8,'0');
const sha=(v:Uint8Array)=>createHash('sha256').update(v).digest('hex');

class Memory implements KeeperMemory29 {
  match=new Uint8Array(0x10000);
  table=new Uint8Array(0x1000);
  effects:(string|number)[][]=[];
  private place(address:number,size:number):[Uint8Array,number]{
    if(address>=MATCH && address+size<=MATCH+this.match.length)return [this.match,address-MATCH];
    if(address>=TABLE && address+size<=TABLE+this.table.length)return [this.table,address-TABLE];
    throw new RangeError(`unmapped synthetic read/write ${hex(address)}`);
  }
  private value(address:number,size:number):number{
    const [bytes,offset]=this.place(address,size);
    let result=0;for(let i=0;i<size;i++)result|=bytes[offset+i]<<(i*8);
    return result>>>0;
  }
  private put(address:number,size:number,value:number):void{
    const [bytes,offset]=this.place(address,size);
    for(let i=0;i<size;i++)bytes[offset+i]=(value>>>(i*8))&255;
  }
  read8(a:number):number{this.effects.push(['read',hex(a),1]);return this.value(a,1);}
  read16(a:number):number{this.effects.push(['read',hex(a),2]);return this.value(a,2);}
  read32(a:number):number{this.effects.push(['read',hex(a),4]);return this.value(a,4);}
  write8(a:number,v:number):void{this.effects.push(['write',hex(a),1,v&255]);this.put(a,1,v);}
  write32(a:number,v:number):void{this.effects.push(['write',hex(a),4,v>>>0]);this.put(a,4,v);}
  seed(modes:number[]):void{
    for(let side=0;side<2;side++){
      const mode=modes[side],base=BASES[side];
      for(let i=0;i<20;i++){
        const slot=base+i*0x1be;
        this.match[slot+0x19]=this.match[slot+0x1a]=255;
        this.match[slot+0x27]=side;
      }
      this.put(MATCH+0x8ebc+4*side,4,TABLE+side*0x100);
      const slot=(i:number)=>base+i*0x1be;
      const status=(i:number,v:number)=>{this.match[slot(i)+0x19]=v&255;};
      const tact=(index:number,value:number,which=0)=>this.put(TABLE+side*0x100+which*0x40+index*2,2,value);
      if(mode===0){status(2,2);this.put(MATCH+CACHES[side],4,MATCH+slot(2));}
      else if(mode===1){status(3,1);this.put(MATCH+CACHES[side],4,MATCH+slot(2));tact(1,1);}
      else if(mode===2){status(2,3);status(5,1);tact(1,1);}
      else if(mode===3)status(5,2);
      else if(mode===4||mode===5){
        status(5,2);status(12,0xfe);this.match[slot(12)+0x1a]=3;this.match[slot(12)+0x20]=255;
        this.match[slot(12)+0x27]=side+2;
        this.put(MATCH+0x8ebc+4*(side+2),4,TABLE+side*0x100+0x40);
        tact(3,1,1);if(mode===4)tact(3,1);
      }else if(mode===6){}
      else if(mode===7){status(1,11);this.put(MATCH+CACHES[side],4,MATCH+slot(1));}
      else if(mode===8){status(1,0);status(3,1);tact(0,1);tact(1,1);}
      else if(mode===9)this.put(MATCH+CACHES[side],4,MATCH+slot(2));
      else if(mode===10)status(5,11);
      else if([11,12,13,14].includes(mode)){
        status(5,2);status(12,mode===13?0xfd:0xfe);
        this.match[slot(12)+0x1a]=mode===11?11:3;
        this.match[slot(12)+0x20]=mode===14?0:255;
        this.match[slot(12)+0x27]=side+2;
        this.put(MATCH+0x8ebc+4*(side+2),4,TABLE+side*0x100+0x40);
        if(mode!==12)tact(3,1,1);
      }
      else throw new RangeError('unsupported synthetic mode');
    }
  }
}

const oracleFile=process.argv[2]??'evidence/keeper-selector-29-oracle.json.gz';
assert.ok(process.argv.length<=3,'expected at most one oracle path');
const oracle=JSON.parse(gunzipSync(readFileSync(oracleFile)).toString());
const sites=JSON.parse(readFileSync('evidence/keeper-selector-29-sites.json','utf8'));
assert.equal(oracle.specimen_sha256,sites.specimen_sha256);
assert.equal(oracle.body_sha256,sites.body_sha256);
assert.equal(oracle.function_cases,315);
assert.ok(Array.isArray(oracle.cases),'case array required');
assert.equal(oracle.cases.length,315,'all retained cases must be compared');
assert.equal(oracle.covered_instruction_starts.length,sites.instruction_count);
assert.deepEqual(oracle.covered_local_edges.map((row:string[])=>row.join(':')).sort(),
  sites.edges.map((row:string[])=>row.join(':')).sort());
let effects=0;
for(let index=0;index<oracle.cases.length;index++){
  const row=oracle.cases[index];
  const expected=index<300
    ? [Math.floor(index/30),Math.floor(index%30/3),index%3]
    : [10+Math.floor((index-300)/3),10+Math.floor((index-300)/3),(index-300)%3];
  assert.deepEqual(row.input,expected,`case schedule ${index}`);
  const [left,right,selector]=row.input as number[];
  const memory=new Memory();memory.seed([left,right]);
  const result=selectKeeperSlot29(MATCH,selector,memory);
  assert.equal(result,row.final.eax,`return ${row.input}`);
  assert.deepEqual(memory.effects,row.effects,`ordered effects ${row.input}`);
  const stack=new Uint8Array(0x1000);
  const view=new DataView(stack.buffer);
  view.setUint32(0x800,0x700000,true);view.setUint32(0x804,selector,true);view.setUint32(0x808,0xc0dec0de,true);
  view.setUint32(0x7fc,row.initial.ebx,true);view.setUint32(0x7f8,row.initial.ebp,true);
  view.setUint32(0x7f4,row.initial.esi,true);view.setUint32(0x7f0,row.initial.edi,true);
  assert.deepEqual([sha(memory.match),sha(memory.table),sha(stack)],row.memory_sha256,`full admitted memory ${row.input}`);
  assert.equal(row.final.ecx,MATCH);assert.equal(row.final.esp,0x100808);
  for(const reg of ['ebx','ebp','esi','edi'])assert.equal(row.final[reg],row.initial[reg],`preserved ${reg}`);
  effects+=memory.effects.length;
}
assert.throws(()=>selectKeeperSlot29(MATCH,-1,new Memory()),RangeError);
assert.throws(()=>selectKeeperSlot29(MATCH,256,new Memory()),RangeError);
console.log(`R29-A keeper selector: ${oracle.function_cases} original-entry cases, ${oracle.executed_instruction_steps} x86 steps, ${effects} ordered effects; full admitted memory and ABI verified.`);

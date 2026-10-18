import { readFileSync,writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { resolvePenaltyKeeper,tacticalPositionWord } from './penalty-keeper-entry.ts';
const [oraclePath,tablePath,output]=process.argv.slice(2);
if(!output)throw new Error('Usage: node check-penalty-keeper-entry.ts oracle.json synthetic-table.bin result.json');
const oracle=JSON.parse(readFileSync(oraclePath,'utf8')),bytes=readFileSync(tablePath);
assert.equal(createHash('sha256').update(bytes).digest('hex'),oracle.synthetic_table_sha256);
const gridBytes=Buffer.alloc(108*4);oracle.grid.values.forEach((v: number,i: number)=>gridBytes.writeFloatLE(v,i*4));
assert.equal(createHash('sha256').update(gridBytes).digest('hex'),oracle.grid.sha256);
const table=Array.from({length:bytes.length/4},(_,i)=>bytes.readUInt32LE(i*4));
let cases=0,eligible=0,rejected=0;const indices=new Set<number>(),activities=new Set<number>(),slots=new Set<number>();
for(const test of oracle.cases){
 const state={...test.initial};const actual=resolvePenaltyKeeper(test.input,test.positions,oracle.grid.values,state,table);
 assert.deepEqual(actual,test.result,`entry case${cases}`);assert.deepEqual(state,test.final,`entry RNG case${cases}`);
 if(actual.eligible)eligible++;else{rejected++;assert.deepEqual(state,test.initial,'Rejected entry must not consume RNG');}
 indices.add(actual.gridIndex);activities.add(test.input.activityRaw);slots.add(test.input.tacticalSlotRaw);cases++;
}
assert.equal(cases,oracle.coverage.cases);assert.equal(eligible,oracle.coverage.eligible);assert.equal(rejected,oracle.coverage.rejected);
assert.equal(indices.size,108);assert.equal(activities.size,256);assert.equal(slots.size,256);
for(const invalid of [{keeperX:9},{matchY:12},{side:2},{activityRaw:256},{tacticalSlotRaw:-1},{variantRaw:256},{adjustmentFloat:NaN},{precisionBits:24}]){
 const test=oracle.cases[0],state={...test.initial};
 assert.throws(()=>resolvePenaltyKeeper({...test.input,...invalid},test.positions,oracle.grid.values,state,table),RangeError);
 assert.deepEqual(state,test.initial);
}
assert.throws(()=>tacticalPositionWord(0,0,[[1],[1]]),RangeError);
const result={status:'passed',sha256:oracle.sha256,cases,eligible,rejected,grid_indices:indices.size,comparisons:'signed16 response, output flags, eligibility and final RNG state; original oracle also verifies ABI and unchanged context/slot',limitations:oracle.limitations};
writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));

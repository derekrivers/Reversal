import { readFileSync,writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { preparePenaltyAttempt } from './penalty-preparation.ts';
const [oraclePath,tablePath,output]=process.argv.slice(2);
if(!output)throw new Error('Usage: node check-penalty-preparation.ts oracle.json synthetic-table.bin result.json');
const oracle=JSON.parse(readFileSync(oraclePath,'utf8'));const bytes=readFileSync(tablePath);
assert.equal(createHash('sha256').update(bytes).digest('hex'),oracle.synthetic_table_sha256);
const table=Array.from({length:bytes.length/4},(_,i)=>bytes.readUInt32LE(i*4));
let count=0;const pressures=new Set<string>();
for(const test of oracle.cases){const state={...test.initial};const actual=preparePenaltyAttempt(test.input,state,table);
 for(const key of ['errorBudget','baseQuality','quality','eventCode'] as const)assert.equal(actual[key],test.result[key],`case ${count}: ${key}`);
 assert.deepEqual(state,test.final,`case ${count}: final RNG state`);pressures.add(actual.pressure);count++;
}
assert.equal(count,oracle.coverage.cases);assert.equal(pressures.size,3);
for(const invalid of [{shotRatingRaw:13108},{remaining:6},{oneOnOnesRaw:256},{shotRatingRaw:65536}]){
 const state={...oracle.cases[0].initial};const before={...state};
 assert.throws(()=>preparePenaltyAttempt({...oracle.cases[0].input,...invalid},state,table),RangeError);
 assert.deepEqual(state,before,'Unsupported inputs must be rejected before consuming RNG state');
}
const result={status:'passed',sha256:oracle.sha256,cases:count,comparisons:'preparation outputs and complete exposed RNG state',oracle:oracle.oracle,limitations:oracle.limitations};
writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));

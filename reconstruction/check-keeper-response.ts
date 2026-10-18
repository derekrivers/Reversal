import { readFileSync,writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { adjustKeeperResponse,penaltyKeeperResponse } from './keeper-response.ts';
const [oraclePath,tablePath,output]=process.argv.slice(2);
if (!output) throw new Error('Usage: node check-keeper-response.ts oracle.json synthetic-table.bin result.json');
const oracle=JSON.parse(readFileSync(oraclePath,'utf8')),bytes=readFileSync(tablePath);
assert.equal(createHash('sha256').update(bytes).digest('hex'),oracle.synthetic_table_sha256);
const table=Array.from({length:bytes.length/4},(_,i)=>bytes.readUInt32LE(i*4));
const paths: Record<string,number>={};let count=0;
for (const test of oracle.cases) {
  const state={...test.initial};
  const {drawBounds,...result}=test.mode==='postlude' ? adjustKeeperResponse(test.input,test.baseRaw,state,table) : penaltyKeeperResponse(test.input,state,table);
  assert.deepEqual(result,test.result,`keeper result case${count}`);
  assert.deepEqual(drawBounds,test.postludeBounds,`RNG call order/bounds case${count}`);
  assert.deepEqual(state,test.final,`final RNG state case${count}`);
  const key=`${test.input.precisionBits}:${test.mode}:${result.path}`;paths[key]=(paths[key]??0)+1;count++;
}
assert.equal(count,oracle.coverage.cases);assert.deepEqual(paths,oracle.coverage.paths);
assert.equal(Object.keys(paths).length,12,'Both precision and entry modes exercise all three paths');
for (const invalid of [{precisionBits:24},{ratingRaw:65536},{fallbackRatingRaw:-1},{counterRaw:256},{matchByteRaw:1.5},{adjustmentFloat:NaN},{adjustmentFloat:101},{distanceFloat:21},{distanceFloat:0.1}]) {
  const state={...oracle.cases[0].initial},before={...state};
  assert.throws(()=>penaltyKeeperResponse({...oracle.cases[0].input,...invalid},state,table),RangeError);
  assert.deepEqual(state,before,'Domain guards must precede RNG changes');
}
const result={status:'passed',sha256:oracle.sha256,cases:count,paths,comparisons:'response, fallback flag, branch, ordered postlude RNG bounds and final RNG state',control_words:oracle.control_words,limitations:oracle.limitations};
writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));

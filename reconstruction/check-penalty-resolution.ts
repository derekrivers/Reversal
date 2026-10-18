import { readFileSync,writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { penaltyKeeperBase,classifyPenaltyShot,penaltyScoringGate } from './penalty-resolution.ts';
const [directory,tablePath,output] = process.argv.slice(2);
if (!output) throw new Error('Usage: node check-penalty-resolution.ts oracle-directory synthetic-table.bin result.json');
const read = (name: string) => JSON.parse(readFileSync(`${directory}/${name}`, 'utf8'));
const oracle = read('oracle.json'), keeper = read('keeper.json'), gate = read('gate.json');
const bytes = readFileSync(tablePath), classification = readFileSync(`${directory}/classification.bin`);
const hash = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
assert.equal(hash(bytes),oracle.synthetic_table_sha256);assert.equal(hash(classification),oracle.classification.sha256);
assert.equal(keeper.sha256,oracle.sha256);assert.equal(gate.sha256,oracle.sha256);
assert.equal(keeper.synthetic_table_sha256,oracle.synthetic_table_sha256);
assert.equal(classification.length,oracle.classification.bytes);assert.equal(classification.length,131072*2);
const table=Array.from({length:bytes.length/4},(_,i)=>bytes.readUInt32LE(i*4));
let index=0;const categories=new Map<number,number>();
for (const variant of [0,1]) for (let raw=0;raw<65536;raw++) {
  const state={...oracle.classification.initial};
  const actual=classifyPenaltyShot(raw,variant,state,table);
  assert.equal(actual,classification[index*2],`classification ${variant}:${raw}`);
  assert.deepEqual(state,oracle.classification.final_states_by_draw_count[classification[index*2+1]],`classification RNG ${variant}:${raw}`);
  categories.set(actual,(categories.get(actual)??0)+1);index++;
}
assert.equal(index,oracle.classification.cases);
assert.deepEqual(Object.fromEntries(categories),oracle.classification.category_counts);
for (const test of keeper.cases) {
  const state={...test.initial};
  assert.equal(penaltyKeeperBase(test.ratingRaw,state,table),test.baseResponse,`keeper ${test.ratingRaw}`);
  assert.deepEqual(state,test.final,`keeper RNG ${test.ratingRaw}`);
}
for (const test of gate.cases) {
  const actual=penaltyScoringGate(test.quality&65535,test.keeperTerm&65535,test.matchStateRaw);
  assert.equal(actual.ratio,test.ratio,'float32 ratio');assert.equal(actual.entersScoringBranch,test.entersScoringBranch);
}
assert.equal(keeper.cases.length,oracle.keeper.cases);assert.equal(gate.cases.length,oracle.gate.cases);
for (const invalid of [-1,65536,0.5,NaN]) {
  const state={...oracle.classification.initial};const before={...state};
  assert.throws(()=>penaltyKeeperBase(invalid,state,table),RangeError);
  assert.throws(()=>classifyPenaltyShot(invalid,0,state,table),RangeError);assert.deepEqual(state,before);
  assert.throws(()=>penaltyScoringGate(invalid,0,0),RangeError);
}
assert.throws(()=>classifyPenaltyShot(120,256,{...oracle.classification.initial},table),RangeError);
assert.throws(()=>penaltyScoringGate(0,0,256),RangeError);
const result={status:'passed',sha256:oracle.sha256,classification_cases:index,keeper_cases:keeper.cases.length,gate_cases:gate.cases.length,
  comparisons:'category, exposed RNG state, keeper base draw, float32 ratio and branch destination',limitations:oracle.limitations};
writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));

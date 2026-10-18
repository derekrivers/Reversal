import { readFileSync,writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';
import { eventPriority,stopAfterGoalRule } from './event-rules.ts';
const [directory,output]=process.argv.slice(2);
if(!output)throw new Error('Usage: node check-event-rules.ts oracle-directory result.json');
const meta=JSON.parse(readFileSync(`${directory}/event-rule-oracle.json`,'utf8'));
function verified(name:string,hash:string):Buffer {
  const data=readFileSync(`${directory}/${name}`);
  assert.equal(createHash('sha256').update(data).digest('hex'),hash);return data;
}
const tables=verified('priority-tables.bin',meta.priority.table_sha256);
const priority=verified('priority-oracle.bin',meta.priority.oracle_sha256);
const rules=verified('post-goal-rule-oracle.bin',meta.post_goal.oracle_sha256);
assert.equal(tables.length,meta.priority.profiles*677);
assert.equal(priority.length,meta.priority.profiles*65536);
assert.equal(rules.length,meta.post_goal.fixture_flag_bytes.length*65536);
let priorityCases=0,ruleCases=0;
for(let profile=0;profile<meta.priority.profiles;profile++) {
  const table=tables.subarray(profile*677,(profile+1)*677);
  for(let code=0;code<65536;code++) {
    assert.equal(eventPriority(code,table),priority.readInt8(priorityCases),`profile=${profile} code=${code}`);priorityCases++;
  }
}
for(const flag of meta.post_goal.fixture_flag_bytes)for(let target=0;target<65536;target++) {
  assert.equal(Number(stopAfterGoalRule(target,flag)),rules[ruleCases],`flag=${flag} target=${target}`);ruleCases++;
}
const result={status:'passed',sha256:meta.sha256,priority_cases:priorityCases,post_goal_cases:ruleCases,
  oracle:meta.oracle,node:process.version,limitations:meta.limitations};
writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));

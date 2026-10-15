#!/usr/bin/env node
'use strict';

// B2 structural cost gate for incremental subscription updates.
// A passing cost result alone does not establish accounting correctness.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('./harness');
const { verifyReads } = require('./read-oracle');
const compare = (a, b) => {
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let index = 0; index < Math.min(a.length, b.length); index++) {
      const order = compare(a[index], b[index]);
      if (order) return order;
    }
    return a.length - b.length;
  }
  return a < b ? -1 : a > b ? 1 : 0;
};

const ROOT = path.resolve(__dirname, '../..');
const snapshot = q => q(`RETURN {
  sources:(SELECT * FROM cost_source ORDER BY id),
  points:(SELECT * FROM cost_point ORDER BY id),
  readers:(SELECT * FROM cost_reader ORDER BY id),
  range_readers:(SELECT * FROM cost_range_reader ORDER BY id),
  tenants:(SELECT * FROM rebase_tenant ORDER BY id),
  rebase_read:(SELECT * FROM rebase_read ORDER BY id),
  rebase_read_group:(SELECT * FROM rebase_read_group ORDER BY id),
  rebase_read_frame:(SELECT * FROM rebase_read_frame ORDER BY id),
  rebase_read_lock:(SELECT * FROM rebase_read_lock ORDER BY id),
  cost_stats:(SELECT * FROM cost_stats ORDER BY id)
};`);

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-read-cost-'));
  let server;
  try {
    fs.writeFileSync(path.join(directory, 'schema.surql'), `
DEFINE TABLE cost_source SCHEMAFULL;
DEFINE FIELD amount ON cost_source TYPE decimal;
DEFINE FIELD z_points ON cost_source TYPE object COMMENT '@rebase-tree-root @rebase-tree-key int @rebase-tree-duplicates';
DEFINE FUNCTION OVERWRITE fn::cost::member($row: object) {
  RETURN [fn::tree::ordered_member($row.id,'z_point',$row.source,'z_points',[$row.at],{value:$row.value},{})];
} PERMISSIONS NONE;
DEFINE TABLE cost_point SCHEMAFULL COMMENT '@rebase-members fn::cost::member';
DEFINE FIELD source ON cost_point TYPE record<cost_source> REFERENCE ON DELETE REJECT;
DEFINE FIELD at ON cost_point TYPE int;
DEFINE FIELD value ON cost_point TYPE decimal;
DEFINE FIELD z_point ON cost_point TYPE option<object> COMMENT '@rebase-tree-node @rebase-tree-key int @rebase-tree-owner cost_source.z_points';
DEFINE TABLE cost_reader SCHEMAFULL;
DEFINE FIELD source ON cost_reader TYPE record<cost_source> REFERENCE ON DELETE REJECT;
DEFINE FIELD amount ON cost_reader TYPE decimal
  VALUE fn::record::read_value($this.source,'amount',0dec) COMMENT '@rebase-derived';
DEFINE TABLE cost_range_reader SCHEMAFULL;
DEFINE FIELD source ON cost_range_reader TYPE record<cost_source> REFERENCE ON DELETE REJECT;
DEFINE FIELD lower ON cost_range_reader TYPE int;
DEFINE FIELD upper ON cost_range_reader TYPE int;
DEFINE FIELD active ON cost_range_reader TYPE bool DEFAULT true;
DEFINE FIELD amount ON cost_range_reader TYPE decimal VALUE IF $this.active THEN
  fn::tree::read_value($this.source,'z_points','range',[[$this.lower],[$this.upper]],'measures.value.sum',0dec) ELSE 0dec END
  COMMENT '@rebase-derived';
`);
    const compiled = generateBundle(loadMaterials({ groups: [
      { name:'framework', roots:[path.join(ROOT, 'framework')] },
      { name:'project', roots:[directory] },
    ] }));
    // Instrument actual private-node gets, interval visits, subtree summary
    // pulls, candidate readers, and derived-row refreshes in the same fixture.
    const sql = compiled.bundle
      .replace('DEFINE FUNCTION OVERWRITE fn::tree::get(', 'DEFINE FUNCTION OVERWRITE fn::cost::get(')
      .replace('DEFINE FUNCTION OVERWRITE fn::tree::pull(', 'DEFINE FUNCTION OVERWRITE fn::cost::pull(')
      .replace('DEFINE FUNCTION OVERWRITE fn::reads::stab(', 'DEFINE FUNCTION OVERWRITE fn::cost::stab(')
      .replace('DEFINE FUNCTION OVERWRITE fn::reads::candidates(', 'DEFINE FUNCTION OVERWRITE fn::cost::candidates(')
      .replace('DEFINE FUNCTION OVERWRITE fn::rebase::derive(', 'DEFINE FUNCTION OVERWRITE fn::cost::derive(') + `
DEFINE TABLE cost_stats SCHEMALESS PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::tree::get($link: option<object>) {
  IF $link != NONE AND record::tb($link.rid) = 'rebase_read' {
    UPSERT cost_stats:one SET gets=(gets??0)+1 RETURN NONE;
  };
  RETURN fn::cost::get($link);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::tree::pull($link: object, $detached: option<object>) {
  IF record::tb($link.rid) = 'rebase_read' {
    UPSERT cost_stats:one SET pulls=(pulls??0)+1 RETURN NONE;
  };
  RETURN fn::cost::pull($link,$detached);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::reads::stab($link: option<object>, $key: array) {
  IF $link != NONE { UPSERT cost_stats:one SET visits=(visits??0)+1 RETURN NONE; };
  RETURN fn::cost::stab($link,$key);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::reads::candidates($group: object, $key: array) {
  LET $reads=fn::cost::candidates($group,$key);
  UPSERT cost_stats:one SET candidates=(candidates??0)+array::len($reads),
    candidate_calls=(candidate_calls??0)+1,
    candidate_groups=array::distinct(array::concat(candidate_groups??[],[$group.id])) RETURN NONE;
  RETURN $reads;
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::rebase::derive($row: object, $scope: object) {
  IF record::tb($row.id) IN ['cost_reader','cost_range_reader'] {
    UPSERT cost_stats:one SET refreshes=(refreshes??0)+1 RETURN NONE;
  };
  RETURN fn::cost::derive($row,$scope);
} PERMISSIONS NONE;
`;
    server = await start({ engine:'surrealkv' });
    const q = client(server.url), measurements = [];
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, sql);
    await q('CREATE cost_stats:one SET pulls=0,gets=0,visits=0,candidates=0,candidate_calls=0,candidate_groups=[],refreshes=0;');
    await q('CREATE cost_source:one SET owned_by=rebase_tenant:default,amount=3dec; CREATE cost_source:two SET owned_by=rebase_tenant:default,amount=9dec;');
    const pointSql = [];
    for (let i = 0; i < 64; i++) pointSql.push(`CREATE cost_point:p_one_${String(i).padStart(3,'0')} SET owned_by=rebase_tenant:default,source=cost_source:one,at=${i},value=1dec;`);
    for (let i = 0; i < 32; i++) pointSql.push(`CREATE cost_point:p_two_${String(i).padStart(3,'0')} SET owned_by=rebase_tenant:default,source=cost_source:two,at=${i * 2},value=2dec;`);
    pointSql.push('CREATE cost_point:p_one_100 SET owned_by=rebase_tenant:default,source=cost_source:one,at=100,value=1dec;');
    pointSql.push('CREATE cost_point:p_two_100 SET owned_by=rebase_tenant:default,source=cost_source:two,at=100,value=2dec;');
    await q(pointSql.join('\n'));
    const check = async () => {
      const state = await snapshot(q);
      const expectedReads = state.readers.map(row => ({
        reader:row.id, phase:'refresh', source_root:'cost_source:one',
        kind:'record', path:'amount', fallback:'0',
      })).concat(state.range_readers.filter(row => row.active).map(row => ({
        reader:row.id, phase:'refresh', source_root:row.source, source_slot:'z_points', kind:'range',
        arguments:[[row.lower],[row.upper]], path:'measures.value.sum', fallback:'0',
      })));
      for (const row of state.readers) assert.equal(Number(row.amount), Number(state.sources.find(source => source.id === row.source).amount), row.id);
      for (const row of state.range_readers) {
        const wanted = row.active ? state.points.filter(point => point.source === row.source
          && point.at >= row.lower && point.at < row.upper).reduce((sum, point) => sum + Number(point.value), 0) : 0;
        assert.equal(Number(row.amount), wanted, `${row.id}: independently sorted range value`);
      }
      const entries = state.points.map(point => ({ link:{rid:point.id,slot:'z_point'}, owner:{rid:point.source,slot:'z_points'},
        key:[point.at,point.id,'z_point'], measures:{value:Number(point.value)}, tags:{}, spans:{}, dependent:false }));
      for (const source of state.sources) {
        const wanted = state.points.filter(point => point.source === source.id).reduce((sum, point) => sum + Number(point.value), 0);
        assert.equal(Number(source.z_points.summary.measures.value?.sum ?? 0), wanted, `${source.id}: source tree sum`);
      }
      verifyReads(state, [...state.sources,...state.points,...state.readers,...state.range_readers,...state.tenants], entries, compare,
        { rootSpecs:[{table:'cost_source',slot:'z_points'}], expectedReads });
    };
    const mutate = async (statement, size, operation) => {
      await q('UPDATE cost_stats:one SET pulls=0,gets=0,visits=0,candidates=0,candidate_calls=0,candidate_groups=[],refreshes=0;');
      await q(statement);
      const bound = 3 * Math.ceil(Math.log2(size + 1)) + 3;
      const getBound = 16 * Math.ceil(Math.log2(size + 1)) + 16;
      const counts = (await snapshot(q)).cost_stats[0];
      assert(counts.pulls <= bound, `${operation} with ${size} readers: ${counts.pulls} pulls exceeds logarithmic allowance ${bound}`);
      assert(counts.gets <= getBound, `${operation} with ${size} readers: ${counts.gets} node gets exceeds logarithmic allowance ${getBound}`);
      return { operation, size, pulls:counts.pulls, nodeGets:counts.gets, intervalVisits:counts.visits,
        candidateResults:counts.candidates, candidateCalls:counts.candidate_calls,
        candidateGroups:counts.candidate_groups, derivedRefreshes:counts.refreshes, bound, getBound };
    };
    for (let i = 1; i <= 64; i++) {
      const id = `cost_reader:r${String(i).padStart(3,'0')}`;
      const measurement = await mutate(`CREATE ${id} SET owned_by=rebase_tenant:default,source=cost_source:one;`, i, 'insert');
      if ([1,4,8,16,32,64].includes(i)) { await check(); measurements.push(measurement); }
    }
    await q('UPDATE cost_stats:one SET pulls=0,gets=0,visits=0,candidates=0,candidate_calls=0,candidate_groups=[],refreshes=0;');
    await q('UPDATE cost_source:one SET amount=5dec;');
    let counts = (await snapshot(q)).cost_stats[0];
    assert.equal(counts.pulls, 0, 'retained registrations need no topology repair');
    assert.equal(counts.refreshes, 64, 'all 64 direct readers recompute after their consumed source value changes');
    await check();
    for (let i = 32; i >= 1; i--) {
      const measurement = await mutate(`DELETE ONLY cost_reader:r${String(i).padStart(3,'0')};`, 32+i, 'delete');
      if (i === 32 || i === 1) { await check(); measurements.push(measurement); }
    }

    let rangeCount = 0;
    for (let i = 0; i < 48; i++) {
      const id = `cost_range_reader:r${String(i).padStart(3,'0')}`;
      const [lower, upper] = i < 16 ? [32,33] : i === 16 ? [100,101] : [200 + 2*i,201 + 2*i];
      const measurement = await mutate(`CREATE ${id} SET owned_by=rebase_tenant:default,source=cost_source:one,lower=${lower},upper=${upper};`,
        ++rangeCount, 'range insert');
      if ([1,4,8,16,32,48].includes(rangeCount)) { await check(); measurements.push(measurement); }
    }
    let secondGroupCount = 0;
    for (let i = 0; i < 16; i++) {
      const id = `cost_range_reader:other${String(i).padStart(3,'0')}`;
      const measurement = await mutate(`CREATE ${id} SET owned_by=rebase_tenant:default,source=cost_source:two,lower=100,upper=101;`,
        ++secondGroupCount, 'second-group range insert');
      if ([1,4,8,16].includes(secondGroupCount)) { await check(); measurements.push(measurement); }
    }
    const branch = await mutate('UPDATE cost_range_reader:r000 SET active=false;', rangeCount, 'range branch delete');
    await check(); measurements.push(branch);
    const rebranch = await mutate('UPDATE cost_range_reader:r000 SET active=true;', rangeCount, 'range branch insert');
    await check(); measurements.push(rebranch);

    await q('UPDATE cost_stats:one SET pulls=0,gets=0,visits=0,candidates=0,candidate_calls=0,candidate_groups=[],refreshes=0;');
    await q('UPDATE cost_point:p_one_100 SET value=2dec;');
    counts = (await snapshot(q)).cost_stats[0];
    const oneCandidateBound = 4 * Math.ceil(Math.log2(rangeCount + 1)) + 10;
    const intervalBound = Math.min(rangeCount, 4 * (1 + 1) * Math.ceil(Math.log2(rangeCount + 1)));
    const rangeGroups = (await snapshot(q)).rebase_read_group.filter(group => group.source_root === 'cost_source:one'
      && group.source_slot === 'z_points' && group.kind === 'range');
    assert.equal(rangeGroups.length, 1, 'all overlapping reads share the expected source group');
    assert.equal(counts.candidates, 2, 'the one changed member is checked as old and new, each yielding the same one matching reader');
    assert.equal(counts.candidate_calls, 2, 'old and new member images each probe the same source group');
    assert.deepEqual(counts.candidate_groups, [rangeGroups[0].id], 'the unrelated second source group is not probed');
    assert.equal(counts.refreshes, 1, 'one matching range reader is refreshed');
    assert(counts.visits < rangeCount, `interval stabbing visits ${counts.visits}, fewer than ${rangeCount} range nodes`);
    assert(counts.visits <= oneCandidateBound, `one-candidate interval bound ${counts.visits} <= ${oneCandidateBound}`);
    assert(counts.visits <= intervalBound, `conservative interval stabbing bound ${counts.visits} <= ${intervalBound}`);
    assert.equal(counts.pulls, 0, 'retained range subscriptions do not change topology');
    await check();
    measurements.push({ operation:'skewed one-range fan-out', size:rangeCount, pulls:counts.pulls,
      nodeGets:counts.gets, intervalVisits:counts.visits, candidateResults:counts.candidates,
      candidateCalls:counts.candidate_calls, candidateGroups:counts.candidate_groups,
      derivedRefreshes:counts.refreshes, bound:oneCandidateBound, intervalBound });

    await q('UPDATE cost_stats:one SET pulls=0,gets=0,visits=0,candidates=0,candidate_calls=0,candidate_groups=[],refreshes=0;');
    await q('UPDATE cost_point:p_one_032 SET value=2dec;');
    counts = (await snapshot(q)).cost_stats[0];
    assert.equal(counts.candidates, 32, 'old and new member images each return the sixteen genuinely overlapping readers');
    assert.equal(counts.candidate_calls, 2, 'the old and new member images each probe the same range group');
    assert.equal(counts.refreshes, 16, 'only the sixteen changed range calculations refresh');
    assert.equal(counts.pulls, 0, 'skewed fan-out retains interval topology');
    const manyIntervalBound = Math.min(rangeCount, 4 * (16 + 1) * Math.ceil(Math.log2(rangeCount + 1)));
    assert(counts.visits <= manyIntervalBound, `sixteen-candidate interval bound ${counts.visits} <= ${manyIntervalBound}`);
    assert.deepEqual(counts.candidate_groups, [rangeGroups[0].id], 'the unrelated second source group remains unprobed at higher fan-out');
    await check();
    measurements.push({ operation:'skewed sixteen-reader fan-out', size:rangeCount, pulls:counts.pulls,
      nodeGets:counts.gets, intervalVisits:counts.visits, candidateResults:counts.candidates,
      candidateCalls:counts.candidate_calls, candidateGroups:counts.candidate_groups,
      derivedRefreshes:counts.refreshes, intervalBound:manyIntervalBound });

    const plan = await q(`EXPLAIN SELECT * FROM rebase_read_group:[cost_source:one,'z_points',NONE]..[cost_source:one,'z_points',..];`);
    const planText = JSON.stringify(plan);
    assert.match(planText, /RecordIdScan/i, `bounded group selection should use its record-id interval: ${planText}`);
    assert.doesNotMatch(planText, /TableScan/i, `bounded group lookup must not TableScan: ${planText}`);
    measurements.push({ operation:'native source-group selection EXPLAIN', plan });

    console.log(JSON.stringify(measurements));
    console.log('PASS bounded point/range subscription repair, branch churn, skewed fan-out, multiple groups and exact read inventory');
  } finally {
    if (server) await server.close();
    fs.rmSync(directory, { recursive:true, force:true });
  }
}

if (require.main === module) main().catch(error => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
module.exports = { main };

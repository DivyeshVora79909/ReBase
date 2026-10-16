#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { generateBundle } = require('../compiler/pipeline');
const { classifyMaterials, readMaterialFiles } = require('../compiler/materials');
const { start, client, applySchema } = require('./harness');
const dependency = require('./dependency-oracle');
const tree = require('./oracle');

async function main() {
  const file = path.join(__dirname, 'dependencies-fixture.surql');
  const source = fs.readFileSync(file, 'utf8') + `
DEFINE TABLE OVERWRITE cost_reader SCHEMAFULL;
DEFINE FIELD OVERWRITE curve ON cost_reader TYPE record<dep_curve> REFERENCE ON DELETE REJECT;
DEFINE FIELD OVERWRITE at ON cost_reader TYPE int;
DEFINE FIELD OVERWRITE q ON cost_reader TYPE option<object> FLEXIBLE
VALUE {source:$this.curve,arguments:[[$this.at]],path:'measures.amount.sum',fallback:0dec}
COMMENT '@rebase-dependency latest @rebase-dependency-source dep_curve.z_points';
DEFINE FIELD OVERWRITE amount ON cost_reader TYPE decimal VALUE fn::dependency::value($this.q) COMMENT '@rebase-derived';`;
  const compiled = generateBundle(classifyMaterials([
    ...readMaterialFiles([{ name: 'framework', roots: [path.resolve(__dirname, '../../framework')] }]),
    { group: 'project', path: file, relative: 'fixture.surql', source },
  ]));
  // Instrument only the disposable proof after the production purity check.
  const bundle = compiled.bundle
    .replace('DEFINE FUNCTION OVERWRITE fn::tree::get($link: option<object>) {',
      'DEFINE FUNCTION OVERWRITE fn::tree::get($link: option<object>) { UPDATE dependency_cost:counter SET reads+=1;')
    .replace('DEFINE FUNCTION OVERWRITE fn::rebase::derive($row: object, $inputs_only: bool) {',
      "DEFINE FUNCTION OVERWRITE fn::rebase::derive($row: object, $inputs_only: bool) { IF !$inputs_only AND record::tb($row.id)='cost_reader' { UPDATE dependency_cost:counter SET evaluations+=1; };");
  const server = await start(), q = client(server.url), measurements = [];
  const check = async () => {
    const data = await q('RETURN {curves:(SELECT * FROM dep_curve),points:(SELECT * FROM dep_point),readers:(SELECT * FROM cost_reader)};');
    const rows = Object.values(data).flat();
    const entries = data.points.map(point => ({ link:{rid:point.id,slot:'z_point'},owner:{rid:point.curve,slot:'z_points'},
      key:[point.at,point.id,'z_point'],measures:{amount:Number(point.amount),other:Number(point.other)},tags:{} }));
    const expected = data.readers.map(row => ({reader:row.id,field:'q',source:row.curve,source_slot:'z_points',kind:'latest',phase:'refresh',
      arguments:[[row.at]],path:'measures.amount.sum',fallback:0}));
    for (const query of expected) assert.equal(Number(data.readers.find(row=>row.id===query.reader).amount), dependency.answer(query,entries));
    const indexes = dependency.verifyDependencies(rows,entries,expected,compiled.temporalModel.dependencyModel);
    tree.verify(rows,rows,[...entries,...indexes],dependency.compare);
  };
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q,bundle);
    await q('DEFINE TABLE dependency_cost SCHEMALESS; CREATE dependency_cost:counter SET reads=0,evaluations=0; CREATE dep_curve:cost SET owned_by=rebase_tenant:default;');
    for (let index=0;index<128;index++) {
      const id=String(index).padStart(3,'0');
      await q(`CREATE dep_point:p${id} SET owned_by=rebase_tenant:default,curve=dep_curve:cost,at=${index*4},amount=1dec;`);
      await q(`CREATE cost_reader:r${id} SET owned_by=rebase_tenant:default,curve=dep_curve:cost,at=${index*4+1};`);
      await check();
      if (![31,127].includes(index)) continue;
      await q('UPDATE dependency_cost:counter SET reads=0,evaluations=0;');
      await q(`UPDATE dep_point:p016 SET amount=${index}dec;`);
      const counts = await q('SELECT * FROM ONLY dependency_cost:counter;');
      assert.equal(counts.evaluations,1,'one changed predecessor answer evaluates exactly one reader');
      assert(counts.reads < 100 * (Math.ceil(Math.log2(index+2))+1),'structural reads are bounded by tree height in this fixture');
      measurements.push({readers:index+1,reads:counts.reads,evaluations:counts.evaluations});
      await check();
      await q('UPDATE dependency_cost:counter SET reads=0,evaluations=0; UPDATE dep_point:p016 SET other+=1dec;');
      assert.equal((await q('SELECT * FROM ONLY dependency_cost:counter;')).evaluations,0,'unconsumed channel performs no reader evaluations');
      await check();
    }
    assert(measurements[1].reads < measurements[0].reads*2.5,'four times as many readers does not require a linear scan');
    for(let index=127;index>=0;index--){const id=String(index).padStart(3,'0');await q(`DELETE cost_reader:r${id}; DELETE dep_point:p${id};`);}
    await check(); await q('DELETE dep_curve:cost;');
    console.log(JSON.stringify({status:'PASS',measurements,sourceCheckpoints:133,cleanup:true}));
  } finally { await server.close(); }
}
if(require.main===module)main().catch(error=>{console.error(error);process.exitCode=1;});
module.exports={main};

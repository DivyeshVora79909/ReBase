#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { classifyMaterials, readMaterialFiles } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, recordClient, applySchema } = require('./harness');
const tree = require('./oracle');
const exactTree = require('./exact-oracle');
const { D } = require('../accounting/source-oracle');
const dependency = require('./dependency-oracle');

async function main() {
  const file = path.join(__dirname, 'dependencies-fixture.surql');
  const compiled = generateBundle(classifyMaterials([
    ...readMaterialFiles([{ name: 'framework', roots: [path.resolve(__dirname, '../../framework')] }]),
    { group: 'project', path: file, relative: 'schema.surql', source: fs.readFileSync(file, 'utf8') },
  ]), { context: { namespace: 'temporal_probe', database: 'fixture' } });
  const schemaFile = '/tmp/rebase-dependencies-current.surql';
  fs.writeFileSync(schemaFile, compiled.bundle);
  assert(!/DEFINE TABLE\s+(?:OVERWRITE\s+)?rebase_read\b/.test(compiled.bundle), 'no dynamic subscription table');
  const server = await start(); const q = client(server.url);
  let checkpoints = 0, rollbacks = 0, conflicts = 0;
  const snapshot = () => q(`RETURN {curves:(SELECT * FROM dep_curve ORDER BY id),points:(SELECT * FROM dep_point ORDER BY id),
    feedback:(SELECT * FROM dep_feedback ORDER BY id),joins:(SELECT * FROM dep_join ORDER BY id),readers:(SELECT * FROM dep_reader ORDER BY id),children:(SELECT * FROM dep_child ORDER BY id),
    moments:(SELECT * FROM dep_moment ORDER BY id),scheduled:(SELECT * FROM dep_scheduled ORDER BY id),books:(SELECT * FROM dep_book ORDER BY id),adjustments:(SELECT * FROM dep_adjustment ORDER BY id),audits:(SELECT * FROM audit_mutation ORDER BY id)};`);
  const verify = async () => {
    const data = await snapshot();
    const entries = data.points.map(point=>({link:{rid:point.id,slot:'z_point'},owner:{rid:point.curve,slot:'z_points'},
      key:[point.at,point.id,'z_point'],measures:{amount:new D(point.amount),other:new D(point.other)},tags:{}}));
    const expected = [];
    for (const reader of data.readers) {
      const points = data.points.filter(point => point.curve === reader.curve).sort((a, b) => a.at - b.at || a.id.localeCompare(b.id));
      const initial = data.curves.find(curve => curve.id === reader.curve).initial;
      const sum = values => values.reduce((total, point) => total + Number(point.amount), 0);
      const values = {
        latest: reader.enabled ? Number(points.filter(point => point.at < reader.at).at(-1)?.amount ?? initial) : 0,
        next: Number(points.find(point => point.at >= reader.at)?.amount ?? 0),
        exact: Number(points.find(point => point.at === reader.at)?.amount ?? 0),
        prefix: sum(points.filter(point => point.at < reader.at)),
        segment: sum(points.filter(point => (reader.lower == null || point.at >= reader.lower) && (reader.upper == null || point.at < reader.upper))),
        total: sum(points),
      };
      for (const [field, expected] of Object.entries(values)) assert.equal(Number(reader[field]), expected, `${reader.id}.${field}`);
      const query = (field,kind,args,fallback=0,phase='refresh')=>expected.push({reader:reader.id,field,source:reader.curve,
        source_slot:'z_points',kind,arguments:args,path:'measures.amount.sum',fallback:new D(fallback),phase});
      if(reader.enabled)query('q_latest','latest',[[reader.at]],initial);
      query('q_next','next',[[reader.at]]); query('q_exact','exact',[reader.at]);
      query('q_prefix','range',[null,[reader.at]]); query('q_total','range',[null,null]);
      query('q_range','range',[reader.lower==null?null:[reader.lower],reader.upper==null?null:[reader.upper]]);
      if(reader.limit!=null)query('q_guard','range',[null,[reader.at]],0,'validate');
    }
    for (const child of data.children) assert.equal(Number(child.amount), Number(data.readers.find(reader => reader.id === child.source).latest) * Number(child.factor));
    for (const row of data.joins) assert.equal(Number(row.amount),
      Number(data.children.find(child=>child.id===row.first).amount)+Number(data.children.find(child=>child.id===row.second).amount),`${row.id}: settled diamond`);
    for (const book of data.books) {
      let current = Number(book.base);
      for (const adjustment of [...data.adjustments,...data.scheduled].filter(row => row.book === book.id).sort((a, b) => a.at - b.at || a.id.localeCompare(b.id))) {
        assert.equal(Number(adjustment.delta), Number(adjustment.target) - current, `${adjustment.id} chronological delta`);
        const delta=Number(adjustment.target)-current;
        entries.push({link:{rid:adjustment.id,slot:'z_change'},owner:{rid:book.id,slot:'z_changes'},
          key:[adjustment.at,adjustment.id,'z_change'],measures:{amount:new D(delta)},tags:{}});
        expected.push({reader:adjustment.id,field:'q_before',source:book.id,source_slot:'z_changes',kind:'range',
          arguments:[null,[adjustment.at]],path:'measures.amount.sum',fallback:new D(0),phase:'refresh'});
        current = Number(adjustment.target);
      }
    }
    const rows=Object.entries(data).filter(([name])=>name!=='audits').flatMap(([,rows])=>rows);
    const indexes=dependency.verifyDependencies(rows,entries,expected,compiled.temporalModel.dependencyModel,{
      compare:dependency.compare,Decimal:D,summarize:items=>exactTree.linearSummary(items,D,dependency.compare),
      rootSpecs:compiled.temporal.trees.roots,
    });
    const all=[...entries,...indexes];
    tree.verify(rows,rows,all.map(entry=>({...entry,measures:Object.fromEntries(Object.entries(entry.measures).map(([key,value])=>[key,Number(value instanceof D?value.number():value)]))})),dependency.compare);
    exactTree.verify(rows,rows,all,dependency.compare,D);
    checkpoints++;
  };
  const run = async sql => { await q(sql); await verify(); };
  try {
    await applySchema(q, compiled.bundle);
    await q("CREATE dep_curve:a SET owned_by=rebase_tenant:default,initial=2dec; CREATE dep_curve:b SET owned_by=rebase_tenant:default,initial=3dec;");
    await run('CREATE dep_reader:one SET owned_by=rebase_tenant:default,curve=dep_curve:a,at=10,lower=2,upper=8;');
    await run('CREATE dep_child:one SET owned_by=rebase_tenant:default,source=dep_reader:one;');
    await run('CREATE dep_child:two SET owned_by=rebase_tenant:default,source=dep_reader:one,factor=3dec;');
    await run('CREATE dep_join:one SET owned_by=rebase_tenant:default,first=dep_child:one,second=dep_child:two;');
    const cycleBefore=await snapshot();
    await assert.rejects(q('CREATE dep_feedback:loop SET owned_by=rebase_tenant:default,curve=dep_curve:a;'),/REBASE_CALCULATION_CYCLE/);
    assert.deepEqual(await snapshot(),cycleBefore,'ordered feedback rolls back the initiating transaction');rollbacks++;
    await run('CREATE dep_point:first SET owned_by=rebase_tenant:default,curve=dep_curve:a,at=3,amount=5dec;');
    await run('CREATE dep_point:last SET owned_by=rebase_tenant:default,curve=dep_curve:a,at=10,amount=7dec;');
    await run('UPDATE dep_point:first SET amount=6dec;');
    await run('UPDATE dep_reader:one SET at=3;');
    await run('UPDATE dep_curve:a SET initial=11dec;');
    await run('UPDATE dep_reader:one SET at=12,limit=20dec;');
    const before = await snapshot();
    await assert.rejects(q('UPDATE dep_point:first SET amount=30dec;'), /DEPENDENCY_GUARD/);
    assert.deepEqual(await snapshot(), before, 'validator rejection restores records and index revisions'); rollbacks++;
    await run('UPDATE dep_point:first SET at=5;');
    await run('UPDATE dep_point:first SET curve=dep_curve:b;');
    await run('UPDATE dep_reader:one SET curve=dep_curve:b,enabled=false;');
    await run('UPDATE dep_reader:one SET enabled=true;');
    await run('DELETE dep_point:first;');
    await q('CREATE dep_book:a SET owned_by=rebase_tenant:default,base=10dec;');
    await run('CREATE dep_adjustment:early SET owned_by=rebase_tenant:default,book=dep_book:a,at=3,target=12dec;');
    await run('CREATE dep_adjustment:late SET owned_by=rebase_tenant:default,book=dep_book:a,at=9,target=8dec;');
    await run('UPDATE dep_adjustment:early SET target=15dec;');
    await run('UPDATE dep_adjustment:late SET at=1;');
    await run('CREATE dep_moment:one SET owned_by=rebase_tenant:default,at=4; CREATE dep_scheduled:one SET owned_by=rebase_tenant:default,book=dep_book:a,moment=dep_moment:one,target=14dec;');
    await run('UPDATE dep_moment:one SET at=7;');
    await run('UPDATE dep_moment:one SET at=-2;');
    await run('DELETE dep_scheduled:one; DELETE dep_moment:one;');
    await run('DELETE dep_adjustment:late;');
    await run('DELETE dep_adjustment:early;');
    // Seeded histories exercise reparenting, both bounds, duplicate points,
    // disable/enable, empty intervals and changes to consumed/unconsumed measures.
    await run('UPDATE dep_reader:one SET limit=NONE,curve=dep_curve:a;');
    let seed=0xdec1a;
    const random=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;};
    const present=new Set();
    for(let step=0;step<48;step++){
      const id='random_'+random(8),at=random(17)-8,curve=random(2)?'a':'b';
      if(!present.has(id)){
        await run(`CREATE dep_point:${id} SET owned_by=rebase_tenant:default,curve=dep_curve:${curve},at=${at},amount=${random(11)}dec;`);present.add(id);
      }else if(step%5===0){await run(`DELETE dep_point:${id};`);present.delete(id);}
      else await run(`UPDATE dep_point:${id} SET curve=dep_curve:${curve},at=${at},amount=${random(11)}dec,other=${random(9)}dec;`);
      if(step%4===0)await run(`UPDATE dep_reader:one SET at=${random(17)-8},lower=${step%8===0?'NONE':random(12)-6},upper=${step%12===0?'NONE':random(12)-6},enabled=${step%8===0},curve=dep_curve:${curve};`);
    }
    for(const id of present)await run(`DELETE dep_point:${id};`);
    // Independent transactions must serialize even when the first recalculation
    // keeps a zero result. Retry only a confirmed conflict, as a whole statement.
    await run('UPDATE dep_reader:one SET curve=dep_curve:a,at=20,enabled=true; UPDATE dep_child:one SET factor=0dec;');
    const peer=client(server.url);
    const retry=async(actor,sql)=>{for(let attempt=0;;attempt++){try{return await actor(sql);}catch(error){
      if(!/conflict|retry/i.test(error.message)||attempt>=20)throw error;conflicts++;
    }}};
    for(let i=0;i<6;i++){
      await run('UPDATE dep_child:one SET factor=0dec;');
      await Promise.all([retry(q,`UPDATE dep_point:last SET amount=${11+i}dec;`),retry(peer,`UPDATE dep_child:one SET factor=${i+1}dec;`)]);
      await verify();
    }
    await q("CREATE rebase_user:reader SET name='Reader',parents=[rebase_tenant:default]; CREATE rebase_user:hidden SET name='Hidden',parents=[rebase_tenant:default]; DEFINE ACCESS dependency_reader ON DATABASE TYPE RECORD SIGNIN rebase_user:reader;");
    const actor=await recordClient(server.url,'dependency_reader');
    await assert.rejects(actor("RETURN fn::dependency::current({source:dep_curve:a,source_slot:'z_points',kind:'range',arguments:[NONE,NONE],path:'count',fallback:{value:0}});"),/permission|not allowed/i);
    await assert.rejects(actor("RETURN fn::dependency::resolve({source:dep_curve:a,arguments:[NONE,NONE],path:'count',fallback:0},'range','refresh',[{table:'dep_curve',slot:'z_points',index:'__rebase_dependents_z_points_range'}],true);"),/permission|not allowed/i);
    await q('CREATE dep_curve:hidden SET owned_by=rebase_user:hidden;');
    const privateBefore=await snapshot();
    await actor('UPDATE dep_reader:one SET q_latest={source:dep_curve:hidden},__rebase_dependency_q_latest=NONE; UPDATE dep_curve:a SET rebase_dependency_revision=123456;');
    assert.deepEqual(await snapshot(),privateBefore,'query descriptors, nodes and source revisions are protected');
    await assert.rejects(actor("CREATE dep_reader:hidden SET owned_by=rebase_user:reader,curve=dep_curve:hidden,at=10;"),/permission|not allowed|REBASE_DEPENDENCY_SOURCE/i);rollbacks++;
    assert.deepEqual(await snapshot(),privateBefore,'hidden query source rolls back');
    await q('DELETE dep_curve:hidden;');
    const reapplied=await snapshot();await applySchema(q,compiled.bundle);
    assert.deepEqual(await snapshot(),reapplied,'populated schema reapplication preserves every fixed query and root');
    await run('DELETE dep_join:one;');
    await run('DELETE dep_child:two;');
    await run('DELETE dep_child:one;');
    await run('DELETE dep_reader:one;');
    await run('DELETE dep_point:last;');
    await q('DELETE dep_book:a; DELETE dep_curve:a; DELETE dep_curve:b;');
    console.log(JSON.stringify({ status: 'PASS', checkpoints, rollbackChecks: rollbacks, conflicts, seed: "0xdec1a", cleanup: true, declarations: compiled.temporalModel.dependencyModel.declarations.length }));
  } finally { await server.close(); }
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };

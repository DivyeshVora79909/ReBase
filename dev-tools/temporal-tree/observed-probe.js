#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema, compareIntKey, recordClient } = require('./harness');

const create = (id, fields) => `CREATE ${id} SET owned_by=rebase_tenant:default, ${fields};`;
const snapshot = q => q(`RETURN {
 curves: (SELECT * FROM read_curve ORDER BY id), points: (SELECT * FROM read_point ORDER BY id),
 readers: (SELECT * FROM read_reader ORDER BY id), observers: (SELECT * FROM read_observer ORDER BY id),
 books: (SELECT * FROM read_book ORDER BY id), adjustments: (SELECT * FROM read_adjustment ORDER BY id),
 reads: (SELECT * FROM rebase_read ORDER BY id), groups: (SELECT * FROM rebase_read_group ORDER BY id),
 frames: (SELECT * FROM rebase_read_frame ORDER BY id), locks: (SELECT * FROM rebase_read_lock ORDER BY id),
 calls: (SELECT * FROM read_probe_calls ORDER BY id), stats: (SELECT * FROM read_probe_stats ORDER BY id),
 feedback: (SELECT * FROM read_feedback ORDER BY id), publications: (SELECT * FROM read_publication ORDER BY id),
 dates: (SELECT * FROM read_dates ORDER BY id), quotes: (SELECT * FROM read_quote ORDER BY id), dated: (SELECT * FROM read_dated ORDER BY id)
};`);

function instrument(sql) {
  return sql.replace('DEFINE FUNCTION OVERWRITE fn::rebase::derive(', 'DEFINE FUNCTION OVERWRITE fn::read_probe::derive(')
    .replace('DEFINE FUNCTION OVERWRITE fn::reads::stab(', 'DEFINE FUNCTION OVERWRITE fn::read_probe::stab(')
    .replace('DEFINE FUNCTION OVERWRITE fn::reads::candidates(', 'DEFINE FUNCTION OVERWRITE fn::read_probe::candidates(')
    .replace('DEFINE FUNCTION OVERWRITE fn::reads::remember(', 'DEFINE FUNCTION OVERWRITE fn::read_probe::remember(') + `
DEFINE TABLE OVERWRITE read_probe_calls SCHEMALESS PERMISSIONS NONE;
DEFINE TABLE OVERWRITE read_probe_stats SCHEMALESS PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::rebase::derive($row: object, $scope: object) {
 IF record::tb($row.id) IN ['read_reader', 'read_observer', 'read_adjustment'] {
  UPSERT type::record('read_probe_calls', <string>$row.id) SET calls = (calls ?? 0) + 1 RETURN NONE;
 };
 RETURN fn::read_probe::derive($row, $scope);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::reads::stab($link: option<object>, $key: array) {
 IF $link != NONE { UPSERT read_probe_stats:stabs SET calls=(calls??0)+1 RETURN NONE; };
 RETURN fn::read_probe::stab($link,$key);
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::reads::candidates($group: object, $key: array) {
 LET $reads=fn::read_probe::candidates($group,$key);
 UPSERT read_probe_stats:candidates SET calls=(calls??0)+array::len($reads) RETURN NONE;
 RETURN $reads;
} PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::reads::remember($scope: object,$source: record,$slot: string,$kind: string,$arguments: array,$path: string,$fallback: any,$value: any) {
 IF $scope.reader=read_reader:race AND $kind='latest' { SLEEP 400ms; };
 RETURN fn::read_probe::remember($scope,$source,$slot,$kind,$arguments,$path,$fallback,$value);
} PERMISSIONS NONE;`;
}

function oracle(s) {
  for(const row of s.dated) {
    const quote=s.quotes.filter(quote=>quote.curve===row.curve&&quote.at<=row.at).sort((a,b)=>a.at.localeCompare(b.at)).at(-1);
    assert.equal(Number(row.rate),Number(quote?.rate??s.dates.find(curve=>curve.id===row.curve).initial),'same timestamp/nanosecond dependency');
  }
  for(const row of s.publications) {
    const amount=s.points.filter(point=>point.curve===row.curve).reduce((sum,point)=>sum+Number(point.value),0);
    assert.equal(Number(row.published),amount,'computed publication dependency');
    assert.equal(Number(row.current),amount,'record root-summary read becomes a logical tree subscription');
    const selected=s.points.filter(point=>point.curve===row.curve && point.at<100).sort((a,b)=>a.at-b.at || a.id.localeCompare(b.id)).at(-1);
    assert.deepEqual(row.selection.key,selected?[selected.at,selected.id,'z_point']:undefined,'selected logical key persists without appending');
    assert.equal(row.selection.record,selected?.id,'selected record persists in a flexible derived object');
    assert.deepEqual(row.ranges.map(Number),[0,1,0].map(index=>s.points.filter(point=>point.curve===row.curve && point.at>=(index?8:0)&&point.at<(index?30:8)).reduce((sum,point)=>sum+Number(point.value),0)), 'multiple range reads and exact duplicates');
  }
  for (const reader of s.readers) {
    const curve = s.curves.find(row => row.id === reader.curve);
    const points = s.points.filter(row => row.curve === curve.id).sort((a,b) => a.at-b.at || a.id.localeCompare(b.id));
    let value;
    if (reader.disabled) value = 0;
    else if (reader.operation === 'latest') value = Number(points.filter(row => row.at < reader.at).at(-1)?.value ?? curve.initial);
    else if (reader.operation === 'next') value = Number(points.find(row => row.at >= reader.at)?.value ?? curve.initial);
    else if (reader.operation === 'exact') value = Number(points.find(row => row.at === reader.at)?.value ?? curve.initial);
    else value = points.filter(row => reader.operation === 'summary' || reader.operation === 'before' && row.at < reader.at ||
      reader.operation === 'range' && row.at >= reader.at && row.at < reader.until).reduce((sum,row) => sum + Number(row.value),0);
    assert.equal(Number(reader.z_rate), value, `${reader.id}: selected value`);
    assert.equal(Number(reader.amount), value * Number(reader.quantity), `${reader.id}: dependent field order`);
  }
  for (const observer of s.observers) assert.equal(Number(observer.amount), Number(s.readers.find(row => row.id === observer.source).amount)*2);
  for (const book of s.books) {
    let quantity = Number(book.base);
    const rows = s.adjustments.filter(row => row.book === book.id).sort((a,b) => a.at-b.at);
    for (const row of rows) {
      assert.equal(Number(row.delta), Number(row.target)-quantity, `${row.id}: preceding aggregate`);
      quantity = Number(row.target);
    }
    assert.equal(Number(book.z_adjustments.summary.measures.quantity?.sum ?? 0), quantity-Number(book.base));
  }
  for (const group of s.groups) {
    const reads = s.reads.filter(row => row.group === group.id);
    assert(reads.length>0,'no empty subscription group');
    if (group.kind !== 'range') continue;
    const intervals = reads.filter(row => row.arguments[0][0] < row.arguments[1][0]);
    const byId = new Map(intervals.map(row => [row.id,row])), seen = new Set();
    function visit(link, parent, lower, upper) {
      if (!link) return {height:0,end:undefined,keys:[]};
      const row = byId.get(link.rid); assert(row, 'interval node exists'); assert(!seen.has(row.id), 'no interval cycle'); seen.add(row.id);
      const node = row.z_interval;
      assert.deepEqual(node.parent, parent); assert.deepEqual(node.owner, {rid:group.id,slot:'z_intervals'});
      assert.deepEqual(node.key, [row.arguments[0], row.id, 'z_interval']);
      const compare = (a,b) => compareIntKey(a[0],b[0]) || a[1].localeCompare(b[1]) || a[2].localeCompare(b[2]);
      if (lower) assert(compare(lower,node.key)<0); if (upper) assert(compare(node.key,upper)<0);
      const left = visit(node.left,link,lower,node.key), right = visit(node.right,link,node.key,upper);
      const end = [left.end,row.arguments[1],right.end].filter(Boolean).sort(compareIntKey).at(-1);
      assert.deepEqual(node.summary.end_key,end, 'interval maximum upper bound');
      assert(Math.abs(left.height-right.height)<=1); assert.equal(node.height,1+Math.max(left.height,right.height));
      return {height:node.height,end,keys:[...left.keys,node.key,...right.keys]};
    }
    const tree = visit(group.z_intervals.root,{rid:group.id,slot:'z_intervals'});
    assert.equal(seen.size,intervals.length); assert.equal(group.z_intervals.height,tree.height);
    assert.deepEqual(group.z_intervals.summary.end_key,tree.end);
    assert.equal(group.z_intervals.summary.count,intervals.length);
  }
  for (const reader of s.readers.filter(row => row.disabled)) assert(!s.reads.some(row => row.reader === reader.id && row.phase==='refresh'), 'inactive branches release reads');
}

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(),'rebase-observed-proof-'));
  fs.copyFileSync(path.join(__dirname,'observed-fixture.surql'),path.join(directory,'fixture.surql'));
  const compiled = generateBundle(loadMaterials({groups:[
    {name:'framework',roots:[path.resolve(__dirname,'../../framework')]}, {name:'project',roots:[directory]}
  ]}));
  const sql = instrument(compiled.bundle);
  fs.writeFileSync(path.join(directory,'schema.txt'),sql);
  const server = await start(), q = client(server.url);
  let last='schema application', checkpoints=0, rejections=0;
  const run = async (statement, expected) => {
    last = statement; const before = await snapshot(q); await q(statement); const after = await snapshot(q); oracle(after); checkpoints++;
    if (expected) {
      const calls = after.calls.filter(row => row.calls !== before.calls.find(old => old.id === row.id)?.calls);
      const readers = calls.filter(row => row.id.includes('read_reader:')).map(row => row.id.match(/read_reader:([A-Za-z0-9_]+)/)[1]).sort();
      assert.deepEqual(readers,expected.slice().sort(),'only changed consumed values reevaluate readers');
      for (const row of calls) assert.equal(row.calls-(before.calls.find(old=>old.id===row.id)?.calls??0),1,'each affected calculation runs once');
    }
    return after;
  };
  const reject = async(statement,error) => {
    last=statement; const before=await snapshot(q); await assert.rejects(q(statement),error);
    assert.deepEqual(await snapshot(q),before,'rejected closure rolls back subscriptions and fences'); rejections++;
  };
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q,sql); console.log('Observed reads: schema applied');
    await q(create('read_curve:a','initial=2dec')+create('read_curve:b','initial=7dec'));
    await q(create('read_point:first','curve=read_curve:a,at=5,value=3dec')+create('read_point:last','curve=read_curve:a,at=10,value=5dec'));
    await q(create('read_publication:a','curve=read_curve:a'));
    for(const at of [2,5,6,9,10,12]) await q(create(`read_reader:r${at}`,`curve=read_curve:a,at=${at},operation='latest',quantity=2dec`)+create(`read_observer:o${at}`,`source=read_reader:r${at}`));
    oracle(await snapshot(q)); console.log('Observed reads: predecessor and nested helper capture');
    await run('UPDATE read_point:first SET value=4dec;', ['r6','r9','r10']);
    await run("UPDATE read_point:first SET label='irrelevant';",[]);
    await run('UPDATE read_point:first SET other=3dec;',[]);
    await run(create('read_point:middle','curve=read_curve:a,at=7,value=4dec'),[]);
    await run('UPDATE read_point:middle SET value=6dec;',['r9','r10']);
    await run('UPDATE read_point:middle SET at=6;',[]);
    await run('UPDATE read_curve:a SET initial=9dec;',['r2','r5']);
    await run('DELETE read_point:middle;',['r9','r10']);
    await run('UPDATE read_point:first SET curve=read_curve:b;',['r6','r9','r10']);
    await run('UPDATE read_reader:r6 SET curve=read_curve:b;',['r6']);
    await run('UPDATE read_reader:r6 SET at=2;',['r6']);
    await run('UPDATE read_curve:b SET initial=8dec;',['r6']);
    await run('UPDATE read_reader:r9 SET disabled=true;',['r9']);
    await run('UPDATE read_curve:a SET initial=10dec;',['r2','r5','r10']);
    await run('UPDATE read_reader:r9 SET disabled=false;',['r9']);
    await run("UPDATE read_reader:r9 SET operation='before';",['r9']);
    await run(create('read_point:early','curve=read_curve:a,at=1,value=2dec'),['r2','r5','r9','r10']);
    await run(create('read_reader:range',"curve=read_curve:a,at=2,until=8,operation='range'"),['range']);
    await run(create('read_reader:prefix',"curve=read_curve:a,at=11,operation='before'"),['prefix']);
    await run(create('read_reader:next',"curve=read_curve:a,at=4,operation='next'"),['next']);
    await run(create('read_reader:exact',"curve=read_curve:a,at=6,operation='exact'"),['exact']);
    await run(create('read_reader:all',"curve=read_curve:a,at=0,operation='summary'"),['all']);
    await run(create('read_point:new','curve=read_curve:a,at=6,value=11dec'),['r10','range','prefix','next','exact','all','r9']);
    await run('UPDATE read_point:new SET value=12dec;',['r10','range','prefix','next','exact','all','r9']);
    await run('UPDATE read_point:new SET at=20;',['r10','range','prefix','next','exact','r9']);
    console.log('Observed reads: prefix/range/exact/successor and moves');
    await run('UPDATE read_reader:r12 SET limit=11dec;', ['r12']);
    await reject('UPDATE read_point:last SET value=6dec;',/READ_PROBE_LIMIT/);
    await run('UPDATE read_reader:r5 SET guard=3dec;', ['r5']);
    await reject('UPDATE read_point:early SET value=4dec;',/READ_PROBE_GUARD/);
    await q(create('read_book:b','base=10dec'));
    await run(create('read_adjustment:a','book=read_book:b,at=3,target=9dec'));
    await run(create('read_adjustment:b','book=read_book:b,at=6,target=12dec'));
    await run(create('read_adjustment:c','book=read_book:b,at=9,target=11dec'));
    await run('UPDATE read_adjustment:a SET target=8dec;');
    await run('UPDATE read_book:b SET base=11dec;');
    await run('UPDATE read_adjustment:a SET at=7;');
    await run('DELETE read_adjustment:a;');
    await run('UPDATE read_adjustment:c SET at=20;');
    console.log('Observed reads: adjustment prefix chains and atomic validators');
    await q(create('read_curve:empty','initial=3dec'));
    await run(create('read_reader:empty',"curve=read_curve:empty,at=2,operation='latest'"),['empty']);
    await run(create('read_point:empty','curve=read_curve:empty,at=1,value=4dec'),['empty']);
    await run('UPDATE read_reader:r12 SET limit=13dec;',['r12']);
    await run(create('read_reader:tie',"curve=read_curve:a,at=11,operation='latest'"),['tie']);
    await run(create('read_point:tie','curve=read_curve:a,at=10,value=5dec'),['prefix','all']);
    await run('UPDATE read_point:tie SET value=6dec;',['r12','tie','prefix','all']);
    await reject('UPDATE read_point:tie SET value=7dec;',/READ_PROBE_LIMIT/);
    await run('DELETE read_point:tie;',['r12','tie','prefix','all']);
    // Many intervals miss the changed point. Verify augmented pruning, not a
    // pair of residual filters that would scan every expired/future reader.
    for(let i=0;i<32;i++) {
      await q(create(`read_reader:past${i}`,`curve=read_curve:a,at=${-100-i},until=${-99-i},operation='range'`));
      await q(create(`read_reader:future${i}`,`curve=read_curve:a,at=${100+i},until=${101+i},operation='range'`));
    }
    await q(create('read_reader:overlap',"curve=read_curve:a,at=19,until=21,operation='range'"));
    const beforeRange=await snapshot(q);
    await run('UPDATE read_point:new SET value=13dec;',['all','overlap']);
    const afterRange=await snapshot(q), count=s=>s.stats.find(row=>row.id==='read_probe_stats:stabs')?.calls??0;
    const rangeVisits=count(afterRange)-count(beforeRange), rangeHeight=afterRange.groups.find(group=>group.kind==='range').z_intervals.height;
    assert(rangeVisits<=4*rangeHeight+10,`interval pruning: ${rangeVisits} visits at height ${rangeHeight}`);
    console.log(`Observed reads: interval pruning ${rangeVisits} visits for 68 ranges`);
    await q("CREATE rebase_tenant:other SET name='Other'; CREATE read_curve:other SET owned_by=rebase_tenant:other,initial=1dec;");
    await reject(create('read_reader:wrong',"curve=read_curve:other,at=2,operation='latest'"),/TENANT|tenant/);
    await reject("RETURN fn::reads::tree({reader:read_reader:r2,tenant:rebase_tenant:default,phase:'refresh',version:1},read_curve:other,'z_points','latest',[[2]],'measures.value.sum',0dec);",/REBASE_READ_TENANT/);
    await q("CREATE rebase_user:reader SET name='Reader',parents=[rebase_tenant:default]; DEFINE ACCESS observed_reader ON DATABASE TYPE RECORD SIGNIN rebase_user:reader;");
    const actor=await recordClient(server.url,'observed_reader');
    await actor(create('read_reader:record_user',"curve=read_curve:a,at=9,operation='latest'")); oracle(await snapshot(q));
    const beforePublic=await snapshot(q);
    assert.equal(Number(await actor("RETURN fn::tree::read_value(read_curve:a,'z_points','latest',[[9]],'measures.value.sum',0dec);")),2);
    assert.deepEqual(await snapshot(q),beforePublic,'ordinary reads do not mutate subscriptions');
    await assert.rejects(actor("RETURN fn::reads::begin(read_reader:r2,'refresh');"),/permission|not allowed/i);
    assert.deepEqual(await actor('SELECT * FROM rebase_read;'),[]);
    await actor("CREATE rebase_read:forged SET reader=read_reader:r2;");
    assert.deepEqual(await snapshot(q),beforePublic,'record user cannot forge metadata');
    // Force registration to pause AFTER its read, before committing its source
    // fence; the concurrent source mutation must conflict or see the new read.
    const raced=q(create('read_reader:race',"curve=read_curve:empty,at=2,operation='latest'"));
    await new Promise(resolve=>setTimeout(resolve,80));
    const sourceRace=q('UPDATE read_point:empty SET value=5dec;');
    const concurrent=await Promise.allSettled([raced,sourceRace]);
    for(const outcome of concurrent.filter(outcome=>outcome.status==='rejected')) assert.match(outcome.reason.message,/transaction|conflict|retry/i);
    assert(concurrent.some(outcome=>outcome.status==='rejected'),'overlapping registration/source mutation conflicts');
    oracle(await snapshot(q));
    await q('DELETE read_reader:race;');
    await run('UPDATE read_point:empty SET value=5dec;');
    console.log('Observed reads: tenant isolation, record permissions and concurrent registration');
    await q(create('read_feedback:a','peer=NONE')+create('read_feedback:b','peer=read_feedback:a'));
    await reject('UPDATE read_feedback:a SET peer=read_feedback:a;',/REBASE_READ_CYCLE/);
    await reject('UPDATE read_feedback:a SET peer=read_feedback:b;',/REBASE_READ_CYCLE/);
    await q(create('read_dates:a','initial=10dec')+create('read_dates:b','initial=20dec'));
    await run(create('read_dated:same',"curve=read_dates:a,at=d'2027-01-06T00:00:00Z'"));
    await run(create('read_quote:first',"curve=read_dates:b,at=d'2027-01-06T00:00:00Z',rate=11dec"));
    await run('UPDATE read_quote:first SET curve=read_dates:a;');
    await run('UPDATE read_quote:first SET rate=12dec;');
    await run('DELETE read_quote:first;');
    await applySchema(q,sql); oracle(await snapshot(q));
    await run('UPDATE read_adjustment:b SET target=13dec;');
    for (const table of ['read_dated','read_quote','read_dates','read_feedback','read_publication','read_observer','read_reader','read_adjustment','read_point','read_book','read_curve']) {
      for (const id of await q(`SELECT VALUE id FROM ${table} ORDER BY id;`)) await q(`DELETE ${id};`);
    }
    const end = await snapshot(q); assert.equal(end.reads.length,0); assert.equal(end.groups.length,0); assert.equal(end.frames.length,0);
    assert(end.locks.every(row => !/\[read_(?:curve|point|book|adjustment|reader|observer):/.test(row.id)), 'no fences on deleted application sources');
    console.log(JSON.stringify({status:'PASS',storage:server.engine,checkpoints,rejections,reapplication:true,cleanup:true}));
  } catch(error) {
    console.error('Failed:',last); console.error('Fixture:',directory);
    if(process.env.REBASE_READ_DEBUG) {
      try { fs.writeFileSync(path.join(directory,'failed-state.json'),JSON.stringify(await snapshot(q),null,2)); }
      catch(snapshotError) { console.error('Snapshot unavailable:',snapshotError.message); }
    }
    throw error;
  } finally { await server.close(); }
}
main().catch(error=>{console.error(error);process.exitCode=1;});

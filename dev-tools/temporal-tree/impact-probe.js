#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { parseSchema } = require('../compiler/schema');
const { start, client, applySchema } = require('./harness');

const at = day => `d'2027-01-${String(day).padStart(2, '0')}T00:00:00Z'`;
const create = (id, fields) => `CREATE ${id} SET owned_by=rebase_tenant:default, ${fields};`;
const snap = q => q(`RETURN {
  curves: (SELECT * FROM impact_curve ORDER BY id), points: (SELECT * FROM impact_point ORDER BY id),
  readers: (SELECT * FROM impact_reader ORDER BY id), observers: (SELECT * FROM impact_observer ORDER BY id),
  totals: (SELECT * FROM impact_total ORDER BY id), visits: (SELECT * FROM impact_visits ORDER BY id)
};`);

// Instrument only this disposable proof. Production schemas contain no counters
// and formulas remain unchanged; each private derive invocation is counted here.
function instrument(bundle) {
  return bundle.replace('DEFINE FUNCTION OVERWRITE fn::rebase::derive(', 'DEFINE FUNCTION OVERWRITE fn::impact_probe::derive(') + `
DEFINE TABLE OVERWRITE impact_visits SCHEMALESS PERMISSIONS NONE;
DEFINE FUNCTION OVERWRITE fn::rebase::derive($row: object) {
    IF record::tb($row.id) IN ['impact_reader', 'impact_observer'] {
        UPSERT type::record('impact_visits', <string>$row.id) SET calls = (calls ?? 0) + 1 RETURN NONE;
    };
    RETURN fn::impact_probe::derive($row);
} PERMISSIONS NONE;`;
}

function oracle(s) {
  let sum = 0;
  for (const reader of s.readers) {
    const curve = s.curves.find(row => row.id === reader.curve);
    const previous = s.points.filter(row => row.curve === curve.id && row.effective_at <= reader.effective_at)
      .sort((a, b) => a.effective_at.localeCompare(b.effective_at)).at(-1);
    const rate = Number(previous?.value ?? curve.initial);
    assert.equal(Number(reader.rate), rate, `${reader.id}: predecessor rate`);
    assert.equal(Number(reader.amount), rate * Number(reader.quantity), `${reader.id}: product`);
    sum += Number(reader.amount);
  }
  assert.equal(Number(s.totals[0].z_history.summary.measures.amount?.sum ?? 0), sum, 'published total');
  for (const row of s.observers) assert.equal(Number(row.amount), Number(s.readers.find(r => r.id === row.source).amount) * 2);
}

async function main() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-impact-proof-'));
  const source = fs.readFileSync(path.join(__dirname, 'impact-fixture.surql'), 'utf8');
  fs.writeFileSync(path.join(directory, 'fixture.surql'), source);
  const compiled = generateBundle(loadMaterials({ groups: [
    { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
    { name: 'project', roots: [directory] },
  ] }));
  assert.throws(() => parseSchema("DEFINE TABLE bad SCHEMAFULL COMMENT '@rebase-impact';", ''), /requires a SurrealQL function/);
  assert.throws(() => parseSchema("DEFINE TABLE bad SCHEMAFULL COMMENT '@rebase-impact fn::one @rebase-impact fn::two';", ''), /Conflicting/);
  const schema = instrument(compiled.bundle);
  const server = await start({ engine: 'surrealkv' }), q = client(server.url);
  let checkpoints = 0, rejections = 0, last;
  const run = async (sql, expectedReaders, expectedObservers) => {
    last = sql;
    const before = await snap(q);
    await q(sql);
    const after = await snap(q); oracle(after); checkpoints++;
    const changed = after.visits.filter(row => row.calls !== before.visits.find(old => old.id === row.id)?.calls)
      .map(row => String(row.id)).sort();
    if (expectedReaders) {
      const actual = changed.filter(id => id.includes('impact_reader:')).map(id => id.match(/impact_reader:([^\]"'`]+)/)[1]).sort();
      assert.deepEqual(actual, expectedReaders.map(String).sort(), 'only readers inside the impact range are evaluated');
      for (const row of after.visits.filter(row => changed.includes(row.id) && row.id.includes('impact_reader:'))) {
        assert.equal(row.calls - (before.visits.find(old => old.id === row.id)?.calls ?? 0), 1,
          'overlapping ranges evaluate each candidate once');
      }
    }
    if (expectedObservers) assert.equal(changed.filter(id => id.includes('impact_observer:')).length, expectedObservers.length,
      'unchanged derived outputs stop direct downstream propagation');
    return after;
  };
  const reject = async (sql, error) => {
    last = sql; const before = await snap(q);
    await assert.rejects(q(sql), error); assert.deepEqual(await snap(q), before, 'entire rejected closure rolls back'); rejections++;
  };
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, schema);
    await q(create('impact_curve:a', 'initial=2dec') + create('impact_curve:b', 'initial=7dec') + create('impact_total:all', '')
      .replace(', ;', ';'));
    await q(create('impact_point:first', `curve=impact_curve:a,effective_at=${at(5)},value=3dec`) +
      create('impact_point:last', `curve=impact_curve:a,effective_at=${at(10)},value=5dec`));
    for (const day of [2, 5, 6, 9, 10, 12]) await q(create(`impact_reader:r${day}`,
      `curve=impact_curve:a,total=impact_total:all,effective_at=${at(day)},quantity=2dec`) +
      create(`impact_observer:o${day}`, `source=impact_reader:r${day}`));
    oracle(await snap(q));
    await run('UPDATE impact_point:first SET value=4dec;', ['r5','r6','r9']);
    await run("UPDATE impact_point:first SET label='no calculation change';", [], []);
    await run(create('impact_point:middle', `curve=impact_curve:a,effective_at=${at(7)},value=4dec`), ['r9'], []);
    await run('UPDATE impact_point:middle SET value=6dec;', ['r9']);
    await run(`UPDATE impact_point:middle SET effective_at=${at(6)};`, ['r6','r9']);
    await run('UPDATE impact_curve:a SET initial=9dec;', ['r2']);
    await run('DELETE impact_point:middle;', ['r6','r9']);
    await run('UPDATE impact_point:first SET curve=impact_curve:b;', ['r5','r6','r9']);
    await run('UPDATE impact_reader:r6 SET curve=impact_curve:b;', ['r6']);
    await run(`UPDATE impact_reader:r6 SET effective_at=${at(2)};`, ['r6']);
    await run('UPDATE impact_curve:b SET initial=8dec;', ['r6']);
    await run('UPDATE impact_reader:r9 SET limit=20dec;', ['r9']);
    await reject('UPDATE impact_curve:a SET initial=11dec;', /IMPACT_PROBE_LIMIT/);
    await reject(create('impact_point:duplicate', `curve=impact_curve:a,effective_at=${at(10)},value=7dec`), /TREE_DUPLICATE_VALUE/);
    await reject(`RETURN fn::tree::affected({rid:impact_curve:a,slot:'z_readers'},[${at(10)}],[${at(2)}]);`, /REBASE_IMPACT_BOUNDS/);
    await q('CREATE rebase_tenant:other SET name="Other"; CREATE impact_curve:other SET owned_by=rebase_tenant:other,initial=1dec;');
    await q(`DEFINE FUNCTION OVERWRITE fn::impact_probe::initial($before: option<object>, $after: option<object>) {
      RETURN [{owner:{rid:impact_curve:other,slot:'z_readers'},lower:NONE,upper:NONE}];
    } PERMISSIONS NONE;`);
    await reject('UPDATE impact_curve:a SET initial=10dec;', /REBASE_IMPACT_TENANT/);
    await applySchema(q, schema); oracle(await snap(q));
    await run('UPDATE impact_curve:a SET initial=10dec;', ['r2','r5','r9']);
    // A source selecting itself is rejected before a recursive refresh starts.
    await q(`DEFINE FUNCTION OVERWRITE fn::rebase::impacts($before: option<object>, $after: option<object>) {
      RETURN IF record::tb($after.id) = 'impact_reader' THEN
        [{owner:{rid:$after.curve,slot:'z_readers'},lower:[$after.effective_at],upper:[$after.effective_at + 1ns]}] ELSE [] END;
    } PERMISSIONS NONE;`);
    await reject('UPDATE impact_reader:r9 SET quantity=1dec;', /REBASE_IMPACT_CYCLE/);
    await q(`DEFINE FUNCTION OVERWRITE fn::rebase::impacts($before: option<object>, $after: option<object>) {
      IF $after.id = impact_reader:r5 { RETURN [{owner:{rid:impact_curve:a,slot:'z_readers'},lower:[${at(9)}],upper:[${at(10)}]}]; };
      IF $after.id = impact_reader:r9 { RETURN [{owner:{rid:impact_curve:a,slot:'z_readers'},lower:[${at(5)}],upper:[${at(6)}]}]; };
      RETURN [];
    } PERMISSIONS NONE;`);
    await reject('UPDATE impact_reader:r9 SET quantity=1dec;', /REBASE_IMPACT_CYCLE/);
    await applySchema(q, schema);
    for (const table of ['impact_observer','impact_reader','impact_point','impact_total','impact_curve']) {
      for (const id of await q(`SELECT VALUE id FROM ${table} ORDER BY id;`)) await q(`DELETE ${id};`);
    }
    console.log(JSON.stringify({ status: 'PASS', storage: server.engine, checkpoints, rejections,
      boundedReaders: true, unchangedOutputStopsCascade: true, reapplication: true, cleanup: true }));
  } catch (error) {
    console.error('Failed statement:', last);
    if (process.env.REBASE_IMPACT_DEBUG) console.error(JSON.stringify(await q(`
      LET $after = SELECT * FROM ONLY impact_point:first;
      LET $before = object::extend($after, {value:3dec});
      RETURN { ranges:fn::rebase::impacts($before,$after), candidates:fn::rebase::impact_records($before,$after),
        value:fn::impact_probe::value_at(impact_curve:a,${at(5)}),
        readers:(SELECT id,rate,amount FROM impact_reader ORDER BY id), visits:(SELECT * FROM impact_visits ORDER BY id) };
    `), null, 2));
    throw error;
  }
  finally { await server.close(); fs.rmSync(directory, { recursive: true, force: true }); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });

#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { classifyMaterials, readMaterialFiles } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('./harness');
const tree = require('./oracle');
const dependency = require('./dependency-oracle');

async function main() {
  const file = path.join(__dirname, 'interval-fixture.surql');
  const materials = classifyMaterials([
    ...readMaterialFiles([{ name: 'framework', roots: [path.resolve(__dirname, '../../framework')] }]),
    { group: 'project', path: file, relative: 'schema.surql', source: fs.readFileSync(file, 'utf8') },
  ]);
  const compiled = generateBundle(materials, { context: { namespace: 'temporal_probe', database: 'fixture' } });
  const server = await start();
  const q = client(server.url);
  let checkpoints = 0;
  try {
    await applySchema(q, compiled.bundle);
    await q("CREATE interval_book:a SET owned_by=rebase_tenant:default;");
    await q('CREATE interval_reader:summary SET owned_by=rebase_tenant:default,book=interval_book:a;');
    const rows = new Map();
    const snapshot = () => q('RETURN {books:(SELECT * FROM interval_book ORDER BY id),items:(SELECT * FROM interval_item ORDER BY id),readers:(SELECT * FROM interval_reader ORDER BY id)};');
    const verify = async () => {
      const intervals = [...rows].flatMap(([id, row]) => [
        { id, slot: 'z_range', lower: row.lower, upper: row.upper, amount: row.amount },
        ...(row.extra_amount == null ? [] : [{ id, slot: 'z_extra', lower: row.lower, upper: row.extra_upper, amount: row.extra_amount }]),
      ]);
      const entries = intervals.map(row => ({
        link: { rid: `interval_item:${row.id}`, slot: row.slot },
        owner: { rid: 'interval_book:a', slot: 'z_ranges' },
        key: [row.lower, `interval_item:${row.id}`, row.slot],
        measures: { amount: row.amount }, interval: { upper: row.upper == null ? undefined : [row.upper] },
      }));
      const data = await snapshot();
      const queries = data.readers.flatMap(reader => [
        { field: 'q_measures', path: 'measures', fallback: {} },
        { field: 'q_upper', path: 'interval.upper', fallback: [] },
      ].map(query => ({ ...query, reader: reader.id, source: reader.book, source_slot: 'z_ranges',
        phase: 'refresh', kind: 'range', arguments: [null, null] })));
      const reverse = dependency.verifyDependencies([...data.books, ...data.items, ...data.readers], entries, queries,
        compiled.temporalModel.dependencyModel);
      tree.verify(data.books, [...data.items, ...data.readers], [...entries, ...reverse], dependency.compare);
      for (const query of queries) {
        const reader = data.readers.find(row => row.id === query.reader);
        dependency.equalValue(reader[query.field.slice(2)], dependency.answer(query, entries), `${reader.id}.${query.field}`);
      }
      for (const point of [-21, -10, 0, 1, 4, 7, 10, 20, 100]) {
        const actual = await q(`RETURN fn::tree::read(interval_book:a,'z_ranges','intervals',[${point}]).map(|$link| <string>$link.rid + '/' + $link.slot);`);
        const expected = intervals.filter(row => row.lower <= point && (row.upper == null || point < row.upper))
          .sort((a, b) => a.lower - b.lower || a.id.localeCompare(b.id) || a.slot.localeCompare(b.slot))
          .map(row => `interval_item:${row.id}/${row.slot}`);
        assert.deepEqual(actual, expected, `interval matches at ${point}`);
      }
      const [full, prefix, suffix, summary] = await q(`RETURN [
        fn::tree::read(interval_book:a,'z_ranges','range',[NONE,NONE]),
        fn::tree::read(interval_book:a,'z_ranges','range',[NONE,[7]]),
        fn::tree::read(interval_book:a,'z_ranges','range',[[7],NONE]),
        fn::tree::read(interval_book:a,'z_ranges','summary',[])];`);
      assert.deepEqual(full, summary, 'unbounded range is the complete summary');
      assert.equal(Number(full.measures.amount?.sum ?? 0), intervals.reduce((sum, row) => sum + row.amount, 0));
      assert.equal(Number(prefix.measures.amount?.sum ?? 0), intervals.filter(row => row.lower < 7).reduce((sum, row) => sum + row.amount, 0));
      assert.equal(Number(suffix.measures.amount?.sum ?? 0), intervals.filter(row => row.lower >= 7).reduce((sum, row) => sum + row.amount, 0));
      if (intervals.length) {
        const upper = intervals.some(row => row.upper == null) ? undefined : Math.max(...intervals.map(row => row.upper));
        assert.deepEqual(full.interval.upper, upper === undefined ? undefined : [upper], 'interval maximum including infinity');
      }
      checkpoints++;
    };
    await verify();
    for (const [id, lower, upper, amount] of [['a', 0, 10, 2], ['b', -10, 1, 3], ['c', 7, null, 5], ['d', 0, 4, 7], ['e', 20, 30, 11]]) {
      await q(`CREATE interval_item:${id} SET owned_by=rebase_tenant:default,book=interval_book:a,lower=${lower},upper=${upper ?? 'NONE'},amount=${amount}dec;`);
      rows.set(id, { lower, upper, amount }); await verify();
      if (id === 'a') {
        await q('UPDATE interval_item:a SET upper=12;');
        rows.get('a').upper = 12; await verify();
        await q('UPDATE interval_item:a SET amount=4dec;');
        rows.get('a').amount = 4; await verify();
      }
    }
    // Equal lower bounds on one record must retain both interval identities.
    await q('UPDATE interval_item:a SET extra_upper=4,extra_amount=13dec;');
    Object.assign(rows.get('a'), { extra_upper: 4, extra_amount: 13 }); await verify();
    await q('UPDATE interval_item:a SET extra_upper=NONE;');
    rows.get('a').extra_upper = null; await verify();
    await q('UPDATE interval_item:a SET extra_amount=NONE;');
    rows.get('a').extra_amount = null; await verify();
    await q('UPDATE interval_item:c SET lower=-20,upper=8;'); rows.set('c', { lower: -20, upper: 8, amount: 5 }); await verify();
    const before = await snapshot();
    await assert.rejects(q('UPDATE interval_item:a SET upper=-1;'), /TREE_INTERVAL_BOUNDS/);
    assert.deepEqual(await snapshot(), before, 'invalid bound rolls back the complete index');
    for (const id of ['a', 'c', 'b', 'e', 'd']) { await q(`DELETE interval_item:${id};`); rows.delete(id); await verify(); }
    await q('DELETE interval_reader:summary;'); await verify();
    await q('DELETE interval_book:a;');
    console.log(JSON.stringify({ status: 'PASS', checkpoints, rollbackChecks: 1, cleanup: true }));
  } finally { await server.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };

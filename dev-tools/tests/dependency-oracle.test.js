'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { verifyDependencies, answer, compare } = require('../temporal-tree/dependency-oracle');
const source = { table: 'series', slot: 'points', index: '__rebase_dependents_points_range', kind: 'range' };
const declarations = ['first', 'second'].map(field => ({ table: 'reader', field, node: `__rebase_dependency_${field}`,
  kind: 'range', phase: 'refresh', sources: [source] }));
const model = { declarations, groups: [source] };
const expected = declarations.map(({ field }) => ({ reader: 'reader:one', field, source: 'series:one', source_slot: 'points',
  kind: 'range', phase: 'refresh', arguments: [null, [4]], path: 'count', fallback: 0 }));
function fixture() {
  return [{ id: 'series:one', [source.index]: { summary: { count: 2 } } },
    { id: 'reader:one', ...Object.fromEntries(declarations.flatMap(({ field, node }) => [
      [field, { source: 'series:one', source_slot: 'points', index: source.index, kind: 'range', phase: 'refresh',
        arguments: [null, [4]], path: 'count', fallback: { value: 0 }, result: { value: 0 } }], [node, {}],
    ])) }];
}
test('fixed-slot oracle preserves identical queries in distinct named roles', () => {
  const entries = verifyDependencies(fixture(), [], expected, model);
  assert.equal(entries.length, 2);
  assert.notEqual(entries[0].link.slot, entries[1].link.slot);
  assert.deepEqual(entries.map(entry => entry.interval.upper), [[[4]], [[4]]]);
});
test('oracle rejects missing descriptors, nodes and empty reverse roots independently of tree consistency', () => {
  for (const field of ['first', '__rebase_dependency_first']) {
    const rows = fixture(); delete rows[1][field];
    assert.throws(() => verifyDependencies(rows, [], expected, model), /expected .*present/);
  }
  assert.throws(() => verifyDependencies([{ id: 'series:one' }], [], [], model), /reverse root exists/);
  const rows = fixture(); rows[1].first.arguments = [null, [5]];
  assert.throws(() => verifyDependencies(rows, [], expected, model), /first.arguments/);
});
test('oracle distinguishes full-key boundaries and uses linear range answers', () => {
  const entries = [1, 2, 2, 5].map((at, i) => ({link:{rid:`point:${i}`,slot:'node'},owner:{rid:'series:one',slot:'points'},
    key:[at,`point:${i}`,'node'],measures:{amount:i+1},tags:{}}));
  const query = { source:'series:one',source_slot:'points',kind:'range',arguments:[null,[2]],path:'measures.amount.sum',fallback:0 };
  assert.equal(answer(query,entries), 1);
  assert.equal(answer({...query,arguments:[[2],null]},entries), 9);
  assert.equal(answer({...query,arguments:[[2],[2]]},entries), 0);
  assert(compare([[2], 'reader:a'], [[2, 'point:a'], 'reader:a']) < 0);
});

function valueFixture(amounts, actualValue) {
  const rows = fixture();
  const queries = expected.map(query => ({ ...query, path: 'measures.amount.sum' }));
  for (const { field, path } of queries) {
    rows[1][field].path = path;
    rows[1][field].result.value = actualValue;
  }
  const entries = amounts.map((amount, i) => ({
    link: { rid: `point:${i}`, slot: 'node' }, owner: { rid: 'series:one', slot: 'points' },
    key: [1, `point:${i}`, 'node'], measures: { amount }, tags: {},
  }));
  return { rows, check: options => verifyDependencies(rows, entries, queries, model, options) };
}

test('dependency answers use strict numeric equality by default', () => {
  const value = valueFixture([100.1, 52.01], 152.11);
  assert.throws(() => value.check(), /first.result.value/);
  for (const { field } of declarations) value.rows[1][field].result.value = 100.1 + 52.01;
  value.check();
  delete value.rows[1].first.result;
  assert.throws(() => value.check(), /first.result: result object exists/);
});

test('explicit demo comparison accepts binary roundoff only in query results', () => {
  const { equal } = require('../temporal-tree/oracle');
  const options = { equalResult: equal };
  const value = valueFixture([100.1, 52.01], 152.11);
  value.check(options);
  value.rows[1].first.result.value = 152.12;
  assert.throws(() => value.check(options), /first.result.value/);
  value.rows[1].first.result.value = 152.11;
  value.rows[1].first.arguments = [null, [4.0000000000001]];
  assert.throws(() => value.check(options), /first.arguments/);
});

test('default rational dependency answers reject an 18-place discrepancy', () => {
  const { D } = require('../accounting/source-oracle');
  const { linearSummary } = require('../temporal-tree/exact-oracle');
  const value = valueFixture([new D('100.1'), new D('52.01')], '152.11');
  const options = { Decimal: D, summarize: entries => linearSummary(entries, D, compare) };
  value.check(options);
  value.rows[1].first.result.value = '152.110000000000000001';
  assert.throws(() => value.check(options), /first.result.value/);
});

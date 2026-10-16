'use strict';

const assert = require('node:assert/strict');
const { scan } = require('./oracle');
const { instant } = require('./harness');

const tableOf = id => id.slice(0, id.indexOf(':'));
const identity = (reader, field) => `${reader}/${field}`;
const project = (value, path) => path ? path.split('.').reduce((row, key) => row?.[key], value) : value;

function compare(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      const result = compare(a[i], b[i]);
      if (result) return result;
    }
    return a.length - b.length;
  }
  const date = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT/.test(value);
  const x = date(a) ? instant(a) : a, y = date(b) ? instant(b) : b;
  return x < y ? -1 : x > y ? 1 : 0;
}

function equalValue(actual, expected, label, Decimal) {
  if (Decimal && expected instanceof Decimal) {
    assert(actual != null, `${label}: decimal exists`);
    assert.equal(new Decimal(actual).cmp(expected), 0, label);
  } else if (typeof expected === 'number') {
    assert(actual != null, `${label}: number exists`);
    assert.equal(Number(actual), expected, label);
  } else if (Array.isArray(expected)) {
    assert(Array.isArray(actual), `${label}: array exists`);
    assert.equal(actual.length, expected.length, `${label}: length`);
    expected.forEach((value, index) => equalValue(actual[index], value, `${label}[${index}]`, Decimal));
  } else if (expected && typeof expected === 'object') {
    const keys = value => Object.keys(value || {}).filter(key => value[key] != null).sort();
    assert.deepEqual(keys(actual), keys(expected), `${label}: keys`);
    for (const key of keys(expected)) equalValue(actual[key], expected[key], `${label}.${key}`, Decimal);
  } else if (typeof expected === 'string' && /^\d{4}-\d\d-\d\dT/.test(expected)) {
    assert.equal(instant(actual), instant(expected), label);
  } else {
    assert.deepEqual(actual ?? null, expected ?? null, label);
  }
}

// Deliberately derive answers by scanning independently reconstructed source
// contributions. Maintained descriptors, links and summaries supply no expectations.
function answer(query, entries, compareKeys = compare, summarize = values => scan(values, compareKeys)) {
  const ordered = entries.filter(entry => entry.owner.rid === query.source && entry.owner.slot === query.source_slot)
    .sort((a, b) => compareKeys(a.key, b.key));
  let result;
  if (query.kind === 'range') {
    const [lower, upper] = query.arguments;
    result = summarize(ordered.filter(entry => (lower == null || compareKeys(entry.key, lower) >= 0)
      && (upper == null || compareKeys(entry.key, upper) < 0)));
  } else {
    const key = query.kind === 'exact' ? query.arguments : query.arguments[0];
    const inclusive = query.arguments[1] ?? false;
    const found = query.kind === 'exact'
      ? ordered.find(entry => compareKeys(entry.key.slice(0, -2), key) === 0)
      : query.kind === 'latest'
        ? ordered.filter(entry => compareKeys(entry.key, key) < 0 || inclusive && compareKeys(entry.key, key) === 0).at(-1)
        : ordered.find(entry => compareKeys(entry.key, key) > 0 || inclusive && compareKeys(entry.key, key) === 0);
    if (found) result = { ...summarize([found]), record: found.link.rid, key: found.key };
  }
  return project(result, query.path) ?? query.fallback;
}

function verifyDependencies(rows, entries, expectedQueries, model, options = {}) {
  assert(model, 'dependency declaration metadata is required');
  const { Decimal, rootSpecs = [], summarize, equalResult = equalValue } = options;
  const compareKeys = options.compare || compare;
  const byId = new Map(rows.map(row => [row.id, row]));
  const expected = new Map();
  for (const query of expectedQueries) {
    const id = identity(query.reader, query.field);
    assert(!expected.has(id), `${id}: one expectation per declared role`);
    expected.set(id, query);
  }
  const indexes = [], visited = new Set();
  for (const row of rows) {
    for (const group of model.groups || []) if (group.table === tableOf(row.id)) {
      assert(row[group.index]?.summary, `${row.id}.${group.index}: reverse root exists even when empty`);
    }
    for (const root of rootSpecs.filter(root => root.table === tableOf(row.id))) {
      assert(row[root.slot]?.summary, `${row.id}.${root.slot}: declared root exists`);
    }
    const declarations = model.declarations.filter(item => item.table === tableOf(row.id));
    for (const declaration of declarations) {
      const id = identity(row.id, declaration.field), query = expected.get(id), actual = row[declaration.field];
      visited.add(id);
      if (!query) {
        assert(actual == null, `${id}: disabled query has no descriptor`);
        assert(row[declaration.node] == null, `${id}: disabled query has no index node`);
        continue;
      }
      assert(actual, `${id}: expected descriptor is present`);
      assert(byId.has(query.source), `${id}: source exists`);
      assert.equal(query.kind, declaration.kind, `${id}: authored operation`);
      assert.equal(query.phase, declaration.phase, `${id}: authored phase`);
      const source = declaration.sources.find(item => item.table === tableOf(query.source) && item.slot === query.source_slot);
      assert(source, `${id}: declared source root`);
      const result = answer(query, entries, compareKeys, summarize);
      const { result: actualResult, ...descriptor } = actual;
      equalValue(descriptor, { source: query.source, source_slot: query.source_slot, index: source.index,
        kind: query.kind, phase: query.phase, arguments: query.arguments, path: query.path,
        fallback: { value: query.fallback } }, id, Decimal);
      assert(actualResult && typeof actualResult === 'object' && !Array.isArray(actualResult), `${id}.result: result object exists`);
      // Numeric demo oracles may allow transport roundoff in answers only.
      // Descriptor keys/bounds and the default rational accounting check stay exact.
      equalResult(actualResult, { value: result }, `${id}.result`, Decimal);
      const [lower, upper] = query.arguments;
      if (query.kind === 'range' && lower != null && upper != null && compareKeys(lower, upper) >= 0) {
        assert(row[declaration.node] == null, `${id}: empty interval has no index node`);
        continue;
      }
      assert(row[declaration.node], `${id}: expected fixed index node is present`);
      const position = query.kind === 'range' ? lower ?? [] : query.kind === 'exact' ? query.arguments : lower;
      indexes.push({ link: { rid: row.id, slot: declaration.node }, owner: { rid: query.source, slot: source.index },
        key: [position, row.id, declaration.node], measures: {}, tags: {},
        ...(query.kind === 'range' ? { interval: { upper: upper == null ? null : [upper] } } : {}) });
    }
    for (const slot of Object.keys(row).filter(key => key.startsWith('__rebase_dependency_'))) {
      assert(declarations.some(declaration => declaration.node === slot), `${row.id}.${slot}: declared index slot`);
    }
  }
  for (const id of expected.keys()) assert(visited.has(id), `${id}: expected reader and declaration exist`);
  return indexes;
}

module.exports = { compare, equalValue, answer, verifyDependencies };

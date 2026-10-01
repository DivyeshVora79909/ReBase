'use strict';
const assert = require('node:assert/strict');
const { compareKey } = require('./harness');
const identity = (link) => link ? `${link.rid}/${link.slot}` : null;
const empty = () => ({ count: 0, dependents: 0, measures: {}, tags: {}, spans: {} });

// Reconstruct the ordered sequence from source facts, not maintained node state.
// This intentionally scans; it is an independent verification oracle.
function scan(entries) {
  const result = empty();
  const timestamps = [];
  for (const entry of entries) {
    result.count++;
    result.dependents += entry.dependent ? 1 : 0;
    result.first ??= entry.key;
    result.last = entry.key;
    const primary = entry.key[0];
    let timestamp = timestamps.at(-1);
    if (!timestamp || !Object.is(timestamp.primary, primary)) {
      timestamp = { primary, measures: {} };
      timestamps.push(timestamp);
    }
    for (const [key, amount] of Object.entries(entry.measures)) {
      const metric = result.measures[key] ||= { sum: 0, min_prefix: 0, max_prefix: 0, min: amount, max: amount };
      metric.sum += amount;
      metric.min_prefix = Math.min(metric.min_prefix, metric.sum);
      metric.max_prefix = Math.max(metric.max_prefix, metric.sum);
      metric.min = Math.min(metric.min, amount);
      metric.max = Math.max(metric.max, amount);
      timestamp.measures[key] = (timestamp.measures[key] || 0) + Number(amount);
    }
    for (const [key, value] of Object.entries(entry.tags || {})) {
      const tag = result.tags[key] ||= { value, uniform: true };
      tag.uniform &&= tag.value === value;
    }
    for (const [key, date] of Object.entries(entry.spans || {})) {
      const span = result.spans[key] ||= { min: date, max: date };
      if (compareKey([date], [span.min]) < 0) span.min = date;
      if (compareKey([date], [span.max]) > 0) span.max = date;
    }
  }
  for (const [key, metric] of Object.entries(result.measures)) {
    let balance = 0;
    const boundaries = [];
    for (let i = 0; i < timestamps.length; i++) {
      balance += timestamps[i].measures[key] || 0;
      if (i < timestamps.length - 1) boundaries.push(balance);
    }
    if (boundaries.length) {
      metric.boundary_min = Math.min(...boundaries);
      metric.boundary_max = Math.max(...boundaries);
    } else {
      metric.boundary_min = null;
      metric.boundary_max = null;
    }
    metric.instant_min = Math.min(0, balance, ...boundaries);
    metric.instant_max = Math.max(0, balance, ...boundaries);
  }
  return result;
}

function equal(actual, expected, label = '') {
  // Keys (including safely transported int extremes) must compare exactly.
  // Decimal measure checks below deliberately allow transport roundoff.
  if (Array.isArray(expected)) {
    assert.deepEqual(actual, expected, label);
    return;
  }
  if (typeof expected === 'number') {
    assert(Math.abs(Number(actual) - expected) <= Math.max(1e-10, Math.abs(expected) * 1e-12), `${label}: ${actual} != ${expected}`);
    return;
  }
  if (expected && typeof expected === 'object') {
    const keys = value => Object.keys(value || {}).filter(key =>
      !['boundary_min', 'boundary_max'].includes(key) || value[key] != null).sort();
    const actualKeys = keys(actual), expectedKeys = keys(expected);
    assert.deepEqual(actualKeys, expectedKeys, `${label}: keys`);
    for (const key of expectedKeys) equal(actual[key], expected[key], `${label}.${key}`);
    return;
  }
  assert.deepEqual(actual, expected, label);
}

function verify(owners, records, entries, compare = compareKey) {
  const byRecord = new Map(records.map((r) => [r.id, r]));
  const groups = new Map(owners.flatMap((owner) => Object.entries(owner)
    .filter(([name, value]) => value && typeof value === 'object' && Object.hasOwn(value, 'revision') && Object.hasOwn(value, 'summary'))
    .map(([slot, head]) => [identity({ rid: owner.id, slot }), { owner: { rid: owner.id, slot }, head, entries: [] }])));
  for (const entry of entries) {
    const group = groups.get(identity(entry.owner));
    assert(group, `missing owner for ${identity(entry.link)}`);
    group.entries.push(entry);
  }
  const expectedSlots = new Set(entries.map((e) => identity(e.link)));
  for (const row of records) {
    for (const [slot, node] of Object.entries(row)) {
      if (node && typeof node === 'object' && node.owner && node.key && node.summary) {
        assert(expectedSlots.has(identity({ rid: row.id, slot })), `orphan membership ${row.id}/${slot}`);
      }
    }
  }
  for (const [name, group] of groups) {
    const ordered = group.entries.sort((a, b) => compare(a.key, b.key));
    const byLink = new Map(ordered.map((entry) => [identity(entry.link), entry]));
    const seen = new Set();
    function visit(link, parent, lower, upper) {
      if (!link) return { height: 0, entries: [] };
      const id = identity(link);
      assert(!seen.has(id), `cycle/shared child ${id}`);
      seen.add(id);
      const entry = byLink.get(id);
      assert(entry, `unexpected member ${id}`);
      const node = byRecord.get(link.rid)?.[link.slot];
      assert(node, `dangling link ${id}`);
      assert.deepEqual(node.parent, parent, `parent ${id}`);
      assert.deepEqual(node.owner, group.owner, `owner ${id}`);
      equal(node.key, entry.key, `key ${id}`);
      if (lower) assert(compare(lower, node.key) < 0);
      if (upper) assert(compare(node.key, upper) < 0);
      equal(node.value, scan([entry]), `leaf ${id}`);
      const left = visit(node.left, link, lower, node.key);
      const right = visit(node.right, link, node.key, upper);
      assert(Math.abs(left.height - right.height) <= 1, `balance ${id}`);
      const height = Math.max(left.height, right.height) + 1;
      assert.equal(node.height, height, `height ${id}`);
      const sequence = [...left.entries, entry, ...right.entries];
      equal(node.summary, scan(sequence), `summary ${id}`);
      return { height, entries: sequence };
    }
    const tree = visit(group.head.root, group.owner);
    assert.equal(tree.entries.length, ordered.length, `reachability ${name}`);
    assert.equal(group.head.height, tree.height, `root height ${name}`);
    assert.equal(group.head.refreshing, false, `stuck refresh ${name}`);
    assert.equal(group.head.dirty, undefined, `unprocessed invalidation ${name}`);
    assert.equal(group.head.cursor, undefined, `stale cursor ${name}`);
    equal(group.head.summary, scan(ordered), `published ${name}`);
    ordered.forEach((entry, i) => {
      const node = byRecord.get(entry.link.rid)[entry.link.slot];
      assert.deepEqual(node.prev || null, ordered[i - 1]?.link || null, `previous ${identity(entry.link)}`);
      assert.deepEqual(node.next || null, ordered[i + 1]?.link || null, `next ${identity(entry.link)}`);
    });
  }
  return groups;
}
module.exports = { identity, empty, scan, equal, verify };

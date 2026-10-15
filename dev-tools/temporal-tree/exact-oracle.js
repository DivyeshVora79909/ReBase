'use strict';

const assert = require('node:assert/strict');

const identity = link => link ? `${link.rid}/${link.slot}` : null;
const stable = value => {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().filter(key => value[key] !== undefined)
    .map(key => [key, stable(value[key])]));
};

// Independent linear fold over source-expected entries. It deliberately does
// not use tree shape or combine the production summaries.
function linearSummary(entries, Decimal, compare) {
  const result = { count: 0, dependents: 0, measures: {}, tags: {}, spans: {} };
  const timestamps = [];
  for (const entry of entries) {
    result.count++;
    result.dependents += entry.dependent ? 1 : 0;
    result.first ??= entry.key;
    result.last = entry.key;
    const primary = entry.key[0];
    let timestamp = timestamps.at(-1);
    if (!timestamp || compare([timestamp.primary], [primary]) !== 0) {
      timestamp = { primary, measures: {} };
      timestamps.push(timestamp);
    }
    for (const [key, value] of Object.entries(entry.measures || {})) {
      const amount = new Decimal(value);
      const metric = result.measures[key] ||= {
        sum: new Decimal(0), min_prefix: new Decimal(0), max_prefix: new Decimal(0),
        min: amount, max: amount,
      };
      metric.sum = metric.sum.add(amount);
      if (metric.sum.cmp(metric.min_prefix) < 0) metric.min_prefix = metric.sum;
      if (metric.sum.cmp(metric.max_prefix) > 0) metric.max_prefix = metric.sum;
      if (amount.cmp(metric.min) < 0) metric.min = amount;
      if (amount.cmp(metric.max) > 0) metric.max = amount;
      timestamp.measures[key] = (timestamp.measures[key] || new Decimal(0)).add(amount);
    }
    for (const [key, value] of Object.entries(entry.tags || {})) {
      if (value == null) continue;
      const tag = result.tags[key] ||= { value, uniform: true };
      tag.uniform &&= tag.value === value;
    }
    for (const [key, value] of Object.entries(entry.spans || {})) {
      if (value == null) continue;
      const span = result.spans[key] ||= { min: value, max: value };
      if (compare([value], [span.min]) < 0) span.min = value;
      if (compare([value], [span.max]) > 0) span.max = value;
    }
  }

  for (const [key, metric] of Object.entries(result.measures)) {
    const balance = new Decimal(0), boundaries = [], instants = [new Decimal(0)];
    let running = balance;
    for (let index = 0; index < timestamps.length; index++) {
      running = running.add(timestamps[index].measures[key] || new Decimal(0));
      instants.push(running);
      if (index < timestamps.length - 1) boundaries.push(running);
    }
    if (boundaries.length) {
      metric.boundary_min = boundaries.reduce((a, b) => a.cmp(b) <= 0 ? a : b);
      metric.boundary_max = boundaries.reduce((a, b) => a.cmp(b) >= 0 ? a : b);
    }
    metric.instant_min = instants.reduce((a, b) => a.cmp(b) <= 0 ? a : b);
    metric.instant_max = instants.reduce((a, b) => a.cmp(b) >= 0 ? a : b);
  }
  return result;
}

function equalSummary(actual, expected, label, Decimal) {
  assert(actual && typeof actual === 'object', `${label}: summary object exists`);
  assert.equal(actual.count, expected.count, `${label}.count`);
  assert.equal(actual.dependents, expected.dependents, `${label}.dependents`);
  assert.deepEqual(actual.first ?? null, expected.first ?? null, `${label}.first`);
  assert.deepEqual(actual.last ?? null, expected.last ?? null, `${label}.last`);
  assert.deepEqual(stable(actual.tags || {}), stable(expected.tags), `${label}.tags`);
  assert.deepEqual(stable(actual.spans || {}), stable(expected.spans), `${label}.spans`);
  const actualMeasures = actual.measures || {};
  assert.deepEqual(Object.keys(actualMeasures).sort(), Object.keys(expected.measures).sort(), `${label}.measures`);
  for (const [name, wanted] of Object.entries(expected.measures)) {
    const got = actualMeasures[name];
    const metricLabel = `${label}.measures.${name}`;
    assert(got && typeof got === 'object', `${metricLabel}: metric exists`);
    const present = value => value !== undefined && value !== null;
    const gotKeys = Object.keys(got).filter(key => !key.startsWith('boundary_') || present(got[key])).sort();
    const expectedKeys = Object.keys(wanted).sort();
    assert.deepEqual(gotKeys, expectedKeys, `${metricLabel}: exact fields`);
    for (const key of expectedKeys) {
      const found = got[key];
      const expectedValue = wanted[key];
      assert(found !== undefined && found !== null, `${metricLabel}.${key}: value exists`);
      assert.equal(new Decimal(found).cmp(expectedValue), 0,
        `${metricLabel}.${key}: ${found} != ${expectedValue.number()}`);
    }
  }
}

function verify(owners, records, entries, compare, Decimal) {
  const byRecord = new Map(records.map(row => [row.id, row]));
  const groups = new Map(owners.flatMap(owner => Object.entries(owner)
    .filter(([, value]) => value && typeof value === 'object'
      && Object.hasOwn(value, 'revision') && Object.hasOwn(value, 'summary'))
    .map(([slot, head]) => [identity({ rid: owner.id, slot }), { owner: { rid: owner.id, slot }, head, entries: [] }])));
  for (const entry of entries) {
    const group = groups.get(identity(entry.owner));
    assert(group, `missing exact-summary owner for ${identity(entry.link)}`);
    group.entries.push(entry);
  }

  for (const [name, group] of groups) {
    const ordered = group.entries.sort((a, b) => compare(a.key, b.key));
    const byLink = new Map(ordered.map(entry => [identity(entry.link), entry]));
    const seen = new Set();
    function visit(link, parent) {
      if (link == null) return { entries: [] };
      const id = identity(link);
      assert(!seen.has(id), `${id}: exact-summary tree has a cycle/shared child`);
      seen.add(id);
      const entry = byLink.get(id), row = byRecord.get(link.rid), node = row?.[link.slot];
      assert(entry && node, `${id}: exact-summary member exists`);
      assert.deepEqual(node.parent ?? null, parent, `${id}: exact-summary parent`);
      assert.deepEqual(node.owner, group.owner, `${id}: exact-summary owner`);
      assert.deepEqual(node.key, entry.key, `${id}: exact-summary key`);
      const left = visit(node.left, link), right = visit(node.right, link);
      const sequence = [...left.entries, entry, ...right.entries];
      equalSummary(node.value, linearSummary([entry], Decimal, compare), `${id}.value`, Decimal);
      equalSummary(node.summary, linearSummary(sequence, Decimal, compare), `${id}.summary`, Decimal);
      return { entries: sequence };
    }

    const result = visit(group.head.root, group.owner);
    assert.equal(seen.size, ordered.length, `${name}: exact-summary reachability`);
    equalSummary(group.head.summary, linearSummary(result.entries, Decimal, compare), `${name}.published`, Decimal);
  }
}

module.exports = { linearSummary, equalSummary, verify };

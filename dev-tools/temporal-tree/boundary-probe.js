#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const oracle = require('./oracle');
const { setup, snapshot, verify } = require('./positions-probe');

function product(values, length) {
  if (length === 0) return [[]];
  return values.flatMap(value => product(values, length - 1).map(rest => [value, ...rest]));
}

function empty() {
  return { count: 0, first: null, last: null, sum: 0, instant_min: 0, instant_max: 0 };
}

function singleton(event) {
  const key = [event.time, event.id, 'slot'];
  const result = { count: 1, first: key, last: key };
  if (event.delta !== null) Object.assign(result, {
    sum: event.delta,
    instant_min: Math.min(0, event.delta), instant_max: Math.max(0, event.delta),
  });
  return result;
}

// Independent scalar model of the complete-primary-boundary algebra.
function combine(a, b) {
  if (a.count === 0) return b;
  if (b.count === 0) return a;
  const hasLeft = Object.hasOwn(a, 'sum'), hasRight = Object.hasOwn(b, 'sum');
  const result = { count: a.count + b.count, first: a.first, last: b.last };
  if (!hasLeft && !hasRight) return result;
  const leftSum = hasLeft ? a.sum : 0, rightSum = hasRight ? b.sum : 0;
  const leftMin = hasLeft ? a.boundary_min ?? (a.first[0] < a.last[0] ? 0 : undefined)
    : (a.first[0] < a.last[0] ? 0 : undefined);
  const leftMax = hasLeft ? a.boundary_max ?? (a.first[0] < a.last[0] ? 0 : undefined)
    : (a.first[0] < a.last[0] ? 0 : undefined);
  const rightMin = hasRight ? b.boundary_min ?? (b.first[0] < b.last[0] ? 0 : undefined)
    : (b.first[0] < b.last[0] ? 0 : undefined);
  const rightMax = hasRight ? b.boundary_max ?? (b.first[0] < b.last[0] ? 0 : undefined)
    : (b.first[0] < b.last[0] ? 0 : undefined);
  const sum = leftSum + rightSum;
  const candidatesMin = [leftMin, rightMin === undefined ? undefined : leftSum + rightMin,
    a.last[0] < b.first[0] ? leftSum : undefined].filter(value => value !== undefined);
  const candidatesMax = [leftMax, rightMax === undefined ? undefined : leftSum + rightMax,
    a.last[0] < b.first[0] ? leftSum : undefined].filter(value => value !== undefined);
  const boundaryMin = candidatesMin.length ? Math.min(...candidatesMin) : undefined;
  const boundaryMax = candidatesMax.length ? Math.max(...candidatesMax) : undefined;
  Object.assign(result, {
    sum,
    instant_min: Math.min(0, sum, boundaryMin ?? Infinity),
    instant_max: Math.max(0, sum, boundaryMax ?? -Infinity),
  });
  if (boundaryMin !== undefined) result.boundary_min = boundaryMin;
  if (boundaryMax !== undefined) result.boundary_max = boundaryMax;
  return result;
}

function direct(events) {
  const groups = [];
  const hasMetric = events.some(event => event.delta !== null);
  for (const event of events) {
    let group = groups.at(-1);
    if (!group || group.time !== event.time) groups.push(group = { time: event.time, delta: 0 });
    if (event.delta !== null) group.delta += event.delta;
  }
  const result = {
    count: events.length,
    first: [events[0].time, events[0].id, 'slot'],
    last: [events.at(-1).time, events.at(-1).id, 'slot'],
  };
  if (!hasMetric) return result;
  let sum = 0;
  const boundaries = [];
  for (let i = 0; i < groups.length; i++) {
    sum += groups[i].delta;
    if (i < groups.length - 1) boundaries.push(sum);
  }
  Object.assign(result, {
    sum,
    instant_min: Math.min(0, sum, ...boundaries),
    instant_max: Math.max(0, sum, ...boundaries),
  });
  if (boundaries.length) {
    result.boundary_min = Math.min(...boundaries);
    result.boundary_max = Math.max(...boundaries);
  }
  return result;
}

function checkMissingMetrics() {
  let sequences = 0, folds = 0;
  for (let length = 1; length <= 4; length++) {
    for (const values of product([null, -2, 3], length)) {
      for (const intervals of product([0, 1], length - 1)) {
        const times = [0];
        for (const gap of intervals) times.push(times.at(-1) + gap);
        const events = values.map((delta, i) => ({ time: times[i], id: `m${i}`, delta }));
        const expected = direct(events);
        for (const summary of allFolds(events)) {
          assert.deepEqual(summary, expected, `missing-measure associativity: ${JSON.stringify(events)}`);
          assert.deepEqual(combine(empty(), summary), expected, 'missing-measure left identity');
          assert.deepEqual(combine(summary, empty()), expected, 'missing-measure right identity');
          folds++;
        }
        sequences++;
      }
    }
  }
  console.log(`PASS missing-measure boundary algebra: ${sequences} sequences, ${folds} binary folds and identities`);
}

function allFolds(events) {
  if (events.length === 0) return [empty()];
  if (events.length === 1) return [singleton(events[0])];
  const results = [];
  for (let split = 1; split < events.length; split++) {
    for (const left of allFolds(events.slice(0, split))) {
      for (const right of allFolds(events.slice(split))) results.push(combine(left, right));
    }
  }
  return results;
}

function checkAlgebra() {
  let sequences = 0, folds = 0;
  for (let length = 1; length <= 5; length++) {
    const deltas = product([-2, 0, 3], length);
    const gaps = product([0, 1], length - 1);
    for (const values of deltas) for (const intervals of gaps) {
      const times = [0];
      for (const gap of intervals) times.push(times.at(-1) + gap);
      const events = values.map((delta, i) => ({ time: times[i], id: `r${i}`, delta }));
      const expected = direct(events);
      for (const summary of allFolds(events)) {
        assert.deepEqual(summary, expected, `associativity: ${JSON.stringify(events)}`);
        assert.deepEqual(combine(empty(), summary), expected, 'left identity');
        assert.deepEqual(combine(summary, empty()), expected, 'right identity');
        folds++;
      }
      sequences++;
    }
  }
  console.log(`PASS complete-key algebra: ${sequences} timestamp/delta sequences, ${folds} binary folds, identity and direct reconstructions`);
}

const at = n => `2026-09-25T00:00:00.${String(n).padStart(9, '0')}Z`;
const intervalSource = (id, start, end) => `CREATE position_fact:${id} SET owned_by=rebase_group:root,
  a_time_owner=position_owner:boundary, a_order_owner=position_owner:boundary,
  a_time_z=d'${at(start)}', a_time_a=d'${at(end)}', a_order_z=10, a_order_a=20,
  a_weight_a=-1dec;`;

async function checkDatabase() {
  const env = await setup(), q = env.query;
  try {
    await q('CREATE position_owner:boundary SET owned_by=rebase_group:root, a_instant_capacity=1dec;');
    await q(intervalSource('z_old', 1, 2));
    await q(intervalSource('a_new', 2, 3));

    const data = await snapshot(q);
    const groups = verify(data);
    const metric = await q('RETURN position_owner:boundary.rb_time.summary.measures.weight;');
    assert.equal(Number(metric.max_prefix), 2, 'record-key order sees the temporary same-time overlap');
    assert.equal(Number(metric.boundary_min), 1);
    assert.equal(Number(metric.boundary_max), 1);
    assert.equal(Number(metric.instant_min), 0);
    assert.equal(Number(metric.instant_max), 1, 'adjacent half-open intervals fit capacity one');

    const range = await q(`RETURN fn::tree::range({rid:position_owner:boundary,slot:'rb_time'},
      [d'${at(2)}'], [d'${at(3)}']);`);
    const entries = groups.get('position_owner:boundary/rb_time').entries;
    oracle.equal(range, oracle.scan(entries.filter(entry => entry.key[0] === at(2))), 'same-time range balance');
    assert.equal(Number(range.measures.weight.max_prefix), 1);
    assert.equal(Number(range.measures.weight.instant_max), 0);

    await q('UPDATE position_owner:boundary SET a_instant_floor=0dec;');
    const before = await snapshot(q);
    await assert.rejects(q(`UPDATE position_fact:a_new SET a_time_z=d'${at(1)}';`), /POSITIONS_INSTANT_CAPACITY/);
    assert.deepEqual(await snapshot(q), before, 'same-transaction capacity rejection restores all slots and roots');
    verify(before);

    await q('DELETE position_fact:a_new; DELETE position_fact:z_old; DELETE position_owner:boundary;');
    assert.deepEqual(await snapshot(q), { owners: [], facts: [] });
    console.log('PASS compiled adjacent [start,end) intervals, tie-order independence, complete-timestamp range, and rollback');
  } finally {
    await env.close();
  }
}

async function main() {
  checkAlgebra();
  checkMissingMetrics();
  await checkDatabase();
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main, checkAlgebra, combine, direct };

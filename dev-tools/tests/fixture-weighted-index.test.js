"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { WeightedIndex } = require("../fixtures/weighted-index");

test("sampling respects proportional intervals and excludes zero weights across growth", () => {
  const index = new WeightedIndex([0, 1, 3]);
  assert.equal(index.pick(0), 1);
  assert.equal(index.pick(0.249), 1);
  assert.equal(index.pick(0.25), 2);
  assert.equal(index.pick(0.999), 2);
  for (let value = 1; value <= 50; value++) index.append(value);
  assert.equal(index.total, 1279);
  const all = index.sample(index.positive, () => 0.713);
  assert.equal(all.length, 52);
  assert.equal(new Set(all).size, 52);
  assert(!all.includes(0));
  assert.equal(index.total, 1279);
});

test("removing large weights preserves small candidates and sampling restores weights after failure", () => {
  const index = new WeightedIndex([1e20, 1, 2]);
  index.set(0, 0);
  assert.equal(index.total, 3);
  assert.equal(index.pick(0), 1);
  assert.equal(index.pick(0.5), 2);
  let calls = 0;
  assert.throws(() => index.sample(2, () => { if (calls++) throw new Error("stop"); return 0; }), /stop/);
  assert.equal(index.total, 3);
  assert.equal(index.positive, 2);
  index.set(1, 0); index.set(2, 0);
  assert.equal(index.pick(0.9), -1);
});

test("invalid weights fail without corrupting an existing distribution", () => {
  const index = new WeightedIndex([1, Number.MAX_VALUE]);
  for (const weight of [-1, NaN, Infinity, "1", Number.MAX_VALUE]) {
    assert.throws(() => index.set(0, weight), /weight/);
    assert.equal(index.get(0), 1);
  }
  assert.throws(() => index.sample(3, () => 0.5), /distinct/);
});

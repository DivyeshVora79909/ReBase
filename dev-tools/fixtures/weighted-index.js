"use strict";

function weightValue(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error("Selection weights must be finite nonnegative numbers");
  return value;
}

// A binary sum tree: O(log n) selection/update, amortized O(log n) append.
// Recompute ancestors rather than accumulating floating-point deltas.
class WeightedIndex {
  constructor(weights = []) {
    this.length = weights.length;
    this.capacity = 1;
    while (this.capacity < this.length) this.capacity *= 2;
    this.tree = new Float64Array(this.capacity * 2);
    this.positive = 0;
    weights.forEach((weight, index) => {
      this.tree[this.capacity + index] = weightValue(weight);
      if (weight > 0) this.positive++;
    });
    this.rebuild();
  }

  rebuild() {
    for (let index = this.capacity - 1; index > 0; index--) this.tree[index] = this.tree[index * 2] + this.tree[index * 2 + 1];
    if (!Number.isFinite(this.total)) throw new Error("Total selection weight exceeds finite number range");
  }

  get total() { return this.tree[1]; }
  get(index) { return this.tree[this.capacity + index]; }

  set(index, weight) {
    weightValue(weight);
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.length) throw new Error("Selection index is out of range");
    let node = this.capacity + index;
    const previous = this.tree[node];
    this.positive += Number(weight > 0) - Number(previous > 0);
    this.tree[node] = weight;
    while ((node = Math.floor(node / 2)) > 0) this.tree[node] = this.tree[node * 2] + this.tree[node * 2 + 1];
    if (!Number.isFinite(this.total)) {
      this.set(index, previous);
      throw new Error("Total selection weight exceeds finite number range");
    }
  }

  append(weight) {
    weightValue(weight);
    if (this.length === this.capacity) {
      const next = new Float64Array(this.capacity * 4);
      next.set(this.tree.subarray(this.capacity), this.capacity * 2);
      this.capacity *= 2;
      this.tree = next;
      this.rebuild();
    }
    const index = this.length++;
    this.set(index, weight);
    return index;
  }

  pick(random) {
    if (!(random >= 0 && random < 1)) throw new Error("Selection randomness must be in [0, 1)");
    if (this.total === 0) return -1;
    let node = 1, target = random * this.total;
    while (node < this.capacity) {
      const left = this.tree[node * 2], right = this.tree[node * 2 + 1];
      // The zero check also protects the last ulp of a floating-point boundary.
      if (target < left || right === 0) node *= 2;
      else { target -= left; node = node * 2 + 1; }
    }
    return node - this.capacity;
  }

  sample(count, random) {
    if (!Number.isSafeInteger(count) || count < 0 || count > this.positive) throw new Error("Not enough distinct positive-weight candidates");
    const selected = [];
    try {
      for (let i = 0; i < count; i++) {
        const index = this.pick(random());
        selected.push([index, this.get(index)]);
        this.set(index, 0);
      }
      return selected.map(([index]) => index);
    } finally {
      for (const [index, weight] of selected) this.set(index, weight);
    }
  }
}

module.exports = { WeightedIndex, weightValue };

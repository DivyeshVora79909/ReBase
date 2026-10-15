'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { D, compare } = require('../accounting/source-oracle');
const { linearSummary, verify } = require('../temporal-tree/exact-oracle');

const slot = 'z_value';
const ownerSlot = 'z_values';
const ownerLink = { rid: 'exact_owner:root', slot: ownerSlot };
const entriesFor = () => {
  const one = '2027-01-02T00:00:00.000000001Z';
  const two = '2027-01-02T00:00:00.000000002Z';
  const three = '2027-01-02T00:00:00.000000003Z';
  const raw = [
    [one, 'a_negative', { amount: '-0.100000000000000001' }, { cohort: 'same' }],
    [one, 'b_positive', { amount: '0.100000000000000001' }, { cohort: 'same' }],
    [two, 'c_amount', { amount: '0.333333333333333333', auxiliary: '1.000000000000000001' }, { cohort: 'same' }],
    [two, 'd_auxiliary', { auxiliary: '-1.000000000000000001' }, { cohort: 'same' }],
    [two, 'e_small', { amount: '0.000000000000000001' }, { cohort: 'same' }],
    [three, 'f_cancel', { amount: '-0.333333333333333335', auxiliary: '0.000000000000000001' }, { cohort: 'other' }],
    [three, 'g_empty', {}, {}],
  ].map(([at, id, measures, tags]) => ({
    link: { rid: `exact_member:${id}`, slot }, owner: ownerLink, key: [at, `exact_member:${id}`, slot],
    measures: Object.fromEntries(Object.entries(measures).map(([key, value]) => [key, new D(value)])),
    tags, spans: {}, dependent: false,
  }));
  return raw.sort((a, b) => compare(a.key, b.key));
};

function decimalText(value) {
  const scale = 10n ** 18n;
  const scaled = value.n * scale / value.d;
  assert.equal(value.n * scale % value.d, 0n, 'fixture decimals have finite 18-place output');
  const negative = scaled < 0n, digits = (negative ? -scaled : scaled).toString().padStart(19, '0');
  const fraction = digits.slice(-18).replace(/0+$/, '');
  return `${negative ? '-' : ''}${digits.slice(0, -18)}${fraction ? `.${fraction}` : ''}`;
}

function encode(value) {
  if (value instanceof D) return decimalText(value);
  if (Array.isArray(value)) return value.map(encode);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, encode(child)]));
}

function fixture() {
  const entries = entriesFor();
  const members = entries.map(entry => ({ id: entry.link.rid }));
  const owner = { id: ownerLink.rid };
  const head = { root: null, height: 0, revision: 1, summary: encode(linearSummary(entries, D, compare)) };
  owner[ownerSlot] = head;
  const build = (start, end, parent) => {
    if (start >= end) return { link: null, height: 0, entries: [] };
    const middle = Math.floor((start + end) / 2), entry = entries[middle];
    const left = build(start, middle, entry.link), right = build(middle + 1, end, entry.link);
    const ordered = [...left.entries, entry, ...right.entries];
    const summary = encode(linearSummary(ordered, D, compare));
    const value = encode(linearSummary([entry], D, compare));
    const row = members.find(member => member.id === entry.link.rid);
    row[slot] = { owner: ownerLink, parent, left: left.link, right: right.link, prev: null, next: null,
      key: entry.key, value, summary, height: 1 + Math.max(left.height, right.height) };
    return { link: entry.link, height: row[slot].height, entries: ordered };
  };
  const tree = build(0, entries.length, ownerLink);
  head.root = tree.link;
  head.height = tree.height;
  entries.forEach((entry, index) => {
    const node = members.find(member => member.id === entry.link.rid)[slot];
    node.prev = entries[index - 1]?.link ?? null;
    node.next = entries[index + 1]?.link ?? null;
  });
  return { entries, owner, members, owners: [owner], records: [owner, ...members] };
}

function check(value) {
  verify(value.owners, value.records, value.entries, compare, D);
}

function bumpSmallestDecimal(value) {
  return decimalText(new D(value).add('0.000000000000000001'));
}

test('exact source fold separates key prefixes from complete-timestamp extrema', () => {
  const entries = entriesFor(), summary = linearSummary(entries, D, compare);
  const amount = summary.measures.amount, auxiliary = summary.measures.auxiliary;
  assert.equal(amount.sum.cmp('-0.000000000000000001'), 0);
  assert.equal(amount.min_prefix.cmp('-0.100000000000000001'), 0);
  assert.equal(amount.instant_min.cmp('-0.000000000000000001'), 0);
  assert.equal(amount.instant_max.cmp('0.333333333333333334'), 0);
  assert.equal(amount.boundary_min.cmp('0'), 0);
  assert.equal(amount.boundary_max.cmp('0.333333333333333334'), 0);
  assert.equal(auxiliary.sum.cmp('0.000000000000000001'), 0);
  assert.equal(new D('9007199254740993').add('-9007199254740992').cmp('1'), 0, 'large cancellation stays exact');
  assert.equal(new D('1.005').round(2).cmp('1'), 0, 'positive half rounds to even');
  assert.equal(new D('1.015').round(2).cmp('1.02'), 0, 'odd positive half rounds up to even');
  assert.equal(new D('-1.005').round(2).cmp('-1'), 0, 'negative half rounds to even');
  assert.equal(new D('-1.015').round(2).cmp('-1.02'), 0, 'odd negative half rounds away to even');
});

test('exact tree checker accepts source-linear leaves, internal nodes, and root', () => {
  check(fixture());
});

test('one 18-place unit of decimal corruption fails at leaf, internal summary, and root', () => {
  const corruptions = [
    ['leaf', value => {
      const row = value.members.find(member => member[slot]?.left == null && member[slot]?.right == null
        && member[slot]?.value.measures.amount);
      row[slot].value.measures.amount.sum = bumpSmallestDecimal(row[slot].value.measures.amount.sum);
    }],
    ['internal subtree', value => {
      const root = value.members.find(member => member.id === value.owner[ownerSlot].root.rid)[slot];
      const child = root.left;
      const node = value.members.find(member => member.id === child.rid)[slot];
      node.summary.measures.amount.sum = bumpSmallestDecimal(node.summary.measures.amount.sum);
    }],
    ['published root', value => {
      value.owner[ownerSlot].summary.measures.amount.sum = bumpSmallestDecimal(
        value.owner[ownerSlot].summary.measures.amount.sum);
    }],
  ];
  for (const [name, corrupt] of corruptions) {
    const value = fixture();
    check(value);
    corrupt(value);
    assert.throws(() => check(value), /\.value|\.summary|\.published/, name);
  }
});

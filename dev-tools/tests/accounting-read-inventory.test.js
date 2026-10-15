'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { expectedReadInventory } = require('../accounting/source-oracle');

function openingEntry({ datedQuote = false, identity = false } = {}) {
  const date = '2027-01-02T00:00:00.000000000Z';
  const pair = identity ? null : 'exchange_pair:usd_inr';
  return {
    currency: [
      { id: 'currency:usd', precision: 2 },
      { id: 'currency:inr', precision: 2 },
    ],
    subsidiary: [{ id: 'subsidiary:inr', currency: identity ? 'currency:usd' : 'currency:inr' }],
    exchange_pair: pair ? [{ id: pair, given_resource: 'currency:usd', received_resource: 'currency:inr',
      initial_rate: '10', effective_at: '2027-01-01T00:00:00.000000000Z' }] : [],
    exchange_rate: datedQuote ? [{ id: 'exchange_rate:dated', pair, effective_at: date, rate: '11' }] : [],
    treasury: [{ id: 'treasury:usd', currency: identity ? 'currency:usd' : 'currency:usd',
      resource: 'currency:usd', subsidiary: 'subsidiary:inr', reporting_currency: identity ? 'currency:usd' : 'currency:inr', valuation_pair: pair }],
    account_entry: [{ id: 'account_entry:opening', account: 'treasury:usd', effective_at: date,
      real: '1', receivable: '0', payable: '0' }],
  };
}

test('accounting read inventory follows source quotes and keeps reader identities stable', () => {
  const fallback = expectedReadInventory(openingEntry());
  assert.deepEqual(fallback, [
    { reader: 'account_entry:opening', phase: 'refresh', source_root: 'exchange_pair:usd_inr',
      source_slot: '', kind: 'record', arguments: [], path: 'effective_at', fallback: undefined },
    { reader: 'account_entry:opening', phase: 'refresh', source_root: 'exchange_pair:usd_inr',
      source_slot: 'z_rates', kind: 'latest', arguments: [['2027-01-02T00:00:00.000000001Z']],
      path: 'measures.rate.sum', fallback: undefined },
    { reader: 'account_entry:opening', phase: 'refresh', source_root: 'exchange_pair:usd_inr',
      source_slot: '', kind: 'record', arguments: [], path: 'initial_rate', fallback: undefined },
  ]);

  const dated = expectedReadInventory(openingEntry({ datedQuote: true }));
  assert.deepEqual(dated.map(read => read.path), ['effective_at', 'measures.rate.sum']);
  assert(!dated.some(read => read.path === 'initial_rate'), 'a dated quote removes the source-fact fallback read');
});

test('same-resource rates are a legitimate empty accounting read inventory', () => {
  assert.deepEqual(expectedReadInventory(openingEntry({ identity: true })), []);
  assert.deepEqual(expectedReadInventory({}), []);
});

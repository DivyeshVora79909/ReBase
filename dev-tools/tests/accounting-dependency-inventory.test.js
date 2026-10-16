'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { expectedDependencyInventory, D } = require('../accounting/source-oracle');

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

test('accounting dependencies keep fixed roles across dated quote and fallback changes', () => {
  const fallback = expectedDependencyInventory(openingEntry());
  assert.deepEqual(fallback, [
    { reader: 'account_entry:opening', field: 'q_account_reporting', phase: 'refresh', source: 'exchange_pair:usd_inr',
      source_slot: 'z_rates', kind: 'latest', arguments: [['2027-01-02T00:00:00.000000001Z']],
      path: 'measures.rate.sum', fallback: new D(10) },
  ]);
  assert.deepEqual(expectedDependencyInventory(openingEntry({ datedQuote: true })), fallback,
    'a new selected quote does not change the declared query or remove its fallback');
});

test('same-resource conversion has no ordered dependency', () => {
  assert.deepEqual(expectedDependencyInventory(openingEntry({ identity: true })), []);
  assert.deepEqual(expectedDependencyInventory({}), []);
});

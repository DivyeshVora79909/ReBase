#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');

const root = path.resolve(__dirname, '../..');
const number = (value) => Number(String(value ?? 0).replace(/dec$/i, ''));

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', (error) => error ? reject(error) : resolve()));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitForPort(port, child) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`SurrealDB exited with ${child.exitCode}`);
    const connected = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      const done = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => done(false));
      socket.once('connect', () => done(true));
      socket.once('error', () => done(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('H5c cash refund probe SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    refunds: (SELECT * FROM receivable_cash_refund ORDER BY id),
    receivable_allocations: (SELECT * FROM receivable_cash_allocation ORDER BY id),
    invoice_allocations: (SELECT * FROM sales_invoice_cash_allocation ORDER BY id),
    receivables: (SELECT * FROM receivable ORDER BY id),
    cashins: (SELECT * FROM cash_in ORDER BY id),
    cashouts: (SELECT * FROM cash_out ORDER BY id),
    invoice_lines: (SELECT * FROM sales_invoice_line ORDER BY id),
    invoices: (SELECT * FROM sales_invoice ORDER BY id),
    issues: (SELECT * FROM sales_invoice_issue ORDER BY id),
    claims: (SELECT * FROM claim_account ORDER BY id),
    treasuries: (SELECT * FROM treasury_account ORDER BY id),
    stocks: (SELECT * FROM stock_account ORDER BY id),
    stockins: (SELECT * FROM stock_in ORDER BY id),
    stockouts: (SELECT * FROM stock_out ORDER BY id)
  };`));
}

const byId = (rows, id) => rows.find((row) => String(row.id) === id);
const measure = (row, tree, name, metric = 'sum') => number(row?.[tree]?.summary?.measures?.[name]?.[metric] ?? 0);

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label}: refunds, allocations, sources and every affected root roll back`);
}

function refundCapacityOracle(state, allocationId) {
  const allocation = byId(state.receivable_allocations, allocationId);
  const refunds = state.refunds.filter((row) => String(row.allocation) === allocationId);
  const events = new Map();
  const add = (at, delta) => {
    const key = new Date(at).toISOString();
    events.set(key, (events.get(key) ?? 0) + delta);
  };
  add(allocation.effective_at, number(allocation.amount));
  for (const row of refunds) add(row.effective_at, -number(row.amount));
  let running = 0;
  let instantMin = 0;
  for (const at of [...events.keys()].sort()) {
    running += events.get(at);
    instantMin = Math.min(instantMin, running);
  }
  return { sum: running, instantMin };
}

function cashAvailableOracle(state, sourceId) {
  const source = byId(state.cashins, sourceId);
  const allocations = [...state.receivable_allocations, ...state.invoice_allocations]
    .filter((row) => String(row.source) === sourceId);
  const events = new Map();
  const add = (at, delta) => {
    const key = new Date(at).toISOString();
    events.set(key, (events.get(key) ?? 0) + delta);
  };
  add(source.effective_at, number(source.amount));
  for (const row of allocations) add(row.effective_at, -number(row.amount));
  for (const row of state.refunds) {
    const allocation = byId(state.receivable_allocations, String(row.allocation));
    if (String(allocation?.source) !== sourceId) continue;
    add(row.effective_at, -number(row.amount));
    add(row.effective_at, number(row.amount));
  }
  let running = 0;
  let instantMin = 0;
  for (const at of [...events.keys()].sort()) {
    running += events.get(at);
    instantMin = Math.min(instantMin, running);
  }
  return { sum: running, instantMin };
}

function assertOracles(state, expectedRefunds) {
  const claim = byId(state.claims, 'claim_account:customer');
  const cash = byId(state.treasuries, 'treasury_account:cash');
  const invoiceCash = byId(state.treasuries, 'treasury_account:cash_invoice');
  const mainSource = byId(state.cashins, 'cash_in:main');
  const invoiceSource = byId(state.cashins, 'cash_in:invoice');
  const mainAllocation = byId(state.receivable_allocations, 'receivable_cash_allocation:main');
  const standaloneAmount = state.receivables.filter((row) => String(row.claim_account) === 'claim_account:customer')
    .reduce((sum, row) => sum + number(row.amount), 0);
  const invoiceBase = state.invoice_lines.reduce((sum, row) => sum + number(row.amount), 0);
  const allocationTotal = [...state.receivable_allocations, ...state.invoice_allocations]
    .reduce((sum, row) => sum + number(row.amount), 0);
  const mainSourceAllocated = [...state.receivable_allocations, ...state.invoice_allocations]
    .filter((row) => String(row.source) === 'cash_in:main')
    .reduce((sum, row) => sum + number(row.amount), 0);
  const refundTotal = state.refunds.reduce((sum, row) => sum + number(row.amount), 0);
  assert.equal(refundTotal, expectedRefunds, 'refund facts independently reconstruct expected amount');
  assert.equal(measure(claim, 'z_history', 'receivable'), standaloneAmount + invoiceBase - allocationTotal + refundTotal,
    'customer receivable reconstructs from claim entries, cash allocations and refunds');
  assert.equal(measure(claim, 'z_history', 'net'), standaloneAmount + invoiceBase - allocationTotal + refundTotal,
    'customer net follows the independently reconstructed receivable');
  assert.equal(measure(mainAllocation, 'z_refunds', 'remaining'), number(mainAllocation.amount)
    - state.refunds.filter((row) => String(row.allocation) === 'receivable_cash_allocation:main')
      .reduce((sum, row) => sum + number(row.amount), 0),
  'dated allocation refund capacity reconstructs from the allocation and linked refund rows');
  assert.equal(measure(mainAllocation, 'z_refunds', 'remaining', 'instant_min'),
    refundCapacityOracle(state, 'receivable_cash_allocation:main').instantMin,
  'complete-time refund-capacity floor reconstructs from source rows');
  assert.equal(measure(byId(state.receivables, 'receivable:main'), 'z_settlement', 'settled'),
    number(mainAllocation.amount) - expectedRefunds,
  'standalone receivable settlement equals allocation less linked refunds');
  assert.equal(measure(byId(state.invoices, 'sales_invoice:invoice'), 'z_outstanding', 'outstanding'), 0,
    'ordinary sales invoice allocation remains fully settled');
  assert.equal(measure(cash, 'z_history', 'balance'), number(mainSource.amount) - expectedRefunds,
    'refund treasury equals its cash-in less one debit per refund fact');
  assert.equal(measure(invoiceCash, 'z_history', 'balance'), 10,
    'unrelated invoice settlement cash movement remains unchanged');
  assert.equal(state.cashouts.length, 0, 'the refund route creates no duplicate cash_out');
  assert.equal(measure(mainSource, 'z_allocations', 'allocated'), mainSourceAllocated, 'gross cash allocation remains unchanged');
  assert.equal(measure(mainSource, 'z_allocations', 'refunded'), expectedRefunds,
    'cash-in source refunded measure equals explicit refund facts');
  assert.equal(measure(mainSource, 'z_allocations', 'allocation_reversed'), expectedRefunds,
    'cash-in source allocation reversal equals explicit refund facts');
  assert.equal(measure(mainSource, 'z_allocations', 'available'), number(mainSource.amount) - mainSourceAllocated,
    'refund leaves existing allocatable cash capacity unchanged');
  for (const source of state.cashins) {
    const expected = cashAvailableOracle(state, String(source.id));
    assert.equal(measure(source, 'z_allocations', 'available'), expected.sum,
      `${source.id}: available reconstructs from the dated cash-in/allocation/refund equation`);
    assert.equal(measure(source, 'z_allocations', 'available', 'instant_min'), expected.instantMin,
      `${source.id}: complete-time available floor reconstructs from cash-in/allocation/refund rows`);
  }
  assert.equal(measure(invoiceSource, 'z_allocations', 'allocated'), 10,
    'sales-invoice cash allocation family retains its gross allocation effect');
  assert.equal(measure(invoiceSource, 'z_allocations', 'available'), 0,
    'sales-invoice cash allocation consumes cash-in available capacity');
  assert.equal(number(mainSource.z_allocations.summary.measures.allocated.max_prefix), mainSourceAllocated,
    'cash-in root retains its positive gross allocation cap');
  assert.equal(number(byId(state.stocks, 'stock_account:stock').z_history.summary.measures.quantity.sum), 0,
    'refund has no stock effect');
  for (const allocation of state.receivable_allocations) {
    const expected = refundCapacityOracle(state, String(allocation.id));
    assert.equal(measure(allocation, 'z_refunds', 'remaining'), expected.sum,
      `${allocation.id}: independent dated refund-capacity sum`);
    assert.equal(measure(allocation, 'z_refunds', 'remaining', 'instant_min'), expected.instantMin,
      `${allocation.id}: independent complete-time refund-capacity floor`);
  }
  assert.equal(measure(mainAllocation, 'z_refunds', 'remaining'), number(mainAllocation.amount) - expectedRefunds,
    'allocation refund root equals its one grant less all refund facts');
  return state;
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h5c_${Date.now().toString(36)}`;
  const child = spawn('surreal', ['start', 'memory', '--user', 'root', '--pass', 'root',
    '--bind', `127.0.0.1:${port}`, '--no-banner', '--log', 'error'],
  { cwd: root, stdio: ['ignore', 'ignore', 'ignore'] });
  const db = new Surreal();
  try {
    await waitForPort(port, child);
    await db.connect(`ws://127.0.0.1:${port}/rpc`);
    await db.signin({ username: 'root', password: 'root' });
    await db.query(`DEFINE NAMESPACE ${namespace};`);
    await db.use({ namespace });
    await db.query('DEFINE DATABASE probe;');
    await db.use({ namespace, database: 'probe' });
    await db.query(schema);
    await db.query(`
      CREATE ONLY organization:entity SET owned_by = rebase_group:root, name = 'Entity';
      CREATE ONLY organization:customer SET owned_by = rebase_group:root, name = 'Customer';
      CREATE ONLY organization:wrong_customer SET owned_by = rebase_group:root, name = 'Wrong customer';
      CREATE ONLY organization:authority SET owned_by = rebase_group:root, name = 'Authority';
      CREATE ONLY organization:other_entity SET owned_by = rebase_group:root, name = 'Other entity';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'EUR', precision = 2;
      CREATE ONLY treasury:main SET owned_by = rebase_group:root, name = 'Main treasury';
      CREATE ONLY treasury:invoice SET owned_by = rebase_group:root, name = 'Invoice source treasury';
      CREATE ONLY treasury:foreign SET owned_by = rebase_group:root, name = 'Foreign currency treasury';
      CREATE ONLY treasury_account:cash SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:main, currency = currency:usd;
      CREATE ONLY treasury_account:cash_invoice SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:invoice, currency = currency:usd;
      CREATE ONLY treasury_account:cash_eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:foreign, currency = currency:eur;
      CREATE ONLY treasury_account:cash_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        treasury = treasury:foreign, currency = currency:usd;
      CREATE ONLY claim_account:customer SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:customer, currency = currency:usd;
      CREATE ONLY claim_account:wrong_customer SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:wrong_customer, currency = currency:usd;
      CREATE ONLY receivable:main SET owned_by = rebase_group:root, claim_account = claim_account:customer,
        amount = 60dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY receivable:wrong_party SET owned_by = rebase_group:root, claim_account = claim_account:wrong_customer,
        amount = 1dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY item:widget SET owned_by = rebase_group:root, name = 'Widget', unit = measure_unit:each;
      CREATE ONLY operating_unit:store SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Store';
      CREATE ONLY stock_account:stock SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:store, resource = item:widget;
      CREATE ONLY stock_in:inventory SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = stock_account:stock, quantity = 1dec, effective_at = d'2026-05-30T00:00:00Z';
      CREATE ONLY stock_out:dispatch SET owned_by = rebase_group:root, from_account = stock_account:stock,
        to_party = organization:customer, quantity = 1dec, effective_at = d'2026-05-31T00:00:00Z';
      CREATE ONLY sales_invoice:invoice SET owned_by = rebase_group:root, claim_account = claim_account:customer, number = 'H5C-1';
      CREATE ONLY sales_invoice_issue:issue SET owned_by = rebase_group:root, invoice = sales_invoice:invoice,
        issued_at = d'2026-06-01T12:00:00Z',
        lines = [{ line_key: 'base', source: stock_out:dispatch, billed_quantity: 1dec, unit_price: 10dec }];
      CREATE ONLY cash_in:main SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = treasury_account:cash, amount = 100dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY cash_in:invoice SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = treasury_account:cash_invoice, amount = 10dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY receivable_cash_allocation:main SET owned_by = rebase_group:root, source = cash_in:main,
        target = receivable:main, amount = 60dec, effective_at = d'2026-06-03T00:00:00Z';
      CREATE ONLY sales_invoice_cash_allocation:invoice SET owned_by = rebase_group:root, source = cash_in:invoice,
        target = sales_invoice_issue:issue, amount = 10dec, effective_at = d'2026-06-03T00:00:00Z';
    `);

    let state = assertOracles(await snapshot(db), 0);
    const stableId = 'receivable_cash_refund:first';
    assert.equal(measure(byId(state.cashins, 'cash_in:main'), 'z_allocations', 'available'), 40,
      'cash-in self-seed plus allocation establishes available capacity');
    assert.equal(measure(byId(state.receivable_allocations, 'receivable_cash_allocation:main'), 'z_refunds', 'remaining'), 60,
      'allocation self-seed creates a dated refund grant exactly once');

    await rejectsUnchanged(db, `CREATE ONLY receivable_cash_refund:before SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`,
    'refund at allocation timestamp is rejected; time must be strictly later');
    await rejectsUnchanged(db, `CREATE ONLY receivable_cash_refund:precision SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 1.001dec, effective_at = d'2026-06-04T00:00:00Z';`,
    'currency-inexact refund rejects');

    await db.query('UPDATE receivable_cash_allocation:main SET amount = 59dec;');
    state = assertOracles(await snapshot(db), 0);
    assert.equal(measure(byId(state.cashins, 'cash_in:main'), 'z_allocations', 'available'), 41,
      'allocation amount edit refreshes cash-in available capacity');
    await db.query('UPDATE receivable_cash_allocation:main SET effective_at = d\'2026-06-03T12:00:00Z\';');
    state = assertOracles(await snapshot(db), 0);
    await db.query('UPDATE receivable_cash_allocation:main SET amount = 60dec, effective_at = d\'2026-06-03T00:00:00Z\';');
    state = assertOracles(await snapshot(db), 0);

    await rejectsUnchanged(db, `CREATE ONLY receivable_cash_allocation:wrong_party SET owned_by = rebase_group:root,
      source = cash_in:main, target = receivable:wrong_party, amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`,
    'wrong customer source/target allocation rejects before refund eligibility');

    await db.query(`CREATE ONLY receivable_cash_refund:first SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 20dec, effective_at = d'2026-06-04T00:00:00Z';`);
    state = assertOracles(await snapshot(db), 20);
    assert.equal(String(byId(state.refunds, stableId).allocation), 'receivable_cash_allocation:main');
    await db.query(`CREATE ONLY receivable_cash_refund:sibling SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 20dec, effective_at = d'2026-06-04T00:00:00Z';`);
    state = assertOracles(await snapshot(db), 40);
    assert.equal(measure(byId(state.receivable_allocations, 'receivable_cash_allocation:main'),
      'z_refunds', 'remaining', 'instant_min'), 0, 'same-time siblings preserve complete-time capacity');
    await rejectsUnchanged(db, `CREATE ONLY receivable_cash_refund:excess SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 21dec, effective_at = d'2026-06-05T00:00:00Z';`,
    'cumulative refund beyond the allocation cap rejects');
    await db.query(`CREATE ONLY receivable_cash_refund:final SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 20dec, effective_at = d'2026-06-05T00:00:00Z';`);
    state = assertOracles(await snapshot(db), 60);
    assert.equal(measure(byId(state.receivable_allocations, 'receivable_cash_allocation:main'), 'z_refunds', 'remaining'), 0,
      'full refund consumes the allocation grant exactly');

    await rejectsUnchanged(db, 'UPDATE receivable_cash_allocation:main SET amount = 59dec;',
      'allocation amount reduction below refunds and settled amount rejects');
    await rejectsUnchanged(db, "UPDATE receivable_cash_allocation:main SET effective_at = d'2026-06-06T00:00:00Z';",
      'moving allocation after existing refunds rejects and restores all roots');
    await rejectsUnchanged(db, 'UPDATE cash_in:main SET amount = 59dec;',
      'cash source amount reduction below gross allocation rejects');
    await rejectsUnchanged(db, "UPDATE cash_in:main SET effective_at = d'2026-06-06T00:00:00Z';",
      'cash source date move after allocation rejects and restores refund ancestry');
    await rejectsUnchanged(db, 'UPDATE cash_in:main SET from_party = organization:wrong_customer;',
      'cash source party endpoint edit rejects');
    await rejectsUnchanged(db, 'UPDATE cash_in:main SET to_account = treasury_account:cash_eur;',
      'cash source currency endpoint edit rejects');
    await rejectsUnchanged(db, 'UPDATE cash_in:main SET to_account = treasury_account:cash_other;',
      'cash source entity endpoint edit rejects');
    await rejectsUnchanged(db, 'DELETE receivable_cash_allocation:main;', 'allocation with refunds cannot be deleted');
    await rejectsUnchanged(db, 'DELETE receivable:main;', 'target receivable with allocation/refunds cannot be deleted');
    await rejectsUnchanged(db, 'DELETE cash_in:main;', 'cash source with allocation/refunds cannot be deleted');

    await db.query('UPDATE receivable_cash_refund:first SET amount = 15dec;');
    state = assertOracles(await snapshot(db), 55);
    await db.query("UPDATE receivable_cash_refund:first SET effective_at = d'2026-06-04T12:00:00Z';");
    state = assertOracles(await snapshot(db), 55);
    await db.query('UPDATE receivable_cash_refund:first SET amount = 20dec, effective_at = d\'2026-06-04T00:00:00Z\';');
    state = assertOracles(await snapshot(db), 60);
    await db.query('DELETE receivable_cash_refund:final;');
    state = assertOracles(await snapshot(db), 40);
    await db.query(`CREATE ONLY receivable_cash_refund:final SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 20dec, effective_at = d'2026-06-05T00:00:00Z';`);
    state = assertOracles(await snapshot(db), 60);
    assert.equal(String(byId(state.refunds, 'receivable_cash_refund:first').id), stableId,
      'refund ID remains stable across edits and sibling lifecycle');
    assert.equal(state.cashouts.length, 0, 'no cash_out was created at any point');

    await db.query('DELETE receivable_cash_refund:first;');
    await db.query('DELETE receivable_cash_refund:sibling;');
    await db.query('DELETE receivable_cash_refund:final;');
    state = assertOracles(await snapshot(db), 0);
    await db.query('DELETE receivable_cash_allocation:main;');
    state = await snapshot(db);
    assert.equal(measure(byId(state.cashins, 'cash_in:main'), 'z_allocations', 'available'), 100,
      'deleting the allocation removes its dated refund seed and restores source availability');
    assert.equal(state.receivable_allocations.some((row) => String(row.id) === 'receivable_cash_allocation:main'), false);
    await db.query('DELETE cash_in:main;');
    state = await snapshot(db);
    assert.equal(state.cashins.some((row) => String(row.id) === 'cash_in:main'), false,
      'cash-in self-seed owner deletes after all references and consumers are removed');
    await db.query(`CREATE ONLY cash_in:main SET owned_by = rebase_group:root, from_party = organization:customer,
      to_account = treasury_account:cash, amount = 100dec, effective_at = d'2026-06-02T00:00:00Z';`);
    await db.query(`CREATE ONLY receivable_cash_allocation:main SET owned_by = rebase_group:root,
      source = cash_in:main, target = receivable:main, amount = 60dec, effective_at = d'2026-06-03T00:00:00Z';`);
    state = assertOracles(await snapshot(db), 0);
    assert.equal(measure(byId(state.receivable_allocations, 'receivable_cash_allocation:main'), 'z_refunds', 'remaining'), 60,
      're-created allocation has one fresh dated self-seed');
    await db.query(`CREATE ONLY receivable_cash_refund:first SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 20dec, effective_at = d'2026-06-04T00:00:00Z';`);
    await db.query(`CREATE ONLY receivable_cash_refund:sibling SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 20dec, effective_at = d'2026-06-04T00:00:00Z';`);
    await db.query(`CREATE ONLY receivable_cash_refund:final SET owned_by = rebase_group:root,
      allocation = receivable_cash_allocation:main, amount = 20dec, effective_at = d'2026-06-05T00:00:00Z';`);
    state = assertOracles(await snapshot(db), 60);
    assert.equal(state.cashouts.length, 0, 'self-seed teardown/recreation still produces no cash_out');

    console.log('H5c allocated cash refund, dated capacities, source-row oracle, lifecycle rollback, and no-duplicate-cash passed');
  } finally {
    await db.close().catch(() => {});
    child.kill('SIGTERM');
    await new Promise((resolve) => child.once('exit', resolve));
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

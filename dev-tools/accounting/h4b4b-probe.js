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
  throw new Error('H4b4b SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    issue: (SELECT * FROM ONLY sales_invoice_issue:issue),
    lines: (SELECT * FROM sales_invoice_line ORDER BY id),
    invoice_taxes: (SELECT * FROM sales_invoice_tax_component ORDER BY id),
    invoice_cash_allocation: (SELECT * FROM ONLY sales_invoice_cash_allocation:allocation),
    cashins: (SELECT * FROM cash_in ORDER BY id),
    cashouts: (SELECT * FROM cash_out ORDER BY id),
    allocations: (SELECT * FROM sales_invoice_cash_allocation ORDER BY id),
    withholdings: (SELECT * FROM customer_withholding ORDER BY id),
    policies: (SELECT * FROM customer_withholding_policy_version ORDER BY id),
    customer: (SELECT * FROM ONLY claim_account:customer),
    tax_invoice: (SELECT * FROM ONLY claim_account:tax_invoice),
    tax_tds: (SELECT * FROM ONLY claim_account:tax_tds),
    tax_other: (SELECT * FROM ONLY claim_account:tax_other),
    tax_eur: (SELECT * FROM ONLY claim_account:tax_eur),
    not_tax: (SELECT * FROM ONLY claim_account:not_tax),
    invoice: (SELECT * FROM ONLY sales_invoice:invoice),
    stock: (SELECT * FROM ONLY stock_account:stock),
    dispatch: (SELECT * FROM ONLY stock_out:dispatch),
    cash: (SELECT * FROM ONLY treasury_account:cash),
    all_treasury: (SELECT * FROM treasury_account ORDER BY id)
  };`));
}

const measure = (row, tree, name) => number(row?.[tree]?.summary?.measures?.[name]?.sum ?? 0);

async function oracle(db, withheld) {
  const state = await snapshot(db);
  const sourceBase = state.lines.reduce((sum, row) => sum + number(row.amount), 0);
  const invoiceTax = state.invoice_taxes.reduce((sum, row) => sum + number(row.amount), 0);
  const cashAllocated = state.allocations.reduce((sum, row) => sum + number(row.amount), 0);
  const explicitWithholding = state.withholdings.reduce((sum, row) => sum + number(row.amount), 0);
  const open = sourceBase + invoiceTax - cashAllocated - explicitWithholding;
  assert.equal(explicitWithholding, withheld, 'withholding facts independently reconstruct the expected amount');
  assert.equal(measure(state.customer, 'z_history', 'receivable'), open,
    'customer receivable reconstructs from invoice children, cash allocation and withholding');
  assert.equal(measure(state.customer, 'z_history', 'net'), open,
    'customer net reflects only customer receivable');
  assert.equal(measure(state.invoice, 'z_outstanding', 'outstanding'), open,
    'sales invoice outstanding independently reconstructs');
  assert.equal(state.invoice_taxes.length, 1, 'exactly one invoice-time sales tax component remains');
  assert.equal(number(state.invoice_taxes[0].amount), 10, 'invoice-time tax amount remains exactly 10');
  assert.equal(measure(state.tax_invoice, 'z_history', 'payable'), 10,
    'invoice-time sales tax payable remains exactly once');
  assert.equal(measure(state.tax_tds, 'z_history', 'receivable'), explicitWithholding,
    'separate policy-selected withholding tax account receives the credit');
  assert.equal(measure(state.tax_tds, 'z_history', 'payable'), 0,
    'withholding credit is not duplicated as tax payable');
  assert.equal(measure(state.cash, 'z_history', 'balance'), 90,
    'only the actual 90 cash-in changes treasury');
  const source = state.cashins.find((row) => String(row.id) === 'cash_in:receipt');
  assert.equal(number(source?.z_allocations?.summary?.measures?.allocated?.sum ?? 0), 90,
    'withholding does not consume cash-in allocation capacity');
  assert.equal(measure(state.stock, 'z_history', 'quantity'), 0,
    'withholding has no stock effect');
  assert.equal(measure(state.dispatch, 'z_billing', 'billed'), 1,
    'the original physical dispatch billing remains unchanged');
  return state;
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before,
    `${label}: source, outputs, policies, cash, stock and claim/invoice roots roll back`);
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h4b4b_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:other_entity SET owned_by = rebase_group:root, name = 'Other entity';
      CREATE ONLY organization:customer SET owned_by = rebase_group:root, name = 'Customer';
      CREATE ONLY organization:other_customer SET owned_by = rebase_group:root, name = 'Other customer';
      CREATE ONLY organization:authority SET owned_by = rebase_group:root, name = 'Invoice tax authority';
      CREATE ONLY organization:withholding_authority SET owned_by = rebase_group:root, name = 'Withholding authority';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'EUR', precision = 2;
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY item:unit SET owned_by = rebase_group:root, name = 'Unit', unit = measure_unit:each;
      CREATE ONLY tax_account:invoice_tax SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Invoice component tax';
      CREATE ONLY tax_account:withholding_tax SET owned_by = rebase_group:root,
        authority = organization:withholding_authority, jurisdiction = organization:entity, label = 'Withholding credit';
      CREATE ONLY treasury:main SET owned_by = rebase_group:root, name = 'Main';
      CREATE ONLY treasury:other SET owned_by = rebase_group:root, name = 'Other entity fixture';
      CREATE ONLY treasury_account:cash SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:main, currency = currency:usd;
      CREATE ONLY treasury_account:cash_bad SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:other, currency = currency:usd;
      CREATE ONLY treasury_account:cash_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        treasury = treasury:other, currency = currency:usd;
      CREATE ONLY treasury_account:cash_eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:main, currency = currency:eur;
      CREATE ONLY cash_in:fund_bad SET owned_by = rebase_group:root, from_party = organization:other_customer,
        to_account = treasury_account:cash_bad, amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';
      CREATE ONLY cash_in:fund_other SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = treasury_account:cash_other, amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';
      CREATE ONLY cash_in:fund_eur SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = treasury_account:cash_eur, amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';
      CREATE ONLY operating_unit:store SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Store';
      CREATE ONLY stock_account:stock SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:store, resource = item:unit;
      CREATE ONLY stock_in:inventory SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = stock_account:stock, quantity = 1dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY stock_out:dispatch SET owned_by = rebase_group:root, from_account = stock_account:stock,
        to_party = organization:customer, quantity = 1dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY claim_account:customer SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:customer, currency = currency:usd;
      CREATE ONLY claim_account:tax_invoice SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:invoice_tax, currency = currency:usd;
      CREATE ONLY claim_account:tax_tds SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:withholding_tax, currency = currency:usd;
      CREATE ONLY claim_account:tax_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        opponent = tax_account:withholding_tax, currency = currency:usd;
      CREATE ONLY claim_account:tax_eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:withholding_tax, currency = currency:eur;
      CREATE ONLY claim_account:not_tax SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:withholding_authority, currency = currency:usd;
      CREATE ONLY sales_invoice:invoice SET owned_by = rebase_group:root,
        claim_account = claim_account:customer, number = 'H4B4B-1';
      CREATE ONLY sales_invoice_issue:issue SET owned_by = rebase_group:root, invoice = sales_invoice:invoice,
        issued_at = d'2026-06-02T01:00:00Z',
        lines = [{ line_key: 'base', source: stock_out:dispatch, billed_quantity: 1dec, unit_price: 90dec }],
        tax_components = [{ tax_key: 'tcs_fixture_only', tax_claim_account: claim_account:tax_invoice, amount: 10dec }];
      CREATE ONLY customer_withholding_policy_version:policy_v1 SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_tds, policy_key = 'fixture-customer-withholding', version = 'v1',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY customer_withholding_policy_version:policy_eur SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_eur, policy_key = 'fixture-customer-withholding', version = 'eur',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY customer_withholding_policy_version:policy_other SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_other, policy_key = 'fixture-customer-withholding', version = 'other',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY customer_withholding_policy_version:policy_expired SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_tds, policy_key = 'fixture-customer-withholding', version = 'expired',
        valid_from = d'2025-01-01T00:00:00Z', valid_until = d'2026-06-05T00:00:00Z';
      CREATE ONLY cash_in:receipt SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = treasury_account:cash, amount = 90dec, effective_at = d'2026-06-03T00:00:00Z';
      CREATE ONLY sales_invoice_cash_allocation:allocation SET owned_by = rebase_group:root,
        source = cash_in:receipt, target = sales_invoice_issue:issue, amount = 90dec,
        effective_at = d'2026-06-04T00:00:00Z';
    `);

    let state = await oracle(db, 0);
    const cashBefore = JSON.stringify(state.cash.z_history);
    const sourcePoolBefore = JSON.stringify(state.cashins.find((row) => String(row.id) === 'cash_in:receipt').z_allocations);
    const stockBefore = JSON.stringify(state.stock.z_history);

    await db.query(`CREATE ONLY cash_in:wrong_party SET owned_by = rebase_group:root,
      from_party = organization:other_customer, to_account = treasury_account:cash_bad,
      amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_in:wrong_entity SET owned_by = rebase_group:root,
      from_party = organization:customer, to_account = treasury_account:cash_other,
      amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_in:wrong_currency SET owned_by = rebase_group:root,
      from_party = organization:customer, to_account = treasury_account:cash_eur,
      amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`);
    await rejectsUnchanged(db, `CREATE ONLY sales_invoice_cash_allocation:wrong_party SET owned_by = rebase_group:root,
      source = cash_in:wrong_party, target = sales_invoice_issue:issue, amount = 1dec,
      effective_at = d'2026-06-04T00:00:00Z';`, 'wrong source party allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY sales_invoice_cash_allocation:wrong_entity SET owned_by = rebase_group:root,
      source = cash_in:wrong_entity, target = sales_invoice_issue:issue, amount = 1dec,
      effective_at = d'2026-06-04T00:00:00Z';`, 'wrong source entity allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY sales_invoice_cash_allocation:wrong_currency SET owned_by = rebase_group:root,
      source = cash_in:wrong_currency, target = sales_invoice_issue:issue, amount = 1dec,
      effective_at = d'2026-06-04T00:00:00Z';`, 'wrong source currency allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:wrong_source_type SET owned_by = rebase_group:root,
      allocation = cash_in:receipt, policy_version = customer_withholding_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'non-allocation source type rejects');

    await db.query(`CREATE ONLY customer_withholding:withheld SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation,
      policy_version = customer_withholding_policy_version:policy_v1,
      amount = 10dec, effective_at = d'2026-06-05T00:00:00Z';`);
    state = await oracle(db, 10);
    const stableId = String(state.withholdings[0].id);
    assert.equal(measure(state.customer, 'z_history', 'receivable'), 0, 'customer AR is cleared once');
    assert.equal(measure(state.invoice, 'z_outstanding', 'outstanding'), 0, 'invoice outstanding is cleared once');
    assert.equal(measure(state.tax_tds, 'z_history', 'receivable'), 10, 'selected tax account receivable is 10');

    await rejectsUnchanged(db, "UPDATE customer_withholding_policy_version:policy_v1 SET valid_until = d'2028-01-01T00:00:00Z';",
      'selected immutable policy version rejects mutation');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:duplicate SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation,
      policy_version = customer_withholding_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'duplicate withholding per allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:zero SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation, policy_version = customer_withholding_policy_version:policy_v1,
      amount = 0dec, effective_at = d'2026-06-05T00:00:00Z';`, 'zero withholding rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:precision SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation, policy_version = customer_withholding_policy_version:policy_v1,
      amount = 1.001dec, effective_at = d'2026-06-05T00:00:00Z';`, 'excess currency precision rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:too_large SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation, policy_version = customer_withholding_policy_version:policy_v1,
      amount = 11dec, effective_at = d'2026-06-05T00:00:00Z';`, 'shared customer and invoice over-clear rejects atomically');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:wrong_entity SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation, policy_version = customer_withholding_policy_version:policy_other,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'policy entity mismatch rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:wrong_currency SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation, policy_version = customer_withholding_policy_version:policy_eur,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'policy currency mismatch rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding_policy_version:wrong_tax_identity SET owned_by = rebase_group:root,
      tax_claim_account = claim_account:not_tax, policy_key = 'fixture-customer-withholding', version = 'not-tax',
      valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';`,
    'policy without a tax-account opponent rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:outside_policy SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation, policy_version = customer_withholding_policy_version:policy_expired,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'expired policy version rejects');
    await rejectsUnchanged(db, `CREATE ONLY customer_withholding:before_invoice SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation, policy_version = customer_withholding_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'withholding before invoice/allocation rejects');
    await rejectsUnchanged(db, 'UPDATE customer_withholding:withheld SET amount = 11dec;',
      'failed fact edit restores the complete graph');
    await rejectsUnchanged(db, "UPDATE sales_invoice_cash_allocation:allocation SET effective_at = d'2026-06-06T00:00:00Z';",
      'allocation date move past withholding is tracked and rolls back');
    await rejectsUnchanged(db, "UPDATE sales_invoice_issue:issue SET issued_at = d'2026-06-06T00:00:00Z';",
      'invoice issue date move past withholding is tracked and rolls back');

    await db.query('UPDATE customer_withholding:withheld SET amount = 8dec;');
    state = await oracle(db, 8);
    assert.equal(String(state.withholdings[0].id), stableId, 'fact ID remains stable on edit');
    assert.equal(JSON.stringify(state.cash.z_history), cashBefore, 'fact edit leaves treasury unchanged');
    assert.equal(JSON.stringify(state.cashins.find((row) => String(row.id) === 'cash_in:receipt').z_allocations),
      sourcePoolBefore, 'fact edit leaves cash allocation capacity unchanged');
    assert.equal(JSON.stringify(state.stock.z_history), stockBefore, 'fact edit leaves stock unchanged');
    await db.query('DELETE customer_withholding:withheld;');
    state = await oracle(db, 0);
    assert.equal(JSON.stringify(state.cash.z_history), cashBefore, 'fact removal leaves treasury unchanged');
    assert.equal(JSON.stringify(state.cashins.find((row) => String(row.id) === 'cash_in:receipt').z_allocations),
      sourcePoolBefore, 'fact removal leaves cash allocation capacity unchanged');
    assert.equal(JSON.stringify(state.stock.z_history), stockBefore, 'fact removal leaves stock unchanged');
    await db.query(`CREATE ONLY customer_withholding:withheld SET owned_by = rebase_group:root,
      allocation = sales_invoice_cash_allocation:allocation,
      policy_version = customer_withholding_policy_version:policy_v1,
      amount = 10dec, effective_at = d'2026-06-05T00:00:00Z';`);
    state = await oracle(db, 10);
    assert.equal(String(state.withholdings[0].id), stableId, 're-addition reuses the stable fact ID');
    assert.equal(JSON.stringify(state.cash.z_history), cashBefore, 'fact re-addition leaves treasury unchanged');
    assert.equal(JSON.stringify(state.cashins.find((row) => String(row.id) === 'cash_in:receipt').z_allocations),
      sourcePoolBefore, 'fact re-addition leaves cash allocation capacity unchanged');
    assert.equal(JSON.stringify(state.stock.z_history), stockBefore, 'fact re-addition leaves stock unchanged');
    await rejectsUnchanged(db, 'DELETE sales_invoice_cash_allocation:allocation;',
      'referenced allocation cannot be deleted and strand its withholding fact');

    console.log('Accounting H4b4b customer-withheld TDS, allocation-linked claims, rollback, and cash/stock isolation passed');
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

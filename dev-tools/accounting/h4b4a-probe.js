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
  throw new Error('H4b4a SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    receipt: (SELECT * FROM ONLY purchase_receipt:receipt),
    allocation: (SELECT * FROM ONLY purchase_receipt_cash_allocation:allocation),
    withholdings: (SELECT * FROM supplier_withholding ORDER BY id),
    policies: (SELECT * FROM supplier_withholding_policy_version ORDER BY id),
    supplier: (SELECT * FROM ONLY claim_account:supplier),
    tax: (SELECT * FROM ONLY claim_account:tax),
    tax_other: (SELECT * FROM ONLY claim_account:tax_other),
    tax_alt: (SELECT * FROM ONLY claim_account:tax_alt),
    not_tax: (SELECT * FROM ONLY claim_account:not_tax),
    invoice: (SELECT * FROM ONLY purchase_invoice:invoice),
    stock: (SELECT * FROM ONLY stock_account:stock),
    cash: (SELECT * FROM ONLY treasury_account:cash),
    bad_cash: (SELECT * FROM ONLY treasury_account:cash_bad),
    other_cash: (SELECT * FROM ONLY treasury_account:cash_other),
    eur_cash: (SELECT * FROM ONLY treasury_account:cash_eur),
    cashouts: (SELECT * FROM cash_out ORDER BY id),
    cashins: (SELECT * FROM cash_in ORDER BY id),
    allocations: (SELECT * FROM purchase_receipt_cash_allocation ORDER BY id)
  };`));
}

const measure = (row, tree, name) => number(row?.[tree]?.summary?.measures?.[name]?.sum ?? 0);

async function oracle(db, withheld) {
  const state = await snapshot(db);
  const receipts = (await queryResult(await db.query('SELECT * FROM purchase_receipt;')) ?? []);
  const allocations = (await queryResult(await db.query('SELECT * FROM purchase_receipt_cash_allocation;')) ?? []);
  const facts = state.withholdings;
  const gross = receipts.reduce((sum, row) => sum + number(row.gross_amount), 0);
  const allocated = allocations.reduce((sum, row) => sum + number(row.amount), 0);
  const withheldOracle = facts.reduce((sum, row) => sum + number(row.amount), 0);
  assert.equal(withheldOracle, withheld, 'fact rows independently reconstruct withholding total');
  assert.equal(measure(state.supplier, 'z_history', 'payable'), gross - allocated - withheldOracle,
    'supplier payable equals receipt rows less cash allocation and withholding facts');
  assert.equal(measure(state.invoice, 'z_outstanding', 'outstanding'), gross - allocated - withheldOracle,
    'purchase invoice outstanding equals receipt rows less cash allocation and withholding facts');
  assert.equal(measure(state.tax, 'z_history', 'payable'), 0,
    'purchase assessed-tax account receives no payer-withholding payable');
  assert.equal(measure(state.tax, 'z_history', 'receivable'), 10,
    'H2 assessed tax receivable remains unchanged');
  assert.equal(measure(state.tax, 'z_history', 'net'), 10,
    'purchase assessed-tax account net remains unchanged');
  assert.equal(measure(state.tax_alt, 'z_history', 'payable'), withheldOracle,
    'selected separate withholding tax account receives the payable');
  assert.equal(measure(state.tax_alt, 'z_history', 'receivable'), 0,
    'separate withholding tax account does not duplicate the purchase assessed receivable');
  assert.equal(measure(state.tax_alt, 'z_history', 'net'), withheldOracle === 0 ? 0 : -withheldOracle,
    'withholding tax account net is its separate payable');
  assert.equal(measure(state.cash, 'z_history', 'balance'), -90,
    'withholding creates no cash; only the 90 payment is real');
  const payment = state.cashouts.find((row) => String(row.id) === 'cash_out:payment');
  assert.equal(number(payment?.z_allocations?.summary?.measures?.allocated?.sum ?? 0), 90,
    'withholding does not consume cash_out allocation capacity');
  assert.equal(measure(state.stock, 'z_history', 'quantity'), 9,
    'withholding has no stock effect');
  return state;
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label}: source, facts, cash, stock and claim roots roll back`);
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h4b4a_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:vendor SET owned_by = rebase_group:root, name = 'Vendor';
      CREATE ONLY organization:other_vendor SET owned_by = rebase_group:root, name = 'Other vendor';
      CREATE ONLY organization:authority SET owned_by = rebase_group:root, name = 'Authority';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'EUR', precision = 2;
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY item:unit SET owned_by = rebase_group:root, name = 'Unit', unit = measure_unit:each;
      CREATE ONLY tax_account:authority SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Tax';
      CREATE ONLY tax_account:authority_alt SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Other tax identity';
      CREATE ONLY treasury:main SET owned_by = rebase_group:root, name = 'Main';
      CREATE ONLY treasury:bad SET owned_by = rebase_group:root, name = 'Bad-source fixture';
      CREATE ONLY treasury:other SET owned_by = rebase_group:root, name = 'Other-entity fixture';
      CREATE ONLY treasury_account:cash SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:main, currency = currency:usd, minimum_balance = -100dec;
      CREATE ONLY treasury_account:cash_bad SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:bad, currency = currency:usd;
      CREATE ONLY treasury_account:cash_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        treasury = treasury:other, currency = currency:usd;
      CREATE ONLY treasury_account:cash_eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:main, currency = currency:eur;
      CREATE ONLY cash_in:fund_bad SET owned_by = rebase_group:root, from_party = organization:vendor,
        to_account = treasury_account:cash_bad, amount = 1dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY cash_in:fund_other SET owned_by = rebase_group:root, from_party = organization:vendor,
        to_account = treasury_account:cash_other, amount = 1dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY cash_in:fund_eur SET owned_by = rebase_group:root, from_party = organization:vendor,
        to_account = treasury_account:cash_eur, amount = 1dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY operating_unit:store SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Store';
      CREATE ONLY stock_account:stock SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:store, resource = item:unit;
      CREATE ONLY claim_account:supplier SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:vendor, currency = currency:usd;
      CREATE ONLY claim_account:tax SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:authority, currency = currency:usd;
      CREATE ONLY claim_account:tax_alt SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:authority_alt, currency = currency:usd;
      CREATE ONLY claim_account:not_tax SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:authority, currency = currency:usd;
      CREATE ONLY claim_account:tax_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        opponent = tax_account:authority, currency = currency:usd;
      CREATE ONLY claim_account:tax_eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:authority, currency = currency:eur;
      CREATE ONLY purchase_invoice:invoice SET owned_by = rebase_group:root,
        claim_account = claim_account:supplier, number = 'H4B4A-1';
      CREATE ONLY purchase_receipt:receipt SET owned_by = rebase_group:root, invoice = purchase_invoice:invoice,
        stock_account = stock_account:stock, tax_claim_account = claim_account:tax,
        quantity = 9dec, unit_price = 10dec, tax_amount = 10dec, effective_at = d'2026-06-02T00:00:00Z';
      CREATE ONLY supplier_withholding_policy_version:policy_v1 SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_alt, policy_key = 'fixture-withholding', version = 'v1',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY supplier_withholding_policy_version:policy_eur SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_eur, policy_key = 'fixture-withholding', version = 'eur',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY supplier_withholding_policy_version:policy_other SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_other, policy_key = 'fixture-withholding', version = 'other-entity',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY supplier_withholding_policy_version:policy_expired SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_alt, policy_key = 'fixture-withholding', version = 'expired',
        valid_from = d'2025-01-01T00:00:00Z', valid_until = d'2026-06-04T00:00:00Z';
      CREATE ONLY cash_out:payment SET owned_by = rebase_group:root, from_account = treasury_account:cash,
        to_party = organization:vendor, amount = 90dec, effective_at = d'2026-06-03T00:00:00Z';
      CREATE ONLY purchase_receipt_cash_allocation:allocation SET owned_by = rebase_group:root,
        source = cash_out:payment, target = purchase_receipt:receipt, amount = 90dec,
        effective_at = d'2026-06-04T00:00:00Z';
    `);

    let state = await oracle(db, 0);
    const treasuryBefore = JSON.stringify(state.cash.z_history);
    const stockBefore = JSON.stringify(state.stock.z_history);
    const allocationPoolBefore = JSON.stringify(state.cashouts.find((row) => String(row.id) === 'cash_out:payment').z_allocations);

    await db.query(`CREATE ONLY cash_out:wrong_party SET owned_by = rebase_group:root,
      from_account = treasury_account:cash_bad, to_party = organization:other_vendor,
      amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_out:wrong_entity SET owned_by = rebase_group:root,
      from_account = treasury_account:cash_other, to_party = organization:vendor,
      amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`);
    await db.query(`CREATE ONLY cash_out:wrong_currency SET owned_by = rebase_group:root,
      from_account = treasury_account:cash_eur, to_party = organization:vendor,
      amount = 1dec, effective_at = d'2026-06-03T00:00:00Z';`);
    await rejectsUnchanged(db, `CREATE ONLY purchase_receipt_cash_allocation:wrong_party SET owned_by = rebase_group:root,
      source = cash_out:wrong_party, target = purchase_receipt:receipt, amount = 1dec,
      effective_at = d'2026-06-04T00:00:00Z';`, 'wrong source party allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_receipt_cash_allocation:wrong_entity SET owned_by = rebase_group:root,
      source = cash_out:wrong_entity, target = purchase_receipt:receipt, amount = 1dec,
      effective_at = d'2026-06-04T00:00:00Z';`, 'wrong source entity allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_receipt_cash_allocation:wrong_currency SET owned_by = rebase_group:root,
      source = cash_out:wrong_currency, target = purchase_receipt:receipt, amount = 1dec,
      effective_at = d'2026-06-04T00:00:00Z';`, 'wrong source currency allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:wrong_source_type SET owned_by = rebase_group:root,
      allocation = cash_out:payment, policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-06-04T00:00:00Z';`, 'non-allocation source type rejects');

    await db.query(`CREATE ONLY supplier_withholding:withheld SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation,
      policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 10dec, effective_at = d'2026-06-05T00:00:00Z';`);
    state = await oracle(db, 10);
    const stableId = String(state.withholdings[0].id);
    assert.equal(number(state.supplier.z_history.summary.measures.payable.min_prefix ?? 0), 0,
      'supplier claim floor reaches zero');
    assert.equal(number(state.invoice.z_outstanding.summary.measures.outstanding.min_prefix ?? 0), 0,
      'purchase invoice outstanding floor reaches zero');

    await rejectsUnchanged(db, "UPDATE supplier_withholding_policy_version:policy_v1 SET valid_until = d'2028-01-01T00:00:00Z';",
      'selected immutable policy version rejects mutation');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:duplicate SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation,
      policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'duplicate withholding per allocation rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:zero SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation, policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 0dec, effective_at = d'2026-06-05T00:00:00Z';`, 'zero withholding rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:precision SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation, policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 1.001dec, effective_at = d'2026-06-05T00:00:00Z';`, 'excess currency precision rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:too_large SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation, policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 11dec, effective_at = d'2026-06-05T00:00:00Z';`, 'shared supplier and invoice over-settlement rejects atomically');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding_policy_version:wrong_tax SET owned_by = rebase_group:root,
      tax_claim_account = claim_account:not_tax, policy_key = 'fixture-withholding', version = 'invalid-tax-identity',
      valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';`,
    'policy without a tax-account opponent rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:wrong_entity SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation, policy_version = supplier_withholding_policy_version:policy_other,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'foreign tax entity rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:wrong_currency SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation, policy_version = supplier_withholding_policy_version:policy_eur,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'foreign tax currency rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:outside_policy SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation, policy_version = supplier_withholding_policy_version:policy_expired,
      amount = 1dec, effective_at = d'2026-06-05T00:00:00Z';`, 'expired policy version rejects');
    await rejectsUnchanged(db, `CREATE ONLY supplier_withholding:before_receipt SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation, policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-06-01T00:00:00Z';`, 'withholding before receipt/allocation rejects');

    await rejectsUnchanged(db, "UPDATE purchase_receipt_cash_allocation:allocation SET effective_at = d'2026-06-06T00:00:00Z';",
      'allocation date move past withholding is tracked and rolls back');
    await rejectsUnchanged(db, "UPDATE purchase_receipt:receipt SET effective_at = d'2026-06-06T00:00:00Z';",
      'receipt date move past withholding is tracked and rolls back');

    await db.query('UPDATE supplier_withholding:withheld SET amount = 8dec;');
    state = await oracle(db, 8);
    assert.equal(String(state.withholdings[0].id), stableId, 'fact ID remains stable on edit');
    assert.equal(JSON.stringify(state.cash.z_history), treasuryBefore, 'fact edit leaves cash position unchanged');
    assert.equal(JSON.stringify(state.stock.z_history), stockBefore, 'fact edit leaves stock unchanged');
    assert.equal(JSON.stringify(state.cashouts.find((row) => String(row.id) === 'cash_out:payment').z_allocations), allocationPoolBefore, 'fact edit leaves cash allocation pool unchanged');

    await db.query('DELETE supplier_withholding:withheld;');
    state = await oracle(db, 0);
    assert.equal(JSON.stringify(state.cash.z_history), treasuryBefore, 'fact removal leaves cash position unchanged');
    assert.equal(JSON.stringify(state.stock.z_history), stockBefore, 'fact removal leaves stock unchanged');
    assert.equal(JSON.stringify(state.cashouts.find((row) => String(row.id) === 'cash_out:payment').z_allocations), allocationPoolBefore, 'fact removal leaves cash allocation pool unchanged');
    await db.query(`CREATE ONLY supplier_withholding:withheld SET owned_by = rebase_group:root,
      allocation = purchase_receipt_cash_allocation:allocation,
      policy_version = supplier_withholding_policy_version:policy_v1,
      amount = 10dec, effective_at = d'2026-06-05T00:00:00Z';`);
    state = await oracle(db, 10);
    assert.equal(String(state.withholdings[0].id), stableId, 're-addition reuses the stable fact ID');
    assert.equal(JSON.stringify(state.cash.z_history), treasuryBefore, 'fact re-addition leaves cash position unchanged');
    assert.equal(JSON.stringify(state.stock.z_history), stockBefore, 'fact re-addition leaves stock unchanged');
    assert.equal(JSON.stringify(state.cashouts.find((row) => String(row.id) === 'cash_out:payment').z_allocations), allocationPoolBefore, 'fact re-addition leaves cash allocation pool unchanged');
    await rejectsUnchanged(db, 'DELETE purchase_receipt_cash_allocation:allocation;',
      'referenced allocation cannot be deleted and strand its withholding fact');

    console.log('Accounting H4b4a payer-side supplier withholding, shared-capacity guards, rollback, and cash/stock isolation passed');
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

#!/usr/bin/env node

const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { Surreal } = require('surrealdb');
const { queryResult } = require('../../gateway/utils');

const root = path.resolve(__dirname, '../..');
const decimal = (value) => Number(String(value).replace(/dec$/i, ''));
const money = (value) => Math.round(decimal(value) * 100) / 100;

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
  throw new Error('H4b3 SurrealDB did not become ready');
}

async function snapshot(db) {
  return queryResult(await db.query(`RETURN {
    receipt: (SELECT * FROM ONLY purchase_receipt:receipt),
    recognition: (SELECT * FROM purchase_tax_credit_recognition ORDER BY id),
    policy: (SELECT * FROM purchase_tax_credit_policy_version ORDER BY id),
    supplier: (SELECT * FROM ONLY claim_account:supplier),
    tax: (SELECT * FROM ONLY claim_account:tax),
    tax_eur: (SELECT * FROM ONLY claim_account:tax_eur),
    tax_other: (SELECT * FROM ONLY claim_account:tax_other),
    invoice: (SELECT * FROM ONLY purchase_invoice:invoice),
    stock: (SELECT * FROM ONLY stock_account:stock),
    cash: (SELECT * FROM ONLY treasury_account:cash)
  };`));
}

const measure = (row, tree, name) => money(row?.[tree]?.summary?.measures?.[name]?.sum ?? 0);

async function assertOracle(db, recognized) {
  const state = await snapshot(db);
  assert.equal(decimal(state.receipt.tax_amount), 18);
  assert.equal(decimal(state.receipt.base_amount), 100);
  assert.equal(decimal(state.receipt.gross_amount), 118);
  assert.equal(measure(state.tax, 'z_history', 'receivable'), 18,
    'H2 assessed receivable remains the entered receipt tax');
  assert.equal(measure(state.supplier, 'z_history', 'payable'), 118,
    'supplier payable remains base plus assessed tax');
  assert.equal(measure(state.invoice, 'z_outstanding', 'outstanding'), 118,
    'invoice outstanding remains gross receipt amount');
  assert.equal(measure(state.tax, 'z_history', 'recognized_credit'), recognized,
    'recognition has its own additive claim-account measure');
  assert.equal(measure(state.tax, 'z_history', 'net'), 18,
    'recognized credit does not change net');
  assert.equal(measure(state.stock, 'z_history', 'quantity'), 10,
    'recognition does not change the once-posted receipt stock');
  assert.equal(measure(state.cash, 'z_history', 'balance'), 0,
    'recognition does not imply cash');
  return state;
}

async function rejectsUnchanged(db, statement, label) {
  const before = await snapshot(db);
  await assert.rejects(() => db.query(statement), undefined, label);
  assert.deepEqual(await snapshot(db), before, `${label} rolls source, recognition, and roots back atomically`);
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h4b3_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:vendor SET owned_by = rebase_group:root, name = 'Vendor';
      CREATE ONLY organization:authority SET owned_by = rebase_group:root, name = 'Authority';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'EUR', precision = 2;
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY item:unit SET owned_by = rebase_group:root, name = 'Unit', unit = measure_unit:each;
      CREATE ONLY tax_account:authority SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Tax';
      CREATE ONLY tax_account:authority_alt SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'Other tax identity';
      CREATE ONLY operating_unit:store SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Store';
      CREATE ONLY stock_account:stock SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:store, resource = item:unit;
      CREATE ONLY claim_account:supplier SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = organization:vendor, currency = currency:usd;
      CREATE ONLY claim_account:tax SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:authority, currency = currency:usd;
      CREATE ONLY claim_account:tax_eur SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:authority, currency = currency:eur;
      CREATE ONLY claim_account:tax_alt SET owned_by = rebase_group:root, economic_entity = organization:entity,
        opponent = tax_account:authority_alt, currency = currency:usd;
      CREATE ONLY organization:other_entity SET owned_by = rebase_group:root, name = 'Other entity';
      CREATE ONLY claim_account:tax_other SET owned_by = rebase_group:root, economic_entity = organization:other_entity,
        opponent = tax_account:authority, currency = currency:usd;
      CREATE ONLY purchase_invoice:invoice SET owned_by = rebase_group:root,
        claim_account = claim_account:supplier, number = 'H4B3-1';
      CREATE ONLY purchase_receipt:receipt SET owned_by = rebase_group:root, invoice = purchase_invoice:invoice,
        stock_account = stock_account:stock, tax_claim_account = claim_account:tax,
        quantity = 10dec, unit_price = 10dec, tax_amount = 18dec,
        effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY purchase_tax_credit_policy_version:policy_v1 SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax, policy_key = 'fixture', version = 'v1',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY purchase_tax_credit_policy_version:policy_eur SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_eur, policy_key = 'fixture', version = 'v1',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY purchase_tax_credit_policy_version:policy_alt SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_alt, policy_key = 'fixture', version = 'v1',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
      CREATE ONLY purchase_tax_credit_policy_version:policy_other SET owned_by = rebase_group:root,
        tax_claim_account = claim_account:tax_other, policy_key = 'fixture', version = 'v1',
        valid_from = d'2026-01-01T00:00:00Z', valid_until = d'2027-01-01T00:00:00Z';
    `);

    await assertOracle(db, 0);
    await db.query(`CREATE ONLY purchase_tax_credit_recognition:recognition SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = 12dec, effective_at = d'2026-06-02T00:00:00Z';`);
    await assertOracle(db, 12);
    const stableId = String((await snapshot(db)).recognition[0].id);
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:zero SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = 0dec, effective_at = d'2026-06-02T00:00:00Z';`, 'zero amount rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:negative SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = -1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'negative amount rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:excess_precision SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = 12.001dec, effective_at = d'2026-06-02T00:00:00Z';`, 'amount beyond currency precision rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:too_large SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = 19dec, effective_at = d'2026-06-02T00:00:00Z';`, 'amount above assessed tax rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:before_receipt SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-05-31T00:00:00Z';`, 'recognition before receipt rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:outside_policy SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2027-01-01T00:00:00Z';`, 'recognition outside selected interval rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:wrong_account SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_alt,
      amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'nonmatching tax identity in same entity and currency rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:wrong_currency SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_eur,
      amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'policy currency mismatch rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:wrong_entity SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_other,
      amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'policy entity mismatch rejects');
    await rejectsUnchanged(db, `CREATE ONLY purchase_tax_credit_recognition:duplicate SET owned_by = rebase_group:root,
      receipt = purchase_receipt:receipt, policy_version = purchase_tax_credit_policy_version:policy_v1,
      amount = 1dec, effective_at = d'2026-06-02T00:00:00Z';`, 'second current recognition for one receipt rejects');
    await rejectsUnchanged(db, 'DELETE purchase_receipt:receipt;', 'receipt delete is protected while recognition exists');
    await rejectsUnchanged(db, 'UPDATE purchase_receipt:receipt SET tax_amount = 11dec;',
      'assessed tax reduction below recognition rejects through the tracked dependency');
    await rejectsUnchanged(db, 'UPDATE purchase_tax_credit_policy_version:policy_v1 SET valid_until = d\'2028-01-01T00:00:00Z\';',
      'selected policy version interval is immutable');

    await db.query('UPDATE purchase_tax_credit_recognition:recognition SET amount = 15dec;');
    await assertOracle(db, 15);
    assert.equal(String((await snapshot(db)).recognition[0].id), stableId, 'recognition edit preserves fact ID');
    await db.query('DELETE purchase_tax_credit_recognition:recognition;');
    await assertOracle(db, 0);
    await db.query('DELETE purchase_receipt:receipt;');
    const empty = await snapshot(db);
    assert.equal(empty.receipt == null, true);
    assert.equal(measure(empty.tax, 'z_history', 'receivable'), 0,
      'receipt deletion removes assessed receivable only through H2 source lifecycle');
    assert.equal(measure(empty.tax, 'z_history', 'recognized_credit'), 0);
    assert.equal(measure(empty.supplier, 'z_history', 'payable'), 0);
    assert.equal(measure(empty.invoice, 'z_outstanding', 'outstanding'), 0);
    assert.equal(measure(empty.stock, 'z_history', 'quantity'), 0);
    assert.equal(measure(empty.cash, 'z_history', 'balance'), 0);
    process.stdout.write('Accounting H4b3 purchase recognition, tracked assessment bound, stable lifecycle, and isolated measure passed\n');
  } finally {
    await db.close().catch(() => {});
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
  }
}

if (require.main === module) main().catch((error) => {
  console.error(`Accounting H4b3: FAIL: ${error.stack || error}`);
  process.exitCode = 1;
});

module.exports = { main };

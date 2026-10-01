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
const id = (value) => String(value);

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
    const ready = await new Promise((resolve) => {
      const socket = net.connect(port, '127.0.0.1');
      const finish = (value) => { socket.destroy(); resolve(value); };
      socket.setTimeout(100, () => finish(false));
      socket.once('connect', () => finish(true));
      socket.once('error', () => finish(false));
    });
    if (ready) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('H4a SurrealDB did not become ready');
}

async function graph(db) {
  return queryResult(await db.query(`RETURN {
    rules: (SELECT * FROM sales_tax_rule_version ORDER BY id),
    issues: (SELECT * FROM sales_invoice_issue ORDER BY id),
    lines: (SELECT * FROM sales_invoice_line ORDER BY id),
    taxes: (SELECT * FROM sales_invoice_tax_component ORDER BY id),
    customer: (SELECT * FROM ONLY claim_account:customer),
    tax_a: (SELECT * FROM ONLY claim_account:tax_a),
    tax_b: (SELECT * FROM ONLY claim_account:tax_b),
    tax_eur: (SELECT * FROM ONLY claim_account:tax_eur),
    invoice_a: (SELECT * FROM ONLY sales_invoice:invoice_a),
    invoice_b: (SELECT * FROM ONLY sales_invoice:invoice_b),
    stock_a: (SELECT * FROM ONLY stock_out:dispatch_a),
    stock_b: (SELECT * FROM ONLY stock_out:dispatch_b)
  };`));
}

function sum(owner, rootField, measure) {
  return money(owner?.[rootField]?.summary?.measures?.[measure]?.sum ?? 0);
}

async function oracle(db) {
  const data = await graph(db);
  const rules = new Map(data.rules.map((row) => [id(row.id), row]));
  const expectedTax = new Map();
  let customer = 0;
  let taxA = 0;
  let taxB = 0;
  const invoice = new Map([['sales_invoice:invoice_a', 0], ['sales_invoice:invoice_b', 0]]);
  for (const issue of data.issues) {
    const source = id(issue.id);
    const base = money(issue.lines.reduce((total, line) => total + money(decimal(line.billed_quantity) * decimal(line.unit_price)), 0));
    customer = money(customer + base);
    invoice.set(id(issue.invoice), money(invoice.get(id(issue.invoice)) + base));
    for (const component of issue.tax_components) {
      const rule = component.rule_version ? rules.get(id(component.rule_version)) : null;
      if (component.rule_version) assert(rule, 'selected immutable version exists');
      const amount = rule
        ? rule.kind === 'fixed' ? money(rule.fixed_amount) : money(base * decimal(rule.rate))
        : money(component.amount);
      const key = `${source}|tax:${component.tax_key}`;
      expectedTax.set(key, { amount, ruleVersion: component.rule_version && id(component.rule_version) });
      customer = money(customer + amount);
      invoice.set(id(issue.invoice), money(invoice.get(id(issue.invoice)) + amount));
      if (id(component.tax_claim_account) === 'claim_account:tax_a') taxA = money(taxA + amount);
      else if (id(component.tax_claim_account) === 'claim_account:tax_b') taxB = money(taxB + amount);
      else assert.fail(`unexpected tax claim ${component.tax_claim_account}`);
    }
  }
  assert.equal(data.taxes.length, expectedTax.size, 'exactly one child per selected tax component');
  for (const tax of data.taxes) {
    const expected = expectedTax.get(`${tax.rebase_managed_source}|${tax.rebase_managed_role}`);
    assert(expected, `unexpected managed tax child ${tax.id}`);
    assert.equal(money(tax.amount), expected.amount, 'managed child amount follows the selected source');
    assert.equal(tax.rule_version ? id(tax.rule_version) : undefined, expected.ruleVersion || undefined,
      'managed child pins the exact selected version');
    const issue = data.issues.find((row) => id(row.id) === tax.rebase_managed_source);
    assert.equal(String(tax.effective_at), String(issue.issued_at), 'tax recognition follows issue time');
  }
  assert.equal(sum(data.customer, 'z_history', 'receivable'), customer);
  assert.equal(sum(data.customer, 'z_history', 'net'), customer);
  assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), invoice.get('sales_invoice:invoice_a'));
  assert.equal(sum(data.invoice_b, 'z_outstanding', 'outstanding'), invoice.get('sales_invoice:invoice_b'));
  assert.equal(sum(data.tax_a, 'z_history', 'payable'), taxA);
  assert.equal(sum(data.tax_b, 'z_history', 'payable'), taxB);
  assert.equal(sum(data.tax_a, 'z_history', 'net'), taxA === 0 ? 0 : -taxA);
  assert.equal(sum(data.tax_b, 'z_history', 'net'), taxB === 0 ? 0 : -taxB);
  assert.equal(sum(data.tax_eur, 'z_history', 'payable'), 0);
  assert.equal(sum(data.stock_a, 'z_billing', 'billed'),
    money(data.lines.filter((line) => id(line.source) === 'stock_out:dispatch_a')
      .reduce((total, line) => total + money(line.billed_quantity), 0)));
  assert.equal(sum(data.stock_b, 'z_billing', 'billed'),
    money(data.lines.filter((line) => id(line.source) === 'stock_out:dispatch_b')
      .reduce((total, line) => total + money(line.billed_quantity), 0)));
  return data;
}

async function rejectsWithoutChange(db, operation, label) {
  const before = await graph(db);
  await assert.rejects(() => db.query(operation), undefined, label);
  assert.deepEqual(await graph(db), before, `${label} restores source, children, and all roots`);
}

async function main() {
  const schema = fs.readFileSync(path.join(root, 'build/all-in-accounting/schema.surql'), 'utf8');
  const port = await freePort();
  const namespace = `accounting_h4a_${Date.now().toString(36)}`;
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
      CREATE ONLY organization:authority SET owned_by = rebase_group:root, name = 'Authority';
      CREATE ONLY currency:usd SET owned_by = rebase_group:root, code = 'USD', name = 'USD', precision = 2;
      CREATE ONLY currency:eur SET owned_by = rebase_group:root, code = 'EUR', name = 'EUR', precision = 2;
      CREATE ONLY measure_unit:each SET owned_by = rebase_group:root, code = 'each', name = 'Each', dimension = 'count';
      CREATE ONLY item:unit SET owned_by = rebase_group:root, name = 'Unit', unit = measure_unit:each;
      CREATE ONLY operating_unit:store SET owned_by = rebase_group:root, economic_entity = organization:entity, name = 'Store';
      CREATE ONLY stock_account:stock SET owned_by = rebase_group:root, economic_entity = organization:entity,
        operating_unit = operating_unit:store, resource = item:unit;
      CREATE ONLY stock_in:seed SET owned_by = rebase_group:root, from_party = organization:customer,
        to_account = stock_account:stock, quantity = 10dec, effective_at = d'2026-06-01T00:00:00Z';
      CREATE ONLY stock_out:dispatch_a SET owned_by = rebase_group:root, from_account = stock_account:stock,
        to_party = organization:customer, quantity = 2dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY stock_out:dispatch_b SET owned_by = rebase_group:root, from_account = stock_account:stock,
        to_party = organization:customer, quantity = 2dec, effective_at = d'2026-07-01T00:00:00Z';
      CREATE ONLY tax_account:identity_a SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'A';
      CREATE ONLY tax_account:identity_b SET owned_by = rebase_group:root,
        authority = organization:authority, jurisdiction = organization:entity, label = 'B';
      CREATE ONLY claim_account:customer SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = organization:customer, currency = currency:usd;
      CREATE ONLY claim_account:tax_a SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = tax_account:identity_a, currency = currency:usd;
      CREATE ONLY claim_account:tax_b SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = tax_account:identity_b, currency = currency:usd;
      CREATE ONLY claim_account:tax_eur SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = tax_account:identity_a, currency = currency:eur;
      CREATE ONLY sales_invoice:invoice_a SET owned_by = rebase_group:root,
        claim_account = claim_account:customer, number = 'H4A-A';
      CREATE ONLY sales_invoice:invoice_b SET owned_by = rebase_group:root,
        claim_account = claim_account:customer, number = 'H4A-B';
      CREATE ONLY sales_tax_rule_version:fixed_v1 SET owned_by = rebase_group:root,
        component_key = 'fixed', version = 'v1', tax_claim_account = claim_account:tax_a,
        regime = 'fixture', provision = 'fixed', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'fixed', fixed_amount = 1dec;
      CREATE ONLY sales_tax_rule_version:rate_v1 SET owned_by = rebase_group:root,
        component_key = 'rate', version = 'v1', tax_claim_account = claim_account:tax_b,
        regime = 'fixture', provision = 'proportional', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.10dec;
      CREATE ONLY sales_tax_rule_version:rate_v2 SET owned_by = rebase_group:root,
        component_key = 'rate', version = 'v2', tax_claim_account = claim_account:tax_b,
        regime = 'fixture', provision = 'proportional', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.20dec;
      CREATE ONLY sales_tax_rule_version:wrong_key SET owned_by = rebase_group:root,
        component_key = 'other', version = 'v1', tax_claim_account = claim_account:tax_a,
        regime = 'fixture', provision = 'wrong key', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'fixed', fixed_amount = 1dec;
      CREATE ONLY sales_tax_rule_version:wrong_currency SET owned_by = rebase_group:root,
        component_key = 'fixed', version = 'eur', tax_claim_account = claim_account:tax_eur,
        regime = 'fixture', provision = 'wrong currency', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'fixed', fixed_amount = 1dec;
      CREATE ONLY sales_tax_rule_version:tiny SET owned_by = rebase_group:root,
        component_key = 'rate', version = 'tiny', tax_claim_account = claim_account:tax_b,
        regime = 'fixture', provision = 'rounds to zero', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.00001dec;
    `);
    await oracle(db);
    await db.query(`CREATE ONLY sales_invoice_issue:current SET owned_by = rebase_group:root,
      invoice = sales_invoice:invoice_a, issued_at = d'2026-07-02T00:00:00Z',
      lines = [{ line_key: 'dispatch', source: stock_out:dispatch_a, billed_quantity: 2dec, unit_price: 5dec }],
      tax_components = [
        { tax_key: 'fixed', tax_claim_account: claim_account:tax_a, rule_version: sales_tax_rule_version:fixed_v1 },
        { tax_key: 'rate', tax_claim_account: claim_account:tax_b, rule_version: sales_tax_rule_version:rate_v1 }
      ];`);
    let data = await oracle(db);
    assert.equal(sum(data.customer, 'z_history', 'receivable'), 12);
    assert.equal(sum(data.tax_a, 'z_history', 'payable'), 1);
    assert.equal(sum(data.tax_b, 'z_history', 'payable'), 1);
    const fixedId = id(data.taxes.find((row) => row.rebase_managed_role === 'tax:fixed').id);
    const rateId = id(data.taxes.find((row) => row.rebase_managed_role === 'tax:rate').id);

    await db.query(`UPDATE sales_invoice_issue:current SET lines = [
      { line_key: 'dispatch', source: stock_out:dispatch_a, billed_quantity: 1.5dec, unit_price: 5dec }];`);
    data = await oracle(db);
    assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), 9.25);
    assert.equal(id(data.taxes.find((row) => row.rebase_managed_role === 'tax:fixed').id), fixedId);
    assert.equal(id(data.taxes.find((row) => row.rebase_managed_role === 'tax:rate').id), rateId);

    await db.query(`CREATE ONLY sales_invoice_issue:old SET owned_by = rebase_group:root,
      invoice = sales_invoice:invoice_b, issued_at = d'2026-07-02T00:00:00Z',
      lines = [{ line_key: 'dispatch', source: stock_out:dispatch_b, billed_quantity: 2dec, unit_price: 5dec }],
      tax_components = [
        { tax_key: 'rate', tax_claim_account: claim_account:tax_b, rule_version: sales_tax_rule_version:rate_v1 }
      ];`);
    await oracle(db);
    await db.query(`UPDATE sales_invoice_issue:current SET issued_at = d'2026-07-03T00:00:00Z',
      tax_components = [
        { tax_key: 'fixed', tax_claim_account: claim_account:tax_a, rule_version: sales_tax_rule_version:fixed_v1 },
        { tax_key: 'rate', tax_claim_account: claim_account:tax_b, rule_version: sales_tax_rule_version:rate_v2 }
      ];`);
    data = await oracle(db);
    assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), 10);
    assert.equal(sum(data.invoice_b, 'z_outstanding', 'outstanding'), 11);
    assert.equal(id(data.taxes.find((row) => row.rebase_managed_source === 'sales_invoice_issue:current'
      && row.rebase_managed_role === 'tax:rate').id), rateId);
    assert.equal(id(data.taxes.find((row) => row.rebase_managed_source === 'sales_invoice_issue:old').rule_version),
      'sales_tax_rule_version:rate_v1');

    await db.query("UPDATE sales_invoice_issue:current SET issued_at = d'2026-07-04T00:00:00Z';");
    await oracle(db);

    await rejectsWithoutChange(db, `UPDATE sales_tax_rule_version:rate_v1 SET rate = 0.30dec;`, 'selected version is immutable');
    await rejectsWithoutChange(db, `DELETE sales_tax_rule_version:rate_v1;`, 'selected version cannot be deleted');
    await rejectsWithoutChange(db, `CREATE ONLY sales_tax_rule_version:bad_shape SET owned_by = rebase_group:root,
      component_key = 'bad', version = 'v1', tax_claim_account = claim_account:tax_a,
      regime = 'fixture', provision = 'invalid shape', valid_from = d'2026-07-01T00:00:00Z',
      valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.10dec,
      fixed_amount = 1dec;`, 'rule calculation shape is exclusive');
    await rejectsWithoutChange(db, `CREATE ONLY sales_tax_rule_version:bad_precision SET owned_by = rebase_group:root,
      component_key = 'bad', version = 'precision', tax_claim_account = claim_account:tax_a,
      regime = 'fixture', provision = 'amount exceeds currency precision', valid_from = d'2026-07-01T00:00:00Z',
      valid_until = d'2026-09-01T00:00:00Z', kind = 'fixed', fixed_amount = 1.001dec;`,
    'fixed amount obeys its selected currency precision');
    await rejectsWithoutChange(db, `CREATE ONLY sales_tax_rule_version:bad_interval SET owned_by = rebase_group:root,
      component_key = 'bad', version = 'v2', tax_claim_account = claim_account:tax_a,
      regime = 'fixture', provision = 'invalid interval', valid_from = d'2026-09-01T00:00:00Z',
      valid_until = d'2026-07-01T00:00:00Z', kind = 'fixed', fixed_amount = 1dec;`,
    'rule interval is ordered');
    await rejectsWithoutChange(db, `CREATE ONLY sales_tax_rule_version:bad_account SET owned_by = rebase_group:root,
      component_key = 'bad', version = 'v3', tax_claim_account = claim_account:customer,
      regime = 'fixture', provision = 'invalid account', valid_from = d'2026-07-01T00:00:00Z',
      valid_until = d'2026-09-01T00:00:00Z', kind = 'fixed', fixed_amount = 1dec;`,
    'rule requires tax identity');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET issued_at = d'2026-09-02T00:00:00Z';`,
      'out-of-interval recognition date');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET issued_at = d'2026-06-30T00:00:00Z';`,
      'issue before delivery and rule interval');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'fixed', tax_claim_account: claim_account:tax_a, rule_version: sales_tax_rule_version:wrong_key }
    ];`, 'wrong component key');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'fixed', tax_claim_account: claim_account:tax_eur, rule_version: sales_tax_rule_version:wrong_currency }
    ];`, 'wrong rule currency');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'fixed', tax_claim_account: claim_account:customer, rule_version: sales_tax_rule_version:fixed_v1 }
    ];`, 'wrong tax claim account');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'fixed', tax_claim_account: claim_account:tax_a, rule_version: sales_tax_rule_version:fixed_v1 },
      { tax_key: 'fixed', tax_claim_account: claim_account:tax_a, amount: 1dec }
    ];`, 'duplicate component key');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'rate', tax_claim_account: claim_account:tax_b, rule_version: sales_tax_rule_version:tiny }
    ];`, 'positive rate rounds to zero');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'fixed', tax_claim_account: claim_account:tax_a, amount: 1dec,
        rule_version: sales_tax_rule_version:fixed_v1 }
    ];`, 'manual and rule are exclusive');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'fixed', tax_claim_account: claim_account:tax_a }
    ];`, 'component requires manual amount or version');

    await db.query(`UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'fixed', tax_claim_account: claim_account:tax_a, rule_version: sales_tax_rule_version:fixed_v1 },
      { tax_key: 'rate', tax_claim_account: claim_account:tax_b, rule_version: sales_tax_rule_version:rate_v2 },
      { tax_key: 'manual', tax_claim_account: claim_account:tax_a, amount: 0.50dec }
    ];`);
    data = await oracle(db);
    assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), 10.5, 'H3a manual path coexists');
    await db.query(`UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'rate', tax_claim_account: claim_account:tax_b, rule_version: sales_tax_rule_version:rate_v2 }
    ];`);
    data = await oracle(db);
    assert.equal(data.taxes.some((row) => id(row.id) === fixedId), false, 'component removal deletes stable child');
    await db.query(`DELETE sales_invoice_issue:current;`);
    data = await oracle(db);
    assert.equal(data.taxes.length, 1, 'parent deletion leaves only the older pinned source');
    assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), 0);
    assert(data.stock_a, 'physical dispatch survives invoice deletion');
    process.stdout.write('Accounting H4a fixed/proportional versions, parent-only calculation, rollback and H3a manual path passed\n');
  } finally {
    await db.close().catch(() => {});
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
  }
}

if (require.main === module) main().catch((error) => {
  console.error(`Accounting H4a: FAIL: ${error.stack || error}`);
  process.exitCode = 1;
});

module.exports = { main };

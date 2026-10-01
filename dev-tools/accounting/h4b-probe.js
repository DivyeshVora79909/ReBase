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
  throw new Error('H4b SurrealDB did not become ready');
}

async function graph(db) {
  return queryResult(await db.query(`RETURN {
    rules: (SELECT * FROM sales_tax_rule_version ORDER BY id),
    issues: (SELECT * FROM sales_invoice_issue ORDER BY id),
    lines: (SELECT * FROM sales_invoice_line ORDER BY id),
    taxes: (SELECT * FROM sales_invoice_tax_component ORDER BY id),
    bases: (SELECT * FROM sales_invoice_aggregate_tax_basis ORDER BY id),
    aggregateTaxes: (SELECT * FROM sales_invoice_aggregate_tax_component ORDER BY id),
    customer: (SELECT * FROM ONLY claim_account:customer),
    tax_a: (SELECT * FROM ONLY claim_account:tax_a),
    tax_b: (SELECT * FROM ONLY claim_account:tax_b),
    tax_eur: (SELECT * FROM ONLY claim_account:tax_eur),
    tax_jpy: (SELECT * FROM ONLY claim_account:tax_jpy),
    customer_jpy: (SELECT * FROM ONLY claim_account:customer_jpy),
    invoice_a: (SELECT * FROM ONLY sales_invoice:invoice_a),
    invoice_b: (SELECT * FROM ONLY sales_invoice:invoice_b),
    invoice_jpy: (SELECT * FROM ONLY sales_invoice:invoice_jpy),
    stock_a: (SELECT * FROM ONLY stock_out:dispatch_a),
    stock_b: (SELECT * FROM ONLY stock_out:dispatch_b),
    stock: (SELECT * FROM ONLY stock_account:stock),
    treasury: (SELECT * FROM ONLY treasury_account:cash)
  };`));
}

function sum(owner, rootField, measure) {
  return money(owner?.[rootField]?.summary?.measures?.[measure]?.sum ?? 0);
}

function assertAggregateOracle(data) {
  const issue = data.issues.find((row) => id(row.id) === 'sales_invoice_issue:current');
  const ruleRows = new Map(data.rules.map((row) => [id(row.id), row]));
  const base = money(issue.lines.reduce((total, line) => total
    + money(decimal(line.billed_quantity) * decimal(line.unit_price)), 0));
  const component = issue.tax_components.find((row) => row.aggregate_rule_version != null);
  const rule = ruleRows.get(id(component.aggregate_rule_version));
  const tax = money(base * decimal(rule.rate));
  assert.equal(sum(data.invoice_a, 'z_taxable_input', 'basis'), base, 'input root independently matches rounded issue lines');
  assert.equal(money(data.bases[0].z_base), base, 'published basis independently matches eligible inputs');
  assert.equal(money(data.aggregateTaxes[0].amount), tax, 'tax child independently matches selected version and basis');
  assert.equal(sum(data.customer, 'z_history', 'receivable'), money(base + tax), 'customer receivable reconstructs from lines and tax');
  assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), money(base + tax), 'invoice outstanding reconstructs');
  assert.equal(sum(data.tax_a, 'z_history', 'payable'), tax, 'tax authority payable reconstructs from output');
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
  const namespace = `accounting_h4b_${Date.now().toString(36)}`;
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
      CREATE ONLY currency:jpy SET owned_by = rebase_group:root, code = 'JPY', name = 'JPY', precision = 0;
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
      CREATE ONLY claim_account:customer_jpy SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = organization:customer, currency = currency:jpy;
      CREATE ONLY claim_account:tax_a SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = tax_account:identity_a, currency = currency:usd;
      CREATE ONLY claim_account:tax_b SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = tax_account:identity_b, currency = currency:usd;
      CREATE ONLY claim_account:tax_eur SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = tax_account:identity_a, currency = currency:eur;
      CREATE ONLY claim_account:tax_jpy SET owned_by = rebase_group:root,
        economic_entity = organization:entity, opponent = tax_account:identity_a, currency = currency:jpy;
      CREATE ONLY sales_invoice:invoice_a SET owned_by = rebase_group:root,
        claim_account = claim_account:customer, number = 'H4A-A';
      CREATE ONLY sales_invoice:invoice_b SET owned_by = rebase_group:root,
        claim_account = claim_account:customer, number = 'H4A-B';
      CREATE ONLY sales_invoice:invoice_jpy SET owned_by = rebase_group:root,
        claim_account = claim_account:customer_jpy, number = 'H4B-JPY';
      CREATE ONLY treasury:cash SET owned_by = rebase_group:root, name = 'Cash';
      CREATE ONLY treasury_account:cash SET owned_by = rebase_group:root, economic_entity = organization:entity,
        treasury = treasury:cash, currency = currency:usd;
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
      CREATE ONLY sales_tax_rule_version:aggregate_jpy SET owned_by = rebase_group:root,
        component_key = 'aggregate', version = 'jpy', tax_claim_account = claim_account:tax_jpy,
        regime = 'fixture', provision = 'zero precision currency', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.10dec;
      CREATE ONLY sales_tax_rule_version:tiny SET owned_by = rebase_group:root,
        component_key = 'rate', version = 'tiny', tax_claim_account = claim_account:tax_b,
        regime = 'fixture', provision = 'rounds to zero', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.00001dec;
      CREATE ONLY sales_tax_rule_version:aggregate_v1 SET owned_by = rebase_group:root,
        component_key = 'aggregate', version = 'v1', tax_claim_account = claim_account:tax_a,
        regime = 'fixture', provision = 'aggregate', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.10dec;
      CREATE ONLY sales_tax_rule_version:aggregate_v2 SET owned_by = rebase_group:root,
        component_key = 'aggregate', version = 'v2', tax_claim_account = claim_account:tax_a,
        regime = 'fixture', provision = 'aggregate', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.20dec;
      CREATE ONLY sales_tax_rule_version:aggregate_tiny SET owned_by = rebase_group:root,
        component_key = 'aggregate', version = 'tiny', tax_claim_account = claim_account:tax_a,
        regime = 'fixture', provision = 'zero', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.00001dec;
      CREATE ONLY sales_tax_rule_version:aggregate_fixed SET owned_by = rebase_group:root,
        component_key = 'aggregate', version = 'fixed', tax_claim_account = claim_account:tax_a,
        regime = 'fixture', provision = 'fixed is not aggregate', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'fixed', fixed_amount = 1dec;
      CREATE ONLY sales_tax_rule_version:aggregate_two SET owned_by = rebase_group:root,
        component_key = 'aggregate-two', version = 'v1', tax_claim_account = claim_account:tax_a,
        regime = 'fixture', provision = 'second aggregate', valid_from = d'2026-07-01T00:00:00Z',
        valid_until = d'2026-09-01T00:00:00Z', kind = 'proportional', rate = 0.05dec;
    `);
    await oracle(db);
    const unchanged = await graph(db);
    const stockQuantityBefore = sum(unchanged.stock, 'z_history', 'quantity');
    const cashBefore = sum(unchanged.treasury, 'z_history', 'balance');
    await db.query(`CREATE ONLY sales_invoice_issue:current SET owned_by = rebase_group:root,
      invoice = sales_invoice:invoice_a, issued_at = d'2026-07-02T00:00:00Z',
      lines = [
        { line_key: 'one', source: stock_out:dispatch_a, billed_quantity: 1dec, unit_price: 3.334dec },
        { line_key: 'two', source: stock_out:dispatch_a, billed_quantity: 1dec, unit_price: 4.444dec }
      ], tax_components = [{ tax_key: 'aggregate', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:aggregate_v1 }];`);
    let data = await graph(db);
    assert.equal(data.lines.length, 2, 'both pre-tax invoice line children exist');
    assert.deepEqual(data.lines.map((line) => money(line.amount)).sort((a, b) => a - b), [3.33, 4.44],
      'each line is rounded before aggregation');
    assert.equal(money(3.334 + 4.444), 7.78, 'rounding the raw combined amount would produce a different basis');
    assert.equal(sum(data.invoice_a, 'z_taxable_input', 'basis'), 7.77, 'taxable basis sums rounded invoice lines');
    assert.equal(decimal(data.bases[0].z_base), 7.77, 'tree-less basis observes settled line-root total');
    assert.equal(decimal(data.aggregateTaxes[0].amount), 0.78, 'one aggregate tax rounds once at currency precision');
    assert.equal(data.aggregateTaxes.length, 1, 'exactly one aggregate output for the selected component');
    assert.equal(data.taxes.length, 0, 'aggregate component does not also enter the H4a output route');
    assert.equal(sum(data.customer, 'z_history', 'receivable'), 8.55);
    assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), 8.55);
    assert.equal(sum(data.tax_a, 'z_history', 'payable'), 0.78);
    assert.equal(sum(data.tax_a, 'z_history', 'net'), -0.78);
    assertAggregateOracle(data);
    assert.equal(sum(data.stock, 'z_history', 'quantity'), stockQuantityBefore, 'stock is unchanged by tax output');
    assert.equal(sum(data.treasury, 'z_history', 'balance'), cashBefore, 'tax output creates no cash');
    const basisId = id(data.bases[0].id);
    const taxId = id(data.aggregateTaxes[0].id);

    await db.query(`UPDATE sales_invoice_issue:current SET lines = [
      { line_key: 'one', source: stock_out:dispatch_a, billed_quantity: 2dec, unit_price: 3.33dec }
    ];`);
    data = await graph(db);
    assert.equal(data.lines.length, 1, 'removed line output is reconciled');
    assert.equal(sum(data.invoice_a, 'z_taxable_input', 'basis'), 6.66, 'line edit and removal refresh the input tree');
    assert.equal(decimal(data.bases[0].z_base), 6.66);
    assert.equal(decimal(data.aggregateTaxes[0].amount), 0.67);
    assert.equal(id(data.bases[0].id), basisId, 'basis output identity remains stable');
    assert.equal(id(data.aggregateTaxes[0].id), taxId, 'tax output identity remains stable');
    assertAggregateOracle(data);

    await db.query(`UPDATE sales_invoice_issue:current SET lines = [
      { line_key: 'one', source: stock_out:dispatch_a, billed_quantity: 1.5dec, unit_price: 4.44dec },
      { line_key: 'two', source: stock_out:dispatch_a, billed_quantity: 0.25dec, unit_price: 4dec }
    ];`);
    data = await graph(db);
    assert.equal(data.lines.length, 2, 'added eligible line child appears');
    assert.equal(sum(data.invoice_a, 'z_taxable_input', 'basis'), 7.66, 'added line refreshes input basis');
    assert.equal(decimal(data.aggregateTaxes[0].amount), 0.77, 'added line refreshes aggregate result');
    assertAggregateOracle(data);

    await db.query(`UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:aggregate_v2 }
    ];`);
    data = await graph(db);
    assert.equal(decimal(data.aggregateTaxes[0].amount), 1.53, 'explicit version selection refreshes aggregate output');
    assert.equal(id(data.aggregateTaxes[0].rule_version), 'sales_tax_rule_version:aggregate_v2');
    assert.equal(id(data.aggregateTaxes[0].id), taxId);
    assertAggregateOracle(data);

    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:aggregate_tiny }
    ];`, 'positive aggregate rate rounded to zero');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:aggregate_fixed }
    ];`, 'fixed calculation is not accepted on the aggregate route');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:aggregate_v2 },
      { tax_key: 'aggregate-two', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:aggregate_two }
    ];`, 'only one aggregate component is supported');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET issued_at = d'2026-09-02T00:00:00Z';`,
      'aggregate version is not effective on the issue date');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_b,
        aggregate_rule_version: sales_tax_rule_version:aggregate_v1 }
    ];`, 'selected rule/account mismatch');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_eur,
        aggregate_rule_version: sales_tax_rule_version:wrong_currency }
    ];`, 'currency mismatch');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_jpy,
        aggregate_rule_version: sales_tax_rule_version:aggregate_jpy }
    ];`, 'currency mismatch for the precision-zero currency');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:wrong_key }
    ];`, 'component key mismatch');

    await db.query('UPDATE claim_account:customer SET net_ceiling = 10dec;');
    await rejectsWithoutChange(db, `UPDATE sales_invoice_issue:current SET lines = [
      { line_key: 'one', source: stock_out:dispatch_a, billed_quantity: 2dec, unit_price: 6dec }
    ];`, 'downstream customer guard rolls back source, basis, tax and roots');
    await db.query('UPDATE claim_account:customer SET net_ceiling = NONE;');
    await db.query('UPDATE sales_invoice_issue:current SET tax_components = [];');
    data = await graph(db);
    assert.equal(data.bases.length, 0, 'aggregate component removal prunes its basis child');
    assert.equal(data.aggregateTaxes.length, 0, 'aggregate component removal prunes its tax child');
    assert.equal(sum(data.tax_a, 'z_history', 'payable'), 0);
    await db.query(`UPDATE sales_invoice_issue:current SET tax_components = [
      { tax_key: 'aggregate', tax_claim_account: claim_account:tax_a,
        aggregate_rule_version: sales_tax_rule_version:aggregate_v2 }
    ];`);
    data = await graph(db);
    assert.equal(id(data.aggregateTaxes[0].id), taxId, 'readding the component preserves output ID');
    await db.query('DELETE sales_invoice_issue:current;');
    data = await graph(db);
    assert.equal(data.bases.length, 0, 'issue deletion clears the basis child');
    assert.equal(data.aggregateTaxes.length, 0, 'issue deletion clears the tax child');
    assert.equal(data.lines.length, 0, 'issue deletion clears invoice-line outputs');
    assert.equal(sum(data.customer, 'z_history', 'receivable'), 0);
    assert.equal(sum(data.invoice_a, 'z_outstanding', 'outstanding'), 0);
    assert.equal(sum(data.tax_a, 'z_history', 'payable'), 0);
    await db.query(`CREATE ONLY sales_invoice_issue:jpy SET owned_by = rebase_group:root,
      invoice = sales_invoice:invoice_jpy, issued_at = d'2026-07-02T00:00:00Z',
      lines = [{ line_key: 'jpy-line', source: stock_out:dispatch_a,
        billed_quantity: 1dec, unit_price: 13.5dec }],
      tax_components = [{ tax_key: 'aggregate', tax_claim_account: claim_account:tax_jpy,
        aggregate_rule_version: sales_tax_rule_version:aggregate_jpy }];`);
    data = await graph(db);
    const jpyBasis = data.bases.find((row) => String(row.rebase_managed_source) === 'sales_invoice_issue:jpy');
    const jpyTax = data.aggregateTaxes.find((row) => String(row.rebase_managed_source) === 'sales_invoice_issue:jpy');
    assert.equal(Number(jpyBasis.z_base), 14, 'JPY pre-tax line is rounded at zero decimal places');
    assert.equal(Number(jpyTax.amount), 1, 'JPY aggregate tax rounds at zero decimal places');
    assert.equal(sum(data.customer_jpy, 'z_history', 'receivable'), 15);
    assert.equal(sum(data.invoice_jpy, 'z_outstanding', 'outstanding'), 15);
    assert.equal(sum(data.tax_jpy, 'z_history', 'payable'), 1);
    await db.query('DELETE sales_invoice_issue:jpy;');
    data = await graph(db);
    assert.equal(data.bases.some((row) => String(row.rebase_managed_source) === 'sales_invoice_issue:jpy'), false);
    assert.equal(data.aggregateTaxes.some((row) => String(row.rebase_managed_source) === 'sales_invoice_issue:jpy'), false);
    assert.equal(sum(data.customer_jpy, 'z_history', 'receivable'), 0);
    assert.equal(sum(data.invoice_jpy, 'z_outstanding', 'outstanding'), 0);
    assert.equal(sum(data.tax_jpy, 'z_history', 'payable'), 0);
    assert.equal(sum(data.stock, 'z_history', 'quantity'), stockQuantityBefore);
    assert.equal(sum(data.treasury, 'z_history', 'balance'), cashBefore);
    process.stdout.write('Accounting H4b aggregate basis, stable output, atomic guards, and no cash/stock effects passed\n');
  } finally {
    await db.close().catch(() => {});
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
  }
}

if (require.main === module) main().catch((error) => {
  console.error(`Accounting H4b: FAIL: ${error.stack || error}`);
  process.exitCode = 1;
});

module.exports = { main };

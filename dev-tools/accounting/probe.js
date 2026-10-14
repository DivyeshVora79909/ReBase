'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { Surreal, Decimal, RecordId } = require('surrealdb');
const { start, client, recordClient, applySchema } = require('../temporal-tree/harness');
const { exact } = require('./source-oracle');
const { acceptance, at, compile, create, cleanup, setup } = require('./acceptance');

async function core(h, writer) {
  const { q, mutate, reject, value, pass } = h;
  const invoice = (id, account = 'customer', kind = 'sales') =>
    create(`${kind}_invoice:${id}`, `account=organization_currency_account:${account},invoice_date=${at(10)}`);
  const issue = (id, invoiceId = id, fields = '') => create(`sales_issue:${id}`,
    `invoice=sales_invoice:${invoiceId},stock_account=stock_account:widget,counterparty_stock=organization_resource_account:customer,quantity=10dec,price=10dec,effective_at=${at(5)}${fields}`);
  const tax = (id, source, day = 6, fields = '') => create(`issue_tax:${id}`,
    `source=sales_issue:${source},tax_account=indirect_tax_account:vat,rate=10dec,effective_at=${at(day)}${fields}`);
  const note = (id, account = 'customer', kind = 'sales') =>
    create(`${kind}_adjustment_note:${id}`, `account=organization_currency_account:${account}`);
  const adjustment = (id, source, day, changes, noteId = 'credit') => create(`issue_adjustment:${id}`,
    `source=sales_issue:${source},adjustment_note=sales_adjustment_note:${noteId},effective_at=${at(day)},${changes}`);

  await reject(create('organization_currency_account:duplicate', `name='Duplicate',organization=organization:customer,currency=currency:inr,effective_at=${at(1)}`), /TREE_DUPLICATE_VALUE/);
  await reject(create('stock_account:duplicate', `name='Duplicate',subsidiary=subsidiary:one,resource=item:widget,operating_unit=operating_unit:store,valuation_pair=exchange_pair:widget_inr,effective_at=${at(1)}`), /TREE_DUPLICATE_VALUE/);
  await reject(create('account_entry:owned_claim', `account=treasury:cash,receivable=1dec,effective_at=${at(2)}`), /OWNED_ACCOUNT_REAL_ONLY/);
  await reject(create('stock_entry:negative_claim', `account=organization_resource_account:customer,payable=-1dec,effective_at=${at(2)}`), /ASSERT|assert|negative/i);
  await reject(create('misc_stock_account:wrong_subsidiary', `name='Wrong',subsidiary=subsidiary:two,resource=item:finished,operating_unit=operating_unit:store,valuation_pair=exchange_pair:finished_inr,effective_at=${at(1)}`), /ACCOUNTING_SUBSIDIARY|EXCHANGE_PAIR_DIMENSIONS/);
  await value('organization:customer.z_accounts.summary.count', 3);
  await value('subsidiary:two.z_organizations.summary.count', 1);
  await value('treasury:cash_second.z_history.summary.count', 0);
  for (const [input, expected] of [['2.5', 2], ['3.5', 4], ['-2.5', -2], ['-3.5', -4]]) {
    await value(`fn::accounting::round(${input}dec,0)`, expected);
  }
  await reject('UPDATE treasury:cash SET minimum_real=10001dec;', /ACCOUNT_BALANCE_FLOOR/);
  pass('sparse native dimensions, multiple treasuries, unit guards and decimal rounding');

  await mutate(['sale', 'empty', 'caps', 'early', 'move', 'target', 'fx'].map(id => invoice(id, id === 'fx' ? 'customer_usd' : 'customer')).join('\n') +
    invoice('purchase', 'supplier', 'purchase') + note('credit') + note('debit') + note('empty') + note('other', 'other') + note('purchase', 'supplier', 'purchase'));
  await reject(create('invoice_settlement:empty', `invoice=sales_invoice:empty,treasury=treasury:cash,amount=1dec,effective_at=${at(3)}`), /INVOICE_OVERSETTLED_AT_DATE/);
  await mutate(issue('sale'), writer);
  await value('organization_currency_account:customer.z_history.summary.measures.payable.sum', 100);
  await value('subsidiary:one.z_history.summary.measures.counterparty_receivable.sum', 100);
  await value('stock_account:widget.z_history.summary.measures.real.sum', 190);
  await value('organization_resource_account:customer.z_history.summary.measures.real.sum', 10);
  await mutate(tax('sale', 'sale') + create('issue_net_tax:sale', `source=sales_issue:sale,tax_account=indirect_tax_account:vat,rate=10dec,effective_at=${at(7)}`), writer);
  await value('issue_net_tax:sale.amount', 11);
  await mutate(create('issue_net_tax:parallel', `source=sales_issue:sale,tax_account=indirect_tax_account:vat,rate=10dec,effective_at=${at(7)}`) +
    create('issue_net_tax:later', `source=sales_issue:sale,tax_account=indirect_tax_account:vat,rate=10dec,effective_at=${at(8)}`));
  await value('issue_net_tax:parallel.amount', 11);
  await value('issue_net_tax:later.amount', '13.2');
  await mutate('UPDATE issue_tax:sale SET rate=20dec;');
  await value('issue_net_tax:sale.amount', 12);
  await mutate('DELETE ONLY issue_net_tax:later; DELETE ONLY issue_net_tax:parallel; UPDATE issue_tax:sale SET rate=10dec;');
  await reject(`UPDATE issue_net_tax:sale SET effective_at=${at(5)};`, /NET_TAX_REQUIRES_PRIOR_BASIS/);
  await reject('UPDATE issue_tax:sale SET lower_bound=6dec,upper_bound=5dec;', /TAX_BOUND_ORDER/);
  await mutate(create('invoice_settlement:advance', `invoice=sales_invoice:sale,treasury=treasury:cash,amount=90dec,effective_at=${at(3)}`), writer);
  await value(`fn::tree::read(sales_invoice:sale,'z_history','before',[${at(4)}]).measures.balance.sum`, -90);
  await reject('UPDATE invoice_settlement:advance SET amount=122dec;', /INVOICE_OVERSETTLED_AT_DATE/);
  await reject(`UPDATE sales_issue:sale SET effective_at=${at(11)};`, /ORIGINAL_ON_OR_BEFORE_INVOICE|TAX_TIME/);
  await reject(`UPDATE sales_invoice:sale SET invoice_date=${at(4)};`, /ORIGINAL_ON_OR_BEFORE_INVOICE|INVOICE_OVERSETTLED_AT_DATE|TAX_TIME/);
  pass('mirrored perspectives, direct source postings, covered advances and strictly prior net-tax bases');

  await mutate(adjustment('first', 'sale', 11, 'quantity_delta=-1dec,price_delta=1dec'));
  await value('issue_adjustment:first.amount_delta', -1);
  await mutate(create('issue_adjustment_tax:first', `source_tax=issue_tax:sale,adjustment=issue_adjustment:first,effective_at=${at(11, '00:00:01')}`) +
    create('issue_adjustment_net_tax:first', `source_tax=issue_net_tax:sale,adjustment=issue_adjustment:first,effective_at=${at(11, '00:00:02')}`));
  await value('issue_adjustment_tax:first.amount_delta', '-0.10');
  await value('issue_adjustment_net_tax:first.amount_delta', '-0.11');
  await value('sales_invoice:sale.z_history.summary.measures.receivable.sum', 121);
  await value('sales_invoice:sale.z_history.summary.measures.payable.sum', '91.21');
  await value('sales_invoice:sale.z_history.summary.measures.balance.sum', '29.79');
  await mutate(`UPDATE issue_adjustment_net_tax:first SET effective_at=${at(11, '00:00:01')};`);
  await value('issue_adjustment_net_tax:first.amount_delta', '-0.1');
  await mutate(`UPDATE issue_adjustment_net_tax:first SET effective_at=${at(11, '00:00:02')};`);
  await reject(create('issue_adjustment_tax:duplicate', `source_tax=issue_tax:sale,adjustment=issue_adjustment:first,effective_at=${at(12)}`), /unique|already contains|duplicate/i);
  await reject('UPDATE sales_adjustment_note:credit SET account=organization_currency_account:other;', /ADJUSTMENT_NOTE_DIMENSIONS/);
  await reject(adjustment('wrong_note', 'sale', 12, 'quantity_delta=-1dec', 'other'), /ADJUSTMENT_NOTE_DIMENSIONS/);
  await reject(adjustment('mixed_note', 'sale', 12, 'price_delta=1dec'), /ADJUSTMENT_NOTE_MIXED_SIGN/);
  await reject(adjustment('too_large', 'sale', 12, 'quantity_delta=-11dec'), /ISSUE_CHANGE_MAGNITUDE|ISSUE_CAPACITY/);
  await reject(adjustment('overpaid', 'sale', 12, 'quantity_delta=-4dec'), /INVOICE_OVERSETTLED_AFTER_DATE/);
  await mutate(adjustment('second', 'sale', 12, 'price_delta=-1dec') +
    create('issue_adjustment_tax:second', `source_tax=issue_tax:sale,adjustment=issue_adjustment:second,effective_at=${at(12, '00:00:01')}`) +
    create('issue_adjustment_net_tax:second', `source_tax=issue_net_tax:sale,adjustment=issue_adjustment:second,effective_at=${at(12, '00:00:02')}`));
  await value('issue_adjustment:second.amount_delta', -9);
  await mutate('UPDATE issue_adjustment:first SET quantity_delta=-2dec;');
  await value('issue_adjustment:first.amount_delta', -12);
  await value('issue_adjustment:second.amount_delta', -8);
  await mutate('UPDATE issue_adjustment:first SET quantity_delta=-1dec;');
  await mutate(create('payment_adjustment:refund', `source=invoice_settlement:advance,amount_delta=-20dec,adjustment_note=sales_adjustment_note:debit,effective_at=${at(13)}`));
  await reject(create('payment_adjustment:over_refund', `source=invoice_settlement:advance,amount_delta=-80dec,adjustment_note=sales_adjustment_note:debit,effective_at=${at(14)}`), /PAYMENT_REVERSAL_CAPACITY|INVOICE_NEGATIVE_TOTAL/);
  await reject('UPDATE payment_adjustment:refund SET entered_invoice_delta=20dec;', /PAYMENT_CHANGE_DIRECTION/);
  await mutate(create('tax_adjustment:manual', `source_tax=issue_tax:sale,amount_delta=-1dec,adjustment_note=sales_adjustment_note:credit,effective_at=${at(14)}`) +
    create('net_tax_adjustment:manual', `source_tax=issue_net_tax:sale,amount_delta=-1dec,adjustment_note=sales_adjustment_note:credit,effective_at=${at(14, '00:00:01')}`) +
    create('tax_adjustment_net_tax:manual', `source_tax=issue_net_tax:sale,adjustment=tax_adjustment:manual,effective_at=${at(14, '00:00:02')}`));
  await value('tax_adjustment_net_tax:manual.amount_delta', '-0.1');
  await mutate('UPDATE issue_tax:sale SET rate=20dec;');
  await value('issue_adjustment_tax:first.amount_delta', '-0.2');
  await value('issue_adjustment_net_tax:first.amount_delta', '-0.12');
  await mutate('UPDATE issue_tax:sale SET rate=10dec;');
  await reject(`UPDATE issue_adjustment:first SET effective_at=${at(6)};`, /ADJUSTMENT_TAX_ORDER|ADJUSTMENT_AFTER_SOURCE/);
  await reject('DELETE ONLY sales_issue:sale;', /reference|referenced/i);
  pass('product-difference adjustments, chronological cascades, all five strict tax adjustments and directional note validation');

  await mutate(issue('caps') + tax('caps', 'caps', 6, ',upper_bound=5dec'));
  await mutate(adjustment('cap_first', 'caps', 11, 'quantity_delta=-2dec') +
    create('issue_adjustment_tax:cap_first', `source_tax=issue_tax:caps,adjustment=issue_adjustment:cap_first,effective_at=${at(11, '00:00:01')}`));
  await value('issue_adjustment_tax:cap_first.amount_delta', 0);
  await mutate(adjustment('cap_second', 'caps', 12, 'quantity_delta=-4dec') +
    create('issue_adjustment_tax:cap_second', `source_tax=issue_tax:caps,adjustment=issue_adjustment:cap_second,effective_at=${at(12, '00:00:01')}`));
  await value('issue_adjustment_tax:cap_second.amount_delta', -1);
  await mutate('UPDATE issue_tax:caps SET rate=20dec;');
  await value('issue_adjustment_tax:cap_second.amount_delta', 0);
  await mutate('UPDATE issue_tax:caps SET rate=1dec,lower_bound=2dec;');
  await value('issue_tax:caps.amount', 2);
  await value('issue_adjustment_tax:cap_second.amount_delta', 0);
  await mutate(issue('early') + adjustment('early', 'early', 6, 'quantity_delta=-1dec') + tax('early', 'early', 7) +
    create('issue_net_tax:early', `source=sales_issue:early,tax_account=indirect_tax_account:vat,rate=10dec,effective_at=${at(8)}`));
  await value('issue_tax:early.basis', 90);
  await value('issue_net_tax:early.amount', '9.9');
  await reject(create('issue_adjustment_tax:double', `source_tax=issue_tax:early,adjustment=issue_adjustment:early,effective_at=${at(11)}`), /ADJUSTMENT_TAX_ORDER/);
  await mutate('UPDATE issue_adjustment:early SET quantity_delta=-2dec;');
  await value('issue_tax:early.amount', 8);
  await value('issue_net_tax:early.amount', '8.8');
  pass('capped marginal rules, pre-invoice unified adjustments and prevention of repeated dated tax effects');

  await mutate(create('purchase_issue:purchase', `invoice=purchase_invoice:purchase,stock_account=stock_account:widget,counterparty_stock=organization_resource_account:supplier,quantity=4dec,price=2dec,effective_at=${at(5)}`) +
    create('issue_tax:purchase', `source=purchase_issue:purchase,tax_account=indirect_tax_account:vat_usd,rate=10dec,effective_at=${at(6)}`) +
    create('invoice_settlement:purchase', `invoice=purchase_invoice:purchase,treasury=treasury:cash,exchange_pair=exchange_pair:inr_usd,amount=50dec,effective_at=${at(3)}`));
  await value('purchase_invoice:purchase.z_history.summary.measures.payable.sum', '8.8');
  await value('purchase_invoice:purchase.z_history.summary.measures.receivable.sum', 5);
  await value('organization_currency_account:supplier.z_history.summary.measures.net.sum', '3.8');
  await mutate(create('issue_adjustment:purchase', `source=purchase_issue:purchase,quantity_delta=-1dec,adjustment_note=purchase_adjustment_note:purchase,effective_at=${at(11)}`));
  await reject('UPDATE issue_adjustment:purchase SET adjustment_note=sales_adjustment_note:credit;', /ADJUSTMENT_NOTE_DIMENSIONS/);
  await mutate(issue('move') + issue('fx'));
  await mutate('UPDATE sales_issue:move SET invoice=sales_invoice:target;');
  await value('sales_invoice:move.z_history.summary.count', 0);
  await value('sales_invoice:target.z_history.summary.measures.amount.sum', 100);
  await mutate(invoice('other', 'other') + 'UPDATE sales_issue:move SET invoice=sales_invoice:other,counterparty_stock=organization_resource_account:other;');
  await value('organization_resource_account:other.z_history.summary.measures.real.sum', 10);
  await mutate('UPDATE sales_issue:move SET invoice=sales_invoice:target,counterparty_stock=organization_resource_account:customer;');
  await value('organization_resource_account:other.z_history.summary.count', 0);
  await mutate('UPDATE issue_tax:sale SET tax_account=indirect_tax_account:alternate;');
  await mutate('UPDATE issue_tax:sale SET tax_account=indirect_tax_account:vat;');
  pass('purchase perspective, multiple organization currencies and old/new parent repairs');

  await mutate(create('invoice_settlement:fx_late', `invoice=sales_invoice:fx,treasury=treasury:cash,exchange_pair=exchange_pair:inr_usd,amount=500dec,effective_at=${at(9)}`) +
    create('invoice_settlement:fx_early', `invoice=sales_invoice:fx,treasury=treasury:cash,exchange_pair=exchange_pair:inr_usd,amount=100dec,effective_at=${at(5)}`));
  await mutate(create('exchange_rate:later', `pair=exchange_pair:inr_usd,rate=0.12dec,effective_at=${at(8)}`));
  await mutate(create('exchange_rate:earlier', `pair=exchange_pair:inr_usd,rate=0.09dec,effective_at=${at(4)}`));
  await value('invoice_settlement:fx_early.invoice_amount', 9);
  await value('invoice_settlement:fx_late.invoice_amount', 60);
  await mutate('UPDATE exchange_rate:earlier SET rate=0.11dec;');
  await value('invoice_settlement:fx_early.invoice_amount', 11);
  await value('invoice_settlement:fx_late.invoice_amount', 60);
  await mutate('UPDATE exchange_pair:inr_usd SET initial_rate=0.105dec;');
  await value('invoice_settlement:purchase.invoice_amount', '5.25');
  await value('invoice_settlement:fx_early.invoice_amount', 11);
  await mutate(`UPDATE exchange_rate:earlier SET effective_at=${at(6)};`);
  await value('invoice_settlement:fx_early.invoice_amount', '10.5');
  await mutate('UPDATE exchange_rate:earlier SET pair=exchange_pair:usd_inr,rate=11dec;');
  await value('invoice_settlement:fx_late.invoice_amount', 60);
  await mutate('DELETE ONLY exchange_rate:earlier; UPDATE exchange_pair:inr_usd SET initial_rate=0.1dec;');
  await reject(create('exchange_rate:duplicate', `pair=exchange_pair:inr_usd,rate=0.11dec,effective_at=${at(8)}`), /TREE_DUPLICATE_VALUE/);
  await reject('UPDATE exchange_rate:later SET rate=1dec;', /INVOICE_OVERSETTLED_AT_DATE/);
  await mutate(`UPDATE invoice_settlement:fx_early SET effective_at=${at(9)};`);
  await value('invoice_settlement:fx_early.invoice_amount', 12);
  await mutate('UPDATE invoice_settlement:fx_early SET invoice=sales_invoice:target,exchange_pair=NONE;');
  await value('invoice_settlement:fx_early.invoice_amount', 100);
  await mutate('DELETE ONLY exchange_rate:later;');
  await value('invoice_settlement:fx_late.invoice_amount', 50);
  const nativeBefore = await q('RETURN [stock_account:widget.z_history.summary.measures.real.sum,organization_resource_account:customer.z_history.summary.measures.real.sum];');
  await mutate(create('exchange_rate:valuation', `pair=exchange_pair:widget_inr,rate=12dec,effective_at=${at(4)}`));
  assert.deepEqual(await q('RETURN [stock_account:widget.z_history.summary.measures.real.sum,organization_resource_account:customer.z_history.summary.measures.real.sum];'), nativeBefore);
  await reject(`UPDATE exchange_pair:widget_inr SET effective_at=${at(2)};`, /RATE_NOT_EFFECTIVE/);
  await mutate('DELETE ONLY exchange_rate:valuation;');
  pass('dated rate insertion, edit, move, reparent, deletion, fallback and reader date/reference changes');

  // Deterministic edits exercise products, prefix refresh and reporting against
  // an independent source replay after every operation.
  await mutate(invoice('random') + issue('random') + note('random'));
  for (let i = 0; i < 12; i++) {
    const price = 8 + (i * 7 % 9) / 10;
    await mutate(`UPDATE sales_issue:random SET price=${price}dec;`);
    await mutate(adjustment(`random_${i}`, 'random', 11 + i, 'quantity_delta=-0.25dec,price_delta=0.01dec', 'random'));
  }
  const native = new Surreal();
  try {
    await native.connect(h.url + '/rpc');
    await native.signin({ username: 'root', password: 'root' });
    await native.use({ namespace: 'temporal_probe', database: 'fixture' });
    const rows = await native.query('CREATE ONLY $id CONTENT $content;', {
      id: new RecordId('account_entry', 'native_decimal'),
      content: { owned_by: new RecordId('rebase_tenant', 'default'), account: new RecordId('misc_currency_account', 'precise'),
        real: new Decimal('0.123456789012345678'), effective_at: new Date('2027-01-02T00:00:00Z') },
    });
    assert(rows[0].real instanceof Decimal);
    exact(rows[0].real, '0.123456789012345678', 'native SDK decimal');
  } finally { await native.close(); }
  await h.check(); h.result.checkpoints++;
  await mutate(issue('protected', 'sale', ',amount=999dec'), writer);
  await value('sales_issue:protected.amount', 100);
  await reject('UPDATE subsidiary:one SET net_ceiling=0dec;', /ACCOUNT_NET_CEILING/);
  pass('bounded source-oracle mutation replay, native SDK decimals and protected derived amounts');
}

async function main({ extensions = false, onlyExtensions = false, evidence } = {}) {
  const compiled = compile(), server = await start({ engine: 'surrealkv' }), q = client(server.url);
  const h = acceptance(q, compiled); h.url = server.url;
  const started = new Date();
  const timingMs = {};
  try {
    console.log('CHECK fresh accounting schema application (disposable SurrealKV)');
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    let timer = Date.now();
    await applySchema(q, compiled.bundle);
    timingMs.applySchema = Date.now() - timer;
    timer = Date.now();
    await setup(q); await h.check();
    timingMs.setup = Date.now() - timer;
    timer = Date.now();
    const writer = await recordClient(server.url, 'accounting_writer');
    if (!onlyExtensions) await core(h, writer);
    if (extensions || onlyExtensions) await require('./extension-probe').extensions(h, writer);
    timingMs.scenarios = Date.now() - timer;
    console.log('CHECK populated identical-schema reapplication');
    h.result.last = 'populated schema reapplication';
    const before = await h.snapshot();
    timer = Date.now();
    await applySchema(q, compiled.bundle);
    assert.deepEqual(await h.snapshot(), before, 'identical schema application preserves every compiled table and private row');
    await h.check(); h.pass('exact populated schema reapplication');
    timingMs.reapplySchema = Date.now() - timer;
    timer = Date.now();
    await cleanup(h);
    timingMs.cleanup = Date.now() - timer;
    const fingerprintFiles = ['framework/reads.surql','dev-tools/compiler/reads.surql','dev-tools/compiler/temporal.surql',
      'dev-tools/compiler/derived-order.js','dev-tools/compiler/generators/temporal.js','dev-tools/compiler/generators/tree.js',
      'dev-tools/accounting/acceptance.js','dev-tools/accounting/probe.js','dev-tools/accounting/extension-probe.js',
      'dev-tools/accounting/source-oracle.js','dev-tools/accounting/integrity-fx-probe.js',
      'dev-tools/temporal-tree/read-oracle.js','dev-tools/temporal-tree/read-oracle.test.js',
      'dev-tools/temporal-tree/observed-probe.js','dev-tools/temporal-tree/typed-probe.js'];
    const report = { started: started.toISOString(), finished: new Date().toISOString(), storage: 'SurrealKV',
      runtime: { node: process.version, surreal: execFileSync(process.env.REBASE_TREE_SURREAL_BIN || 'surreal', ['version'], { encoding: 'utf8' }).trim() },
      schemaSha256: createHash('sha256').update(compiled.bundle).digest('hex'), schemaBytes: Buffer.byteLength(compiled.bundle),
      tables: compiled.schema.tables.size, snapshottedTables: [...compiled.schema.tables.keys()],
      checkpoints: h.result.checkpoints, structuralChecks: h.result.structuralChecks, valueChecks: h.result.valueChecks,
      rollbacks: h.result.rollbacks, unexpectedFailures: 0, cases: h.result.cases, timingMs,
      commands: ['npm run build:all-in-accounting', 'npm run check:all-in-accounting',
        'surreal validate build/all-in-accounting/schema.surql',
        'node dev-tools/accounting/probe.js --all --evidence designs/rebase-system/evidence/2026-10-14-integrity-accounting.json'],
      sourceSha256: Object.fromEntries(fingerprintFiles.map(file => [file,
        createHash('sha256').update(fs.readFileSync(require('node:path').resolve(__dirname, '../..', file))).digest('hex')])) };
    if (evidence) fs.writeFileSync(evidence, JSON.stringify(report, null, 2) + '\n');
    console.log(`PASS accounting: ${report.checkpoints} source-oracle checkpoints, ${report.rollbacks} complete rollback snapshots`);
    return report;
  } catch (error) {
    console.error('Last accounting operation:', h.result.last);
    if (process.env.REBASE_ACCOUNTING_DEBUG) fs.writeFileSync(process.env.REBASE_ACCOUNTING_DEBUG, JSON.stringify(await h.snapshot(), null, 2));
    throw error;
  }
  finally { await server.close(); }
}

if (require.main === module) main({ extensions: process.argv.includes('--all'),
  evidence: process.argv.includes('--evidence') ? process.argv[process.argv.indexOf('--evidence') + 1] : undefined,
}).catch(error => { console.error(error.stack || error); process.exitCode = 1; });
module.exports = { core, main, setup };

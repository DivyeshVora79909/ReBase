#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { start, client, applySchema } = require('../temporal-tree/harness');
const { acceptance, at, compile, create, cleanup, setup } = require('./acceptance');

// This preserves the multi-currency history that exposed stale private read
// indexes. Each source statement is committed and checked independently against
// the rational source replay, every business AVL tree, and all read indexes.
async function main() {
  const compiled = compile();
  const server = await start({ engine: 'surrealkv' });
  const q = client(server.url);
  const h = acceptance(q, compiled);
  h.url = server.url;
  const started = Date.now();
  const startedAt = new Date();
  let ready = false;
  let sourceWrites = 0;

  const write = async (label, sql) => {
    h.result.last = `${label}: ${sql}`;
    console.log(`CHECK ${label}`);
    await h.mutate(sql);
    sourceWrites++;
  };
  const pair = (id, given, received, rate) => create(`exchange_pair:${id}`,
    `given_resource=${given},received_resource=${received},initial_rate=${rate}dec,effective_at=${at(1)}`);

  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, compiled.bundle);
    await setup(q);
    await h.check();
    ready = true;
    console.log('CHECK independent INR subsidiary with EUR and USD organizations');

    const dimensions = [
      create('currency:eur', "code='EUR',name='Euro',precision=2"),
      create('subsidiary:f', `name='Three currency division',currency=currency:inr,effective_at=${at(1)}`),
      create('operating_unit:f', `name='FX stockroom',subsidiary=subsidiary:f,capacity=2dec`),
      create('organization:f_eu', `name='European customer',subsidiary=subsidiary:f,currency=currency:eur,effective_at=${at(1)}`),
      create('organization:f_us', `name='American supplier',subsidiary=subsidiary:f,currency=currency:usd,effective_at=${at(1)}`),
      pair('eur_inr', 'currency:eur', 'currency:inr', 12),
      pair('usd_eur', 'currency:usd', 'currency:eur', 0.8),
      pair('eur_usd', 'currency:eur', 'currency:usd', 1.25),
      pair('widget_eur', 'item:widget', 'currency:eur', 0.8),
      create('indirect_tax_account:stress_purchase', `name='Purchase USD tax',subsidiary=subsidiary:f,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,effective_at=${at(1)}`),
      create('organization_currency_account:f_eu', `name='EU USD account',organization=organization:f_eu,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,organization_pair=exchange_pair:usd_eur,effective_at=${at(1)}`),
      create('organization_currency_account:f_us', `name='US EUR account',organization=organization:f_us,currency=currency:eur,valuation_pair=exchange_pair:eur_inr,organization_pair=exchange_pair:eur_usd,effective_at=${at(1)}`),
      create('organization_resource_account:f_eu', `name='EU widgets',organization=organization:f_eu,resource=item:widget,valuation_pair=exchange_pair:widget_inr,organization_pair=exchange_pair:widget_eur,effective_at=${at(1)}`),
      create('organization_resource_account:f_us', `name='US widgets',organization=organization:f_us,resource=item:widget,valuation_pair=exchange_pair:widget_inr,organization_pair=exchange_pair:widget_usd,effective_at=${at(1)}`),
      create('stock_account:f', `name='Owned widgets',subsidiary=subsidiary:f,operating_unit=operating_unit:f,resource=item:widget,valuation_pair=exchange_pair:widget_inr,effective_at=${at(1)}`),
      create('treasury:f', `name='USD treasury',subsidiary=subsidiary:f,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,effective_at=${at(1)}`),
      create('account_entry:f', `account=treasury:f,real=100dec,effective_at=${at(1)}`),
      create('stock_entry:f', `account=stock_account:f,real=100dec,effective_at=${at(1)}`),
    ];
    for (const [index, sql] of dimensions.entries()) await write(`dimension ${index + 1}/${dimensions.length}`, sql);
    await h.value('subsidiary:f.z_organizations.summary.count', 2);
    await h.value('organization:f_eu.z_accounts.summary.count', 2);
    await h.value('organization:f_us.z_accounts.summary.count', 2);
    await h.value('subsidiary:f.z_history.summary.measures.owned_real.sum', 2000);
    h.pass('sparse native currencies and separate organization/subsidiary reporting positions');

    const business = [
      create('sales_invoice:f', `account=organization_currency_account:f_eu,invoice_date=${at(15)}`),
      create('sales_invoice:f_late', `account=organization_currency_account:f_eu,invoice_date=${at(15)}`),
      create('purchase_invoice:f', `account=organization_currency_account:f_us,invoice_date=${at(15)}`),
      create('sales_issue:f', `invoice=sales_invoice:f,stock_account=stock_account:f,counterparty_stock=organization_resource_account:f_eu,quantity=10dec,price=5dec,effective_at=${at(5)}`),
      // Keep this between the first sale and purchase. It is the source write
      // that originally exposed the stale latest/next index summary.
      create('sales_issue:f_late', `invoice=sales_invoice:f_late,stock_account=stock_account:f,counterparty_stock=organization_resource_account:f_eu,quantity=2dec,price=10dec,effective_at=${at(10)}`),
      create('purchase_issue:f', `invoice=purchase_invoice:f,stock_account=stock_account:f,counterparty_stock=organization_resource_account:f_us,quantity=4dec,price=10dec,effective_at=${at(6)}`),
    ];
    for (const [index, sql] of business.entries()) await write(`sale/purchase source ${index + 1}/${business.length}`, sql);
    await h.value('stock_account:f.z_history.summary.measures.real.sum', 92);
    await h.value('subsidiary:f.z_history.summary.measures.owned_real.sum', 1920);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 220);
    await h.value('organization:f_eu.z_history.summary.measures.net.sum', -56);
    await h.value('organization:f_us.z_history.summary.measures.net.sum', 50);
    h.pass('original multi-currency sale/purchase trigger and independently replayed trees');

    await write('add a later USD/INR quote', create('exchange_rate:f_usd', `pair=exchange_pair:usd_inr,rate=11dec,effective_at=${at(8)}`));
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 240);
    await h.value('sales_issue:f_late.z_counterparty_subsidiary.value.measures.receivable.sum', 220);
    await h.value('subsidiary:f.z_history.summary.measures.owned_real.sum', 1920);

    await write('settle a USD customer invoice and EUR supplier invoice', create('invoice_settlement:f_sale', `invoice=sales_invoice:f,treasury=treasury:f,amount=10dec,effective_at=${at(9)}`));
    await write('settle the supplier using a directed USD/EUR rate', create('invoice_settlement:f_purchase', `invoice=purchase_invoice:f,treasury=treasury:f,amount=10dec,exchange_pair=exchange_pair:usd_eur,effective_at=${at(9)}`));
    await h.value('treasury:f.z_history.summary.measures.real.sum', 100);
    await h.value('invoice_settlement:f_purchase.invoice_amount', 8);
    await h.value('organization:f_eu.z_history.summary.measures.net.sum', -48);
    await h.value('organization:f_us.z_history.summary.measures.net.sum', 40);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 226);
    h.pass('native cash cancellation with distinct invoice-currency settlement amounts');

    await write('change USD/EUR without changing its separately authored inverse', create('exchange_rate:f_eur', `pair=exchange_pair:usd_eur,rate=0.9dec,effective_at=${at(8)}`));
    await h.value('invoice_settlement:f_purchase.invoice_amount', 9);
    await h.value('organization:f_eu.z_history.summary.measures.net.sum', -49);
    await h.value('organization:f_us.z_history.summary.measures.net.sum', '38.75');
    await h.value('exchange_pair:eur_usd.initial_rate', 1.25);
    await h.value('treasury:f.z_history.summary.measures.real.sum', 100);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 238);

    await write('insert an earlier USD/INR quote after readers already exist', create('exchange_rate:f_early', `pair=exchange_pair:usd_inr,rate=9dec,effective_at=${at(4)}`));
    await h.value('sales_issue:f.z_counterparty_subsidiary.value.measures.receivable.sum', 450);
    await h.value('sales_issue:f_late.z_counterparty_subsidiary.value.measures.receivable.sum', 220);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 188);

    await write('move USD/INR quote beyond existing readers', `UPDATE exchange_rate:f_usd SET effective_at=${at(11)};`);
    await h.value('sales_issue:f_late.z_counterparty_subsidiary.value.measures.receivable.sum', 180);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 168);
    await h.value('treasury:f.z_history.summary.measures.real.sum', 100);

    await write('delete the earlier quote and restore initial-rate fallback', 'DELETE ONLY exchange_rate:f_early;');
    await h.value('sales_issue:f_late.z_counterparty_subsidiary.value.measures.receivable.sum', 200);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 228);

    await write('create an adjustment note', create('sales_adjustment_note:f', 'account=organization_currency_account:f_eu'));
    await write('post a dated issue adjustment', create('issue_adjustment:f', `source=sales_issue:f,adjustment_note=sales_adjustment_note:f,quantity_delta=-1dec,effective_at=${at(12)}`));
    await h.value('issue_adjustment:f.amount_delta', -5);
    await h.value('issue_adjustment:f.z_counterparty_subsidiary.value.measures.payable.sum', 55);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 173);
    await h.value('stock_account:f.z_history.summary.measures.real.sum', 93);
    await h.value('organization:f_eu.z_history.summary.measures.net.sum', -44.5);

    await write('move the adjustment before the later USD/INR quote', `UPDATE issue_adjustment:f SET effective_at=${at(10)};`);
    await h.value('issue_adjustment:f.z_counterparty_subsidiary.value.measures.payable.sum', 50);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 178);

    await write('insert a widget valuation quote while preserving native units', create('exchange_rate:f_widget', `pair=exchange_pair:widget_inr,rate=12dec,effective_at=${at(8)}`));
    await h.value('stock_account:f.z_history.summary.measures.real.sum', 93);
    await h.value('subsidiary:f.z_history.summary.measures.owned_real.sum', 1928);
    await h.value('subsidiary:f.z_history.summary.measures.net.sum', 178);
    h.pass('dated adjustment reactivity and event-time stock valuation with stable native quantity');

    await write('create converted purchase invoice', create('purchase_invoice:stress_purchase', `account=organization_currency_account:f_us,invoice_date=${at(15)}`));
    await write('create purchase issue source', create('purchase_issue:stress_purchase', `invoice=purchase_invoice:stress_purchase,stock_account=stock_account:f,counterparty_stock=organization_resource_account:f_us,quantity=4dec,price=10dec,effective_at=${at(6)}`));
    await write('create original purchase tax', create('issue_tax:stress_purchase', `source=purchase_issue:stress_purchase,tax_account=indirect_tax_account:stress_purchase,exchange_pair=exchange_pair:eur_usd,rate=10dec,effective_at=${at(7)}`));
    await write('create purchase tax-on-tax source', create('issue_net_tax:stress_purchase', `source=purchase_issue:stress_purchase,tax_account=indirect_tax_account:stress_purchase,exchange_pair=exchange_pair:eur_usd,rate=10dec,effective_at=${at(8)}`));
    await write('create purchase adjustment note', create('purchase_adjustment_note:stress_purchase', 'account=organization_currency_account:f_us'));
    await write('adjust the purchase issue', create('issue_adjustment:stress_purchase', `source=purchase_issue:stress_purchase,adjustment_note=purchase_adjustment_note:stress_purchase,quantity_delta=-1dec,effective_at=${at(11)}`));
    await write('create linked base-tax adjustment', create('issue_adjustment_tax:stress_purchase', `source_tax=issue_tax:stress_purchase,adjustment=issue_adjustment:stress_purchase,effective_at=${at(12, '00:00:01')}`));
    await write('create linked net-tax adjustment after both prior quote and issue readers exist', create('issue_adjustment_net_tax:stress_purchase', `source_tax=issue_net_tax:stress_purchase,adjustment=issue_adjustment:stress_purchase,effective_at=${at(12, '00:00:02')}`));
    await h.value('issue_net_tax:stress_purchase.basis', 44);
    await h.value('issue_adjustment:stress_purchase.amount_delta', -10);
    await h.value('issue_adjustment_tax:stress_purchase.amount_delta', -1);
    await h.value('issue_adjustment_net_tax:stress_purchase.basis_delta', -11);
    await h.value('issue_adjustment_net_tax:stress_purchase.amount_delta', '-1.1');
    h.pass('converted purchase issue, tax-on-tax, adjustment children and valid latest-rate registration');

    const beforeFuture = await q('RETURN [subsidiary:f.z_history.summary.measures.net.sum, organization:f_eu.z_history.summary.measures.net.sum, organization:f_us.z_history.summary.measures.net.sum];');
    await write('add a quote later than every transaction', create('exchange_rate:f_future', `pair=exchange_pair:usd_inr,rate=100dec,effective_at=${at(30)}`));
    const afterFuture = await q('RETURN [subsidiary:f.z_history.summary.measures.net.sum, organization:f_eu.z_history.summary.measures.net.sum, organization:f_us.z_history.summary.measures.net.sum];');
    assert.deepEqual(afterFuture, beforeFuture, 'future quote cannot alter earlier source dates');
    await h.reject(create('organization_currency_account:f_duplicate', `name='Duplicate',organization=organization:f_eu,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,organization_pair=exchange_pair:usd_eur,effective_at=${at(1)}`), /TREE_DUPLICATE_VALUE|unique|duplicate/i);
    await h.reject(create('exchange_rate:f_duplicate', `pair=exchange_pair:usd_inr,rate=12dec,effective_at=${at(11)}`), /TREE_DUPLICATE_VALUE|unique|duplicate/i);
    h.pass('future quote non-interference and full rollback for duplicate sparse identities/timestamps');

    const evidenceIndex = process.argv.indexOf('--evidence');
    const evidence = evidenceIndex < 0 ? undefined : process.argv[evidenceIndex + 1];
    const report = { storage: 'SurrealKV', schemaBytes: Buffer.byteLength(compiled.bundle), checkpoints: h.result.checkpoints,
      runtime: { node: process.version, surreal: execFileSync(process.env.REBASE_TREE_SURREAL_BIN || 'surreal', ['version'], { encoding: 'utf8' }).trim() },
      schemaSha256: createHash('sha256').update(compiled.bundle).digest('hex'), snapshottedTables: [...compiled.schema.tables.keys()],
      sourceWrites, cleanupDeletes: Math.max(0, h.result.checkpoints - sourceWrites - 1),
      structuralChecks: h.result.structuralChecks, valueChecks: h.result.valueChecks,
      rollbacks: h.result.rollbacks, unexpectedFailures: 0, cases: h.result.cases,
      timingMs: { fixtureAndMutations: Date.now() - started }, started: startedAt.toISOString(), finished: new Date().toISOString(),
      invocation: { executable: process.execPath, script: process.argv[1], args: process.argv.slice(2) },
      evidenceOutput: evidence ? path.resolve(evidence) : null,
      sourceSha256: Object.fromEntries(['dev-tools/compiler/dependencies.surql','dev-tools/compiler/queries.surql',
        'dev-tools/compiler/temporal.surql','dev-tools/compiler/generators/tree.js',
        'dev-tools/accounting/acceptance.js','dev-tools/accounting/source-oracle.js',
        'dev-tools/accounting/integrity-fx-probe.js','dev-tools/temporal-tree/dependency-oracle.js']
        .map(file => [file, createHash('sha256').update(fs.readFileSync(path.resolve(__dirname, '../..', file))).digest('hex')])) };
    const cleanupStarted = Date.now();
    await cleanup(h, { verifyEach: true });
    report.checkpoints = h.result.checkpoints;
    report.timingMs.cleanup = Date.now() - cleanupStarted;
    report.timingMs.total = Date.now() - started;
    report.cleanupDeletes = Math.max(0, h.result.checkpoints - sourceWrites - 1);
    report.structuralChecks = h.result.structuralChecks;
    report.valueChecks = h.result.valueChecks;
    report.rollbacks = h.result.rollbacks;
    report.cases = h.result.cases;
    report.status = 'PASS';
    report.finished = new Date().toISOString();
    report.elapsedMs = Date.now() - started;
    if (evidence) {
      fs.mkdirSync(path.dirname(path.resolve(evidence)), { recursive: true });
      fs.writeFileSync(evidence, JSON.stringify(report, null, 2) + '\n');
    }
    console.log(`PASS accounting integrity FX: ${report.checkpoints} per-write structural/source checkpoints, ${report.rollbacks} exact rollback snapshots, ${report.elapsedMs}ms`);
    return report;
  } catch (error) {
    console.error('Last integrity FX operation:', h.result.last);
    try {
      if (String(h.result.last).includes('DELETE ONLY invoice_settlement:f_purchase')) {
        const state = await h.snapshot();
        console.error('Post-failure settlement dependency state:', JSON.stringify({
          settlement: state.invoice_settlement.find(row => row.id === 'invoice_settlement:f_purchase'),
          rates: state.exchange_pair.map(row => ({id:row.id,
            dependencies:Object.fromEntries(Object.entries(row).filter(([field])=>field.startsWith('__rebase_dependents_')))})),
        }, null, 2));
      }
    } catch (diagnosticError) { console.error('Could not capture post-failure dependency state:', diagnosticError.message); }
    throw error;
  } finally {
    if (!ready) console.error('Integrity FX fixture did not reach its first complete snapshot.');
    await server.close();
  }
}

if (require.main === module) main().catch(error => {
  console.error(`accounting integrity FX: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };

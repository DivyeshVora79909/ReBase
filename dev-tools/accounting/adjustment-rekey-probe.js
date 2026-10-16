#!/usr/bin/env node
'use strict';

// Minimal purchase, tax and settlement history preserving the adjustment
// regression that originally exposed inconsistent dependency maintenance.
const assert = require('node:assert/strict');
const { start, client, applySchema } = require('../temporal-tree/harness');
const { acceptance, at, compile, create, cleanup, setup } = require('./acceptance');

async function main() {
  const compiled = compile();
  const server = await start({ engine: 'surrealkv' });
  const q = client(server.url);
  const h = acceptance(q, compiled);
  h.url = server.url;
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, compiled.bundle);
    await setup(q);
    await h.check();

    const history = [
      ['purchase invoice', create('purchase_invoice:purchase', `account=organization_currency_account:supplier,invoice_date=${at(10)}`)],
      ['purchase adjustment note', create('purchase_adjustment_note:purchase', 'account=organization_currency_account:supplier')],
      ['purchase issue', create('purchase_issue:purchase', `invoice=purchase_invoice:purchase,stock_account=stock_account:widget,counterparty_stock=organization_resource_account:supplier,quantity=4dec,price=2dec,effective_at=${at(5)}`)],
      ['original tax', create('issue_tax:purchase', `source=purchase_issue:purchase,tax_account=indirect_tax_account:vat_usd,rate=10dec,effective_at=${at(6)}`)],
      ['advance settlement', create('invoice_settlement:purchase', `invoice=purchase_invoice:purchase,treasury=treasury:cash,exchange_pair=exchange_pair:inr_usd,amount=50dec,effective_at=${at(3)}`)],
      ['issue adjustment', create('issue_adjustment:purchase', `source=purchase_issue:purchase,adjustment_note=purchase_adjustment_note:purchase,quantity_delta=-1dec,effective_at=${at(11)}`)],
    ];
    for (const [label, sql] of history) await h.mutate(sql);

    await h.value('issue_tax:purchase.amount', '0.8');
    await h.value('invoice_settlement:purchase.invoice_amount', 5);
    await h.value('issue_adjustment:purchase.amount_delta', -2);
    await h.value('purchase_invoice:purchase.z_history.summary.measures.payable.sum', '8.8');
    await h.check();
    h.pass('minimized purchase/tax/settlement adjustment regression and exact dependency integrity');

    await cleanup(h);
    assert.equal(h.result.rollbacks, 0);
    console.log(`PASS minimized adjustment regression: ${h.result.checkpoints} structural/source checkpoints and complete cleanup`);
  } catch (error) {
    console.error('Last adjustment-regression operation:', h.result.last);
    throw error;
  } finally {
    await server.close();
  }
}

if (require.main === module) main().catch(error => {
  console.error(`accounting adjustment regression: FAIL: ${error.stack || error.message}`);
  process.exitCode = 1;
});

module.exports = { main };

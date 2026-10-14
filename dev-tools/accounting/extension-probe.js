'use strict';
const assert = require('node:assert/strict');
const { Surreal, RecordId } = require('surrealdb');
const { recordClient } = require('../temporal-tree/harness');
const { snapshot } = require('./source-oracle');
const { at, create } = require('./acceptance');
const { prepareFixture } = require('./fixture-example');

async function extensions(h, writer) {
  const { q, mutate, reject, value, pass } = h;
  await mutate(create('sales_invoice:ext', `account=organization_currency_account:customer,invoice_date=${at(10)}`) +
    create('sales_issue:ext', `invoice=sales_invoice:ext,stock_account=stock_account:widget,counterparty_stock=organization_resource_account:customer,quantity=2dec,price=100dec,effective_at=${at(5)}`) +
    create('sales_adjustment_note:ext_refund', 'account=organization_currency_account:customer'));
  const fee = 'fee_account=misc_currency_account:fees,fee_rate=1dec,fee_tax_rate=18dec,fee_tax_creditable=true,fee_tax_account=indirect_tax_account:vat';
  await mutate(create('invoice_settlement:ext_fee', `invoice=sales_invoice:ext,treasury=treasury:cash,amount=100dec,effective_at=${at(9)},${fee}`), writer);
  await value('invoice_settlement:ext_fee.fee_amount', 1);
  await value('invoice_settlement:ext_fee.fee_tax_amount', '0.18');
  await value('invoice_settlement:ext_fee.fee_credit_amount', '0.18');
  await value('invoice_settlement:ext_fee.z_cash.value.measures.real.sum', '98.82');
  await reject('UPDATE invoice_settlement:ext_fee SET fee_account=NONE;', /FEE_ACCOUNT_REQUIRED/);
  await reject('UPDATE invoice_settlement:ext_fee SET fee_tax_account=NONE;', /FEE_TAX_ACCOUNT_REQUIRED/);
  await reject('UPDATE invoice_settlement:ext_fee SET fee_lower_bound=2dec,fee_upper_bound=1dec;', /FEE_BOUNDS/);
  await mutate('UPDATE invoice_settlement:ext_fee SET fee_tax_creditable=false,fee_tax_account=NONE;');
  await value('invoice_settlement:ext_fee.fee_account_amount', '1.18');
  await mutate('UPDATE invoice_settlement:ext_fee SET fee_tax_creditable=true,fee_tax_account=indirect_tax_account:vat;');
  await mutate(create('payment_adjustment:ext_refund', `source=invoice_settlement:ext_fee,amount_delta=-10dec,adjustment_note=sales_adjustment_note:ext_refund,effective_at=${at(11)},fee_account=misc_currency_account:fees,fee_lower_bound=1dec`));
  await value('payment_adjustment:ext_refund.fee_amount', 1);
  await mutate(create('payment_withholding:ext', `source=invoice_settlement:ext_fee,tax_account=direct_tax_account:withheld,amount=10dec,effective_at=${at(11)}`));
  await value('direct_tax_account:withheld.z_history.summary.measures.receivable.sum', 10);
  await reject(`UPDATE payment_withholding:ext SET effective_at=${at(8)};`, /WITHHOLDING_BEFORE_PAYMENT/);
  pass('inline bounded fees, creditable/noncreditable fee tax, independent refund fees and withholding');

  await mutate(create('indirect_tax_account:ext_pool', `name='Pool',subsidiary=subsidiary:one,currency=currency:inr,effective_at=${at(1)}`) +
    create('indirect_tax_account:ext_usd', `name='Pool USD',subsidiary=subsidiary:one,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,effective_at=${at(1)}`) +
    create('account_entry:ext_pool', `account=indirect_tax_account:ext_pool,receivable=100dec,payable=100dec,effective_at=${at(2)}`) +
    create('account_entry:ext_usd', `account=indirect_tax_account:ext_usd,receivable=20dec,payable=100dec,effective_at=${at(2)}`));
  await mutate(create('tax_settlement:ext', `tax_account=indirect_tax_account:ext_pool,treasury=treasury:cash,amount=30dec,effective_at=${at(15)}`) +
    create('tax_deposit:ext', `tax_account=indirect_tax_account:ext_pool,treasury=treasury:cash,amount=20dec,effective_at=${at(16)}`) +
    create('tax_refund:ext', `tax_account=indirect_tax_account:ext_pool,treasury=treasury:cash,amount=10dec,effective_at=${at(17)}`) +
    create('tax_offset:ext', `credit_account=indirect_tax_account:ext_pool,liability_account=indirect_tax_account:ext_pool,amount=40dec,effective_at=${at(18)}`));
  await value('indirect_tax_account:ext_pool.z_history.summary.measures.receivable.sum', 190);
  await value('indirect_tax_account:ext_pool.z_history.summary.measures.payable.sum', 150);
  await value('indirect_tax_account:ext_pool.z_history.summary.measures.credit_available.sum', 70);
  await value('indirect_tax_account:ext_pool.z_history.summary.measures.liability_available.sum', 30);
  await reject('UPDATE tax_refund:ext SET amount=200dec;', /TAX_CLAIM_CAPACITY/);
  await reject('UPDATE account_entry:ext_pool SET receivable=0dec;', /TAX_CLAIM_CAPACITY/);
  await mutate(create('tax_settlement:ext_fee', `tax_account=indirect_tax_account:ext_pool,treasury=treasury:cash,amount=10dec,effective_at=${at(19)},fee_account=misc_currency_account:fees,fee_rate=10dec,fee_tax_rate=20dec,fee_tax_creditable=true,fee_tax_account=indirect_tax_account:ext_pool`));
  await value('tax_settlement:ext_fee.z_tax.value.measures.real.sum', '10.2');
  await mutate(create('tax_settlement:ext_fx', `tax_account=indirect_tax_account:ext_usd,treasury=treasury:cash,exchange_pair=exchange_pair:inr_usd,amount=100dec,effective_at=${at(15)}`) +
    create('tax_offset:ext_fx', `credit_account=indirect_tax_account:ext_pool,liability_account=indirect_tax_account:ext_usd,exchange_pair=exchange_pair:inr_usd,amount=10dec,effective_at=${at(18)}`) +
    create('tax_refund:ext_fx', `tax_account=indirect_tax_account:ext_usd,treasury=treasury:cash,exchange_pair=exchange_pair:inr_usd,amount=10dec,effective_at=${at(19)}`));
  await value('tax_offset:ext_fx.liability_amount', 1);
  await mutate(create('exchange_rate:ext_cash', `pair=exchange_pair:inr_usd,rate=0.11dec,effective_at=${at(15)}`));
  await value('tax_settlement:ext_fx.account_amount', 11);
  await value('tax_offset:ext_fx.liability_amount', '1.1');
  await mutate('DELETE ONLY exchange_rate:ext_cash;');
  pass('tax settlement, credit, refund and offset capacities, coincident legs and dated cash conversion');

  await mutate(create('account_claim:ext_rent', `account=organization_currency_account:customer,claim_kind='payable',amount=40dec,effective_at=${at(15)}`) +
    create('claim_settlement:ext_rent', `source=account_claim:ext_rent,paid_account=treasury:cash,amount=15dec,effective_at=${at(16)}`));
  await value('account_claim:ext_rent.z_capacity.summary.measures.remaining.sum', 25);
  await reject('UPDATE account_claim:ext_rent SET amount=10dec;', /CLAIM_SETTLEMENT_CAPACITY/);
  await reject(`UPDATE claim_settlement:ext_rent SET effective_at=${at(14)};`, /CLAIM_BEFORE_SOURCE/);
  await mutate(create('account_claim:ext_goods', `account=organization_resource_account:customer,claim_kind='receivable',amount=3dec,effective_at=${at(15)}`) +
    create('claim_settlement:ext_goods', `source=account_claim:ext_goods,paid_account=stock_account:widget,amount=1.5dec,effective_at=${at(16)}`));
  await value('claim_settlement:ext_goods.account_amount', '1.5');
  await reject('UPDATE claim_settlement:ext_goods SET fee_account=misc_currency_account:fees,fee_rate=1dec;', /FEE_CASH_LEG_REQUIRED/);
  const second = await recordClient(h.url, 'accounting_writer');
  const contenders = ['a', 'b'].map(id => create(`claim_settlement:ext_race_${id}`,
    `source=account_claim:ext_rent,paid_account=treasury:cash,amount=20dec,effective_at=${at(17)}`));
  const outcomes = await Promise.allSettled([writer(contenders[0]), second(contenders[1])]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1, 'only one competing settlement commits');
  for (let i = 0; i < outcomes.length; i++) if (outcomes[i].status === 'rejected') {
    assert.match(String(outcomes[i].reason), /conflict|retry|CLAIM_SETTLEMENT_CAPACITY/i);
    await reject(contenders[i], /CLAIM_SETTLEMENT_CAPACITY/);
  }
  await h.check(); h.result.checkpoints++;
  pass('monetary and resource claims, source-specific capacity and competing sessions');

  await mutate(create('resource_exchange:ext_damage', `from_account=stock_account:widget,to_account=misc_stock_account:damage,from_amount=2dec,effective_at=${at(18)}`) +
    create('resource_exchange:ext_subsidiary', `from_account=treasury:cash,to_account=treasury:foreign,exchange_pair=exchange_pair:inr_usd,from_amount=100dec,effective_at=${at(18)}`) +
    create('resource_exchange:ext_goods_transfer', `from_account=stock_account:foreign,to_account=stock_account:widget,from_amount=1dec,effective_at=${at(19)}`));
  await value('resource_exchange:ext_subsidiary.to_amount', 10);
  await value('misc_stock_account:damage.z_history.summary.measures.real.sum', 2);
  await mutate(create('resource_exchange:ext_fx', `from_account=treasury:usd,to_account=treasury:cash,exchange_pair=exchange_pair:usd_inr,from_amount=100dec,effective_at=${at(18)},fee_account=misc_currency_account:fees_usd,fee_rate=1dec`));
  await value('resource_exchange:ext_fx.to_amount', 1000);
  await value('exchange_pair:usd_inr.z_observations.summary.measures.given.sum', 100);
  await value('exchange_pair:usd_inr.z_observations.summary.measures.received.sum', 1000);
  await reject('UPDATE resource_exchange:ext_fx SET exchange_pair=exchange_pair:inr_usd;', /EXCHANGE_PAIR_DIMENSIONS/);
  await reject('UPDATE resource_exchange:ext_damage SET to_account=stock_account:widget;', /EXCHANGE_IDENTICAL_ACCOUNTS/);
  await mutate(create('exchange_rate:ext_trade', `pair=exchange_pair:usd_inr,rate=11dec,effective_at=${at(18)}`));
  await value('resource_exchange:ext_fx.to_amount', 1100);
  await value('exchange_pair:usd_inr.z_observations.summary.measures.received.sum', 1100);
  await mutate('DELETE ONLY exchange_rate:ext_trade;');
  pass('resource transfers, explicit cross-subsidiary legs and separate authoritative/observed exchange values');

  await mutate(create('production:ext', `name='Run',subsidiary=subsidiary:one,starts_at=${at(20)},ends_at=${at(21)}`) +
    create('production_input:ext', 'production=production:ext,stock_account=stock_account:scarce,quantity=3dec') +
    create('production_input:ext_labor', 'production=production:ext,stock_account=stock_account:labor,quantity=1dec') +
    create('production_output:ext', 'production=production:ext,stock_account=stock_account:finished,quantity=4dec') +
    create('production_cost:ext', 'production=production:ext,treasury=treasury:cash,amount=30dec,fee_account=misc_currency_account:fees,fee_rate=5dec,fee_tax_rate=20dec') +
    create('production_capacity:ext', 'production=production:ext,operating_unit=operating_unit:store,resource=service:labor,quantity=2dec'));
  await value('production_cost:ext.fee_amount', '1.5');
  await value('production_cost:ext.fee_tax_amount', '0.3');
  await value(`fn::tree::read(stock_account:scarce,'z_history','before',[${at(20, '12:00:00')}]).measures.reserved.sum`, 3);
  await value('stock_account:scarce.z_history.summary.measures.receivable.sum', 0);
  await value('stock_account:scarce.z_history.summary.measures.real.sum', 2);
  await mutate(create('stock_entry:ext_same_time', `account=stock_account:scarce,real=100dec,effective_at=${at(20)}`));
  await reject(create('production_input:ext_same_time', 'production=production:ext,stock_account=stock_account:scarce,quantity=3dec'), /PRODUCTION_GROSS_INPUT/);
  await reject('DELETE ONLY stock_entry:scarce;', /PRODUCTION_GROSS_INPUT|ACCOUNT_BALANCE_FLOOR/);
  await mutate(create('production:ext_adjacent', `name='Adjacent',subsidiary=subsidiary:one,starts_at=${at(21)},ends_at=${at(22)}`) +
    create('production_capacity:ext_adjacent', 'production=production:ext_adjacent,operating_unit=operating_unit:store,resource=service:labor,quantity=2dec') +
    create('production:ext_overlap', `name='Overlap',subsidiary=subsidiary:one,starts_at=${at(20, '12:00:00')},ends_at=${at(21, '12:00:00')}`));
  await value('operating_unit:store.z_capacity.summary.measures.used.instant_max', 2);
  await reject(create('production_capacity:ext_overlap', 'production=production:ext_overlap,operating_unit=operating_unit:store,resource=service:labor,quantity=1dec'), /OPERATING_CAPACITY/);
  await reject('UPDATE operating_unit:store SET capacity=1dec;', /OPERATING_CAPACITY/);
  await reject('UPDATE service:labor SET maximum_duration=12h;', /RESOURCE_DURATION/);
  await reject(`UPDATE service:labor SET available_until=${at(20, '12:00:00')};`, /RESOURCE_AVAILABILITY/);
  await mutate(create('resource_exchange:ext_output', `from_account=stock_account:finished,to_account=treasury:cash,exchange_pair=exchange_pair:finished_inr,from_amount=2dec,production_output=production_output:ext,effective_at=${at(22)}`));
  await reject(create('resource_exchange:ext_over_output', `from_account=stock_account:finished,to_account=treasury:cash,exchange_pair=exchange_pair:finished_inr,from_amount=3dec,production_output=production_output:ext,effective_at=${at(22)}`), /PRODUCTION_OUTPUT_CAPACITY|ACCOUNT_BALANCE_FLOOR/);
  await reject(`UPDATE resource_exchange:ext_output SET effective_at=${at(20)};`, /EXCHANGE_OUTPUT_SOURCE|PRODUCTION_OUTPUT_CAPACITY|ACCOUNT_BALANCE_FLOOR/);
  await mutate(`UPDATE production:ext SET starts_at=${at(20, '01:00:00')};`);
  await mutate(`UPDATE production:ext SET starts_at=${at(20)};`);
  pass('native reservations, gross input protection, output consumption, service windows and adjacent capacity');

  await q("CREATE rebase_tenant:isolated SET name='Isolated tenant';");
  await mutate(create('currency:hidden', "code='HID',name='Hidden'", 'rebase_tenant:isolated') +
    create('subsidiary:hidden', `name='Hidden',currency=currency:hidden,effective_at=${at(1)}`, 'rebase_tenant:isolated') +
    create('misc_currency_account:hidden', `name='Hidden',subsidiary=subsidiary:hidden,currency=currency:hidden,effective_at=${at(1)}`, 'rebase_tenant:isolated'));
  await reject('UPDATE invoice_settlement:ext_fee SET fee_account=misc_currency_account:hidden;', /tenant|TENANT|EXCHANGE_PAIR_DIMENSIONS/);
  await reject(create('invoice_settlement:ext_cross_tenant', `invoice=sales_invoice:ext,treasury=treasury:cash,amount=1dec,effective_at=${at(12)}`, 'rebase_tenant:isolated'), /tenant|TENANT/);
  await reject(create('exchange_pair:hidden', `given_resource=currency:usd,received_resource=currency:hidden,initial_rate=1dec,effective_at=${at(1)}`), /tenant|TENANT/);
  assert.deepEqual(await writer('SELECT * FROM misc_currency_account:hidden;'), []);
  await assert.rejects(writer("RETURN fn::tree::read(subsidiary:hidden,'z_history','summary',[]);"), /Tree read not allowed/);
  const treeBefore = await snapshot(q);
  await writer('UPDATE invoice_settlement:ext_fee SET z_cash={};');
  assert.deepEqual(await snapshot(q), treeBefore, 'record access cannot forge maintained tree fields');

  // Execute the published, bound fixture in its own tenant to verify that the
  // developer example creates real native records, rather than just valid JSON.
  await q("CREATE rebase_tenant:example SET name='Published example';");
  const sdk = new Surreal();
  try {
    await sdk.connect(h.url + '/rpc');
    await sdk.signin({ username: 'root', password: 'root' });
    await sdk.use({ namespace: 'temporal_probe', database: 'fixture' });
    for (const row of prepareFixture()) {
      row.content.owned_by = new RecordId('rebase_tenant', 'example');
      await sdk.query('CREATE ONLY $id CONTENT $content;', { id: row.id, content: row.content });
    }
  } finally { await sdk.close(); }
  await h.check(); h.result.checkpoints++;
  await value('sales_invoice:demo_sale.z_history.summary.measures.balance.sum', 10);
  assert.equal(await q('RETURN sales_issue:demo_issue.invoice.account.organization.name;'), 'Customer');
  assert.deepEqual(await q('RETURN sales_invoice:demo_sale<~(sales_issue FIELD invoice);'), ['sales_issue:demo_issue']);
  assert.equal((await q("RETURN fn::tree::read(organization:demo_customer,'z_accounts','find',[currency:demo_usd]);")).rid,
    'organization_currency_account:demo_currency');
  await value(`fn::tree::read(sales_invoice:demo_sale,'z_history','range',[[${at(1)}],[${at(11)}]]).measures.balance.sum`, 20);
  const page = await q("RETURN fn::tree::read(sales_invoice:demo_sale,'z_history','page',[2,NONE,false]);");
  assert.equal(page.items.length, 2); assert(page.next);
  const rest = await q("LET $first=fn::tree::read(sales_invoice:demo_sale,'z_history','page',[2,NONE,false]); RETURN fn::tree::read(sales_invoice:demo_sale,'z_history','page',[2,$first.next,false]);");
  assert.deepEqual(rest.items.map(item => item.link.rid), ['issue_adjustment:demo_credit']);
  await value('stock_account:demo_stock.z_history.summary.measures.sales_reporting_value.sum / stock_account:demo_stock.z_history.summary.measures.sales_quantity.sum', 90);
  pass('tenant isolation, protected tree fields, native-SDK fixture and graph/tree developer queries');
  const beforeRate = await snapshot(q);
  await mutate('UPDATE exchange_pair:widget_inr SET initial_rate=initial_rate+1dec;');
  const afterRate = await snapshot(q);
  for (const table of ['stock_account', 'organization_resource_account', 'misc_stock_account']) {
    assert.deepEqual(afterRate[table].map(row => [row.id, row.z_history.summary]),
      beforeRate[table].map(row => [row.id, row.z_history.summary]), 'valuation edits preserve every native stock summary');
  }
  await mutate('UPDATE exchange_pair:widget_inr SET initial_rate=initial_rate-1dec;');
  pass('late valuation edit refreshes populated reporting projections while preserving native stock');
}

if (require.main === module) require('./probe').main({ onlyExtensions: true })
  .catch(error => { console.error(error.stack || error); process.exitCode = 1; });
module.exports = { extensions };

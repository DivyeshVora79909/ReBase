'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, recordClient, applySchema } = require('../temporal-tree/harness');
const { verify, exact } = require('./source-oracle');

const at = day => `d'2027-01-${String(day).padStart(2, '0')}'`;
const create = (id, fields) => `CREATE ${id} SET owned_by=rebase_tenant:default,${fields};`;
async function main() {
  const compiled = generateBundle(loadMaterials({ groups: [
    { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
    { name: 'project', roots: [path.resolve(__dirname, '../../designs/all-in-accounting')] },
  ] }));
  const server = await start(), q = client(server.url);
  const snapshot = () => q(`RETURN {${[...compiled.schema.tables.keys()].map(t => `${t}:(SELECT * FROM ${t} WITH NOINDEX ORDER BY id)`).join(',')}};`);
  let checkpoints = 0, rollbacks = 0, last='schema application';
  const mutate = async (sql, actor = q) => { last=sql; await actor(sql); checkpoints++; verify(await snapshot()); };
  const reject = async (sql, pattern, actor = q) => {
    last=sql; const before = await snapshot(); await assert.rejects(actor(sql), pattern);
    assert.deepEqual(await snapshot(), before); verify(before); rollbacks++;
  };
  const value = async (expression, expected) => exact(await q(`RETURN ${expression};`), expected, expression);
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;');
    await applySchema(q, compiled.bundle);
    await mutate([
      create('currency:inr', "name='Rupee',code='INR',precision=2"),
      create('currency:usd', "name='Dollar',code='USD',precision=2"),
      create('measure_unit:each', "name='Each',code='each'"),
      create('item:goods', "name='Goods',unit=measure_unit:each"),
      create('operating_unit:shop', "name='Shop'"),
      ...['customer','supplier','other'].map(id => create(`organization:${id}`, `name='${id}',currency=currency:inr,effective_at=${at(1)}`)),
      ...['inr','usd'].map(id => create(`treasury:${id}`, `name='${id}',currency=currency:${id},effective_at=${at(1)}`)),
      create('misc_currency_account:fees', `name='Charges',currency=currency:inr,effective_at=${at(1)}`),
      ...['vat','credit'].map(id => create(`indirect_tax_account:${id}`, `name='${id}',currency=currency:inr,effective_at=${at(1)}`)),
      create('stock_account:goods', `name='Goods',currency=currency:inr,resource=item:goods,operating_unit=operating_unit:shop,effective_at=${at(1)}`),
      create('stock_entry:opening', `account=stock_account:goods,real=100dec,effective_at=${at(1)}`),
      ...['inr','usd'].map(id => create(`account_entry:${id}`, `account=treasury:${id},real=1000dec,effective_at=${at(1)}`)),
      create('sales_invoice:sale', `organization=organization:customer,invoice_date=${at(10)}`),
      create('purchase_invoice:purchase', `organization=organization:supplier,invoice_date=${at(10)}`),
      create('sales_issue:line', `invoice=sales_invoice:sale,stock_account=stock_account:goods,quantity=10dec,price=10dec,exchange_rate=1dec,effective_at=${at(5)}`),
      create('purchase_issue:line', `invoice=purchase_invoice:purchase,stock_account=stock_account:goods,quantity=10dec,price=10dec,exchange_rate=1dec,effective_at=${at(5)}`),
      'CREATE rebase_user:writer SET name="Writer",parents=[rebase_tenant:default]; DEFINE ACCESS extension_writer ON DATABASE TYPE RECORD SIGNIN rebase_user:writer;'
    ].join('\n'));
    const writer = await recordClient(server.url, 'extension_writer');
    await reject(create('sales_adjustment_note:empty', 'organization=organization:customer,draft=false'), /ADJUSTMENT_NOTE_EMPTY/);
    await mutate(create('sales_adjustment_note:credit', 'organization=organization:customer'), writer);
    await mutate(create('issue_adjustment:line', `source=sales_issue:line,quantity_delta=-1dec,effective_at=${at(11)},adjustment_note=sales_adjustment_note:credit`), writer);
    await mutate('UPDATE sales_adjustment_note:credit SET draft=false;');
    await reject(create('issue_adjustment:mixed', `source=sales_issue:line,quantity_delta=1dec,effective_at=${at(12)},adjustment_note=sales_adjustment_note:credit`), /ADJUSTMENT_NOTE_MIXED_SIGN/);
    await reject('UPDATE sales_adjustment_note:credit SET organization=organization:other;', /ADJUSTMENT_NOTE_DIMENSIONS/);
    await reject('DELETE issue_adjustment:line;', /ADJUSTMENT_NOTE_EMPTY/);
    await mutate(create('issue_tax:capped', `source=sales_issue:line,tax_account=indirect_tax_account:vat,rate=10dec,upper_bound=5dec,exchange_rate=1dec,effective_at=${at(6)}`));
    await mutate(create('adjustment_tax:capped', `source_tax=issue_tax:capped,adjustment=issue_adjustment:line,effective_at=${at(12)}`));
    await value('sales_adjustment_note:credit.z_lines.summary.count', 2);
    await value('sales_adjustment_note:credit.z_lines.summary.measures.amount.sum', -10);
    await mutate('UPDATE issue_tax:capped SET rate=2dec;');
    await value('sales_adjustment_note:credit.z_lines.summary.measures.amount.sum', '-10.20');
    await mutate(create('purchase_adjustment_note:debit', 'organization=organization:supplier'));
    await reject('UPDATE issue_adjustment:line SET adjustment_note=purchase_adjustment_note:debit;', /ADJUSTMENT_NOTE_DIMENSIONS|ADJUSTMENT_NOTE_EMPTY/);
    await mutate(create('issue_adjustment:purchase', `source=purchase_issue:line,price_delta=1dec,effective_at=${at(11)},adjustment_note=purchase_adjustment_note:debit`));
    await mutate('UPDATE purchase_adjustment_note:debit SET draft=false;');
    console.log('PASS adjustment-note dimensions, signs, finalization, source edits, neutral capped taxes and rollback');
    await mutate(create('tax_deposit:credit', `tax_account=indirect_tax_account:credit,treasury=treasury:inr,amount=20dec,exchange_rate=1dec,effective_at=${at(7)}`));
    await mutate(create('tax_offset:use', `credit_account=indirect_tax_account:credit,liability_account=indirect_tax_account:vat,amount=1dec,exchange_rate=1dec,effective_at=${at(8)}`));
    await mutate(create('tax_settlement:vat', `tax_account=indirect_tax_account:vat,treasury=treasury:inr,amount=0.8dec,exchange_rate=1dec,effective_at=${at(13)}`));
    await value('indirect_tax_account:vat.z_history.summary.measures.payable.sum',0);
    await mutate(create('tax_refund:credit', `tax_account=indirect_tax_account:credit,treasury=treasury:inr,amount=5dec,exchange_rate=1dec,effective_at=${at(14)}`));
    await value('indirect_tax_account:credit.z_history.summary.measures.receivable.sum',14);
    await reject('UPDATE tax_refund:credit SET amount=20dec;', /TAX_CLAIM_CAPACITY/);
    await reject('UPDATE tax_settlement:vat SET amount=1dec;', /TAX_CLAIM_CAPACITY/);
    await reject(`UPDATE tax_deposit:credit SET effective_at=${at(15)};`, /TAX_CLAIM_CAPACITY/);
    await mutate(create('tax_deposit:same', `tax_account=indirect_tax_account:vat,treasury=treasury:inr,amount=1dec,exchange_rate=1dec,effective_at=${at(15)}`));
    await mutate(create('account_claim:penalty', `account=indirect_tax_account:vat,claim_kind='payable',amount=5dec,description='Explicit penalty',effective_at=${at(15)}`));
    await mutate(create('tax_offset:same', `credit_account=indirect_tax_account:vat,liability_account=indirect_tax_account:vat,amount=1dec,exchange_rate=1dec,effective_at=${at(16)}`));
    await value('indirect_tax_account:vat.z_history.summary.measures.payable.sum',4);
    await mutate(create('account_claim:rent', `account=organization:supplier,claim_kind='payable',amount=100dec,description='Rent',effective_at=${at(18)}`));
    await mutate(create('claim_settlement:rent', `source=account_claim:rent,treasury=treasury:usd,amount=1dec,exchange_rate=80dec,effective_at=${at(19)}`),writer);
    await value('account_claim:rent.z_capacity.summary.measures.remaining.sum',20);
    await reject('UPDATE claim_settlement:rent SET amount=2dec;', /CLAIM_SETTLEMENT_CAPACITY/);
    await reject(`UPDATE claim_settlement:rent SET effective_at=${at(17)};`, /CLAIM_SETTLEMENT_CAPACITY/);
    await reject('UPDATE account_claim:rent SET amount=70dec;', /CLAIM_SETTLEMENT_CAPACITY/);
    await mutate(create('account_claim:interest', `account=organization:customer,claim_kind='receivable',amount=10dec,description='Explicit interest',effective_at=${at(20)}`));
    await mutate(create('claim_settlement:interest', `source=account_claim:interest,treasury=treasury:inr,amount=10dec,exchange_rate=1dec,effective_at=${at(21)}`));
    console.log('PASS tax deposits, settlements, refunds, offsets, independent claims, FX settlement and chronological capacity');
    await mutate(create('invoice_settlement:charged', `invoice=sales_invoice:sale,treasury=treasury:inr,amount=40dec,exchange_rate=1dec,effective_at=${at(8)},fee_account=misc_currency_account:fees,fee_rate=2dec,fee_upper_bound=0.6dec,fee_tax_rate=18dec,fee_tax_creditable=true,fee_tax_account=indirect_tax_account:credit`),writer);
    await value('invoice_settlement:charged.fee_amount','0.6');
    await value('invoice_settlement:charged.fee_tax_amount','0.11');
    await value('invoice_settlement:charged.invoice_amount',40);
    await mutate('UPDATE invoice_settlement:charged SET fee_rate=1dec,fee_amount=999dec;');
    await value('invoice_settlement:charged.fee_amount','0.4');
    await mutate('UPDATE invoice_settlement:charged SET amount=60dec;');
    await reject('UPDATE invoice_settlement:charged SET fee_exchange_rate=2dec;',/ACCOUNTING_EXCHANGE_RATE/);
    await reject('UPDATE invoice_settlement:charged SET fee_tax_account=NONE;',/FEE_TAX_ACCOUNT_REQUIRED/);
    await reject('UPDATE invoice_settlement:charged SET fee_lower_bound=1dec;',/FEE_BOUNDS/);
    await mutate(create('payment_refund:charged', `source=invoice_settlement:charged,amount=5dec,effective_at=${at(9)},fee_account=misc_currency_account:fees,fee_lower_bound=0.1dec,fee_tax_rate=18dec`));
    await value('payment_refund:charged.fee_account_amount','0.12');
    await mutate(create('payment_adjustment:charged', `source=invoice_settlement:charged,amount_delta=-5dec,effective_at=${at(14)},fee_account=misc_currency_account:fees,fee_lower_bound=0.1dec`));
    await mutate('UPDATE claim_settlement:rent SET fee_account=misc_currency_account:fees,fee_rate=10dec,fee_exchange_rate=80dec,fee_tax_rate=18dec,fee_tax_creditable=true,fee_tax_account=indirect_tax_account:credit,fee_tax_exchange_rate=80dec;');
    await value('claim_settlement:rent.fee_account_amount',8);
    await value('claim_settlement:rent.fee_credit_amount','1.6');
    await mutate('UPDATE tax_deposit:credit SET fee_account=misc_currency_account:fees,fee_rate=5dec,fee_tax_rate=18dec,fee_tax_creditable=true,fee_tax_account=indirect_tax_account:credit;');
    await mutate(create('resource_exchange:cash', `from_account=treasury:usd,to_account=treasury:inr,from_amount=2dec,exchange_rate=80dec,effective_at=${at(20)},fee_account=misc_currency_account:fees,fee_rate=1dec,fee_exchange_rate=80dec`));
    await value('resource_exchange:cash.fee_account_amount','1.6');
    await mutate(create('production:paid', `name='Paid run',starts_at=${at(22)},ends_at=${at(23)}`)+create('production_cost:paid', 'production=production:paid,treasury=treasury:inr,amount=10dec,fee_account=misc_currency_account:fees,fee_rate=10dec,fee_tax_rate=18dec'));
    await value("(fn::tree::read(treasury:inr,'z_history','before',["+at(23)+"])).measures.payable.sum",'11.18');
    await reject('UPDATE production_cost:paid SET fee_lower_bound=2000dec;',/ACCOUNT_BALANCE_FLOOR/);
    console.log('PASS inline bounded charges, creditable/noncreditable tax, native VALUE protection, aliased legs, FX and production reservations');
    await value('fn::accounting::round(2.5dec,0)',2);
    await value('fn::accounting::round(3.5dec,0)',4);
    await value('fn::accounting::round(-2.5dec,0)',-2);
    await mutate(create('exchange_pair:price','from_resource=item:goods,to_resource=currency:inr')+create('exchange_pair:fx','from_resource=currency:usd,to_resource=currency:inr'));
    await reject(create('exchange_pair:duplicate','from_resource=currency:usd,to_resource=currency:inr'),/TREE_DUPLICATE_VALUE/);
    await reject(create('exchange_pair:self','from_resource=currency:usd,to_resource=currency:usd'),/PAIR_IDENTICAL_DIMENSIONS/);
    await mutate('UPDATE sales_issue:line SET include_analytics=true,price_pair=exchange_pair:price; UPDATE purchase_issue:line SET include_analytics=true,price_pair=exchange_pair:price;');
    await value('stock_account:goods.z_trade.summary.measures.sales_quantity.sum',9);
    await value('stock_account:goods.z_trade.summary.measures.sales_value.sum',90);
    await value('stock_account:goods.z_trade.summary.measures.purchase_value.sum',110);
    await value('exchange_pair:price.z_history.summary.measures.observations.sum',2);
    await value('exchange_pair:price.z_history.summary.measures.corrections.sum',2);
    await value('exchange_pair:price.z_history.summary.measures.purchase_to.sum',110);
    await value("fn::accounting::ratio(stock_account:goods.z_trade.summary.measures.purchase_value.sum,stock_account:goods.z_trade.summary.measures.purchase_quantity.sum)",11);
    assert.equal(await q('RETURN fn::accounting::ratio(1dec,0dec);'),null);
    await value("(fn::tree::read(currency:inr,'z_trade_by_unit','range',[[operating_unit:shop,"+at(1)+"],[operating_unit:shop,"+at(30)+"]])).measures.sales_value.sum",90);
    await mutate('UPDATE claim_settlement:rent SET fx_pair=exchange_pair:fx,include_analytics=true; UPDATE resource_exchange:cash SET exchange_pair=exchange_pair:fx;');
    await value('exchange_pair:fx.z_history.summary.measures.from_amount.sum',3);
    await value('exchange_pair:fx.z_history.summary.measures.to_amount.sum',240);
    await value('currency:usd.z_payments.summary.measures.net_cash.sum','-1.12');
    await mutate('UPDATE invoice_settlement:charged SET include_analytics=true; UPDATE payment_refund:charged SET include_analytics=true; UPDATE payment_adjustment:charged SET include_analytics=true; UPDATE production_cost:paid SET include_analytics=true;');
    await value('currency:inr.z_payments.summary.measures.gross_in.sum',60);
    await value('currency:inr.z_payments.summary.measures.gross_out.sum',20);
    await value('currency:inr.z_payments.summary.measures.net_cash.sum','37.89');
    await reject('UPDATE resource_exchange:cash SET exchange_pair=exchange_pair:price;',/PAIR_DIMENSIONS/);
    await reject('UPDATE sales_issue:line SET fx_pair=exchange_pair:fx;',/PAIR_DIMENSIONS/);
    await mutate('UPDATE purchase_issue:line SET include_analytics=false;');
    await value('stock_account:goods.z_trade.summary.measures.purchase_value.sum',0);
    await value('exchange_pair:price.z_history.summary.measures.purchase_to.sum',110);
    await mutate('UPDATE purchase_issue:line SET include_analytics=true;');
    console.log('PASS directed pair uniqueness, correction-aware ratios, separate sales/purchases, explicit enrollment and currency/unit ranges');
    await mutate(create('operating_unit:damaged', "name='Damaged goods'")+
      create('misc_stock_account:damages',`name='Damages',currency=currency:inr,resource=item:goods,operating_unit=operating_unit:damaged,effective_at=${at(1)}`)+
      create('stock_account:usd',`name='USD goods',currency=currency:usd,resource=item:goods,operating_unit=operating_unit:shop,effective_at=${at(1)}`));
    await mutate(create('resource_exchange:damages', `from_account=stock_account:goods,to_account=misc_stock_account:damages,from_amount=2dec,exchange_rate=1dec,effective_at=${at(20)}`));
    await value('misc_stock_account:damages.z_history.summary.measures.real.sum',2);
    await reject('UPDATE resource_exchange:damages SET exchange_rate=2dec;',/ACCOUNTING_EXCHANGE_RATE/);
    await reject('UPDATE resource_exchange:damages SET fee_account=misc_currency_account:fees,fee_rate=1dec;',/FEE_CASH_LEG_REQUIRED/);
    await mutate(create('purchase_issue:fx',`invoice=purchase_invoice:purchase,stock_account=stock_account:usd,quantity=2dec,price=1dec,exchange_rate=80dec,effective_at=${at(7)},include_analytics=true,price_pair=exchange_pair:price,fx_pair=exchange_pair:fx`));
    await mutate(create('issue_adjustment:fx',`source=purchase_issue:fx,exchange_rate_delta=-10dec,effective_at=${at(17)}`));
    await value('stock_account:usd.z_trade.summary.measures.purchase_value.sum',2);
    await value('exchange_pair:fx.z_history.summary.measures.purchase_from.sum',2);
    await value('exchange_pair:fx.z_history.summary.measures.purchase_to.sum',140);
    await value('exchange_pair:fx.z_history.summary.measures.purchase_rate.min',80);
    await mutate('UPDATE purchase_issue:fx SET price=2dec;');
    await value('exchange_pair:fx.z_history.summary.measures.purchase_from.sum',4);
    await value('exchange_pair:fx.z_history.summary.measures.purchase_to.sum',280);
    await value('currency:inr.z_trade.summary.measures.purchase_value.sum',390);
    await value('item:goods.z_trade.summary.measures.purchase_quantity.sum',12);
    console.log('PASS existing transfers cover damage locations; FX corrections change value without inventing quantity or observed quotes');
    await mutate('UPDATE purchase_issue:line SET stock_account=misc_stock_account:damages;');
    await value("(fn::tree::read(currency:inr,'z_trade_by_unit','range',[[operating_unit:shop,"+at(1)+"],[operating_unit:shop,"+at(30)+"]])).measures.purchase_value.sum",280);
    await value("(fn::tree::read(currency:inr,'z_trade_by_unit','range',[[operating_unit:damaged,"+at(1)+"],[operating_unit:damaged,"+at(30)+"]])).measures.purchase_value.sum",110);
    await mutate('UPDATE purchase_issue:line SET stock_account=stock_account:goods;');
    await mutate(create('organization:usd',`name='USD supplier',currency=currency:usd,effective_at=${at(1)}`)+
      create('purchase_invoice:usd',`organization=organization:usd,invoice_date=${at(10)}`)+
      create('exchange_pair:usd_price','from_resource=item:goods,to_resource=currency:usd')+
      create('purchase_issue:usd',`invoice=purchase_invoice:usd,stock_account=stock_account:usd,quantity=1dec,price=1dec,exchange_rate=1dec,effective_at=${at(7)},include_analytics=true,price_pair=exchange_pair:usd_price`));
    await value('currency:usd.z_trade.summary.measures.purchase_value.sum',1);
    await value('currency:inr.z_trade.summary.measures.purchase_value.sum',390);
    await value('item:goods.z_trade.summary.measures.purchase_quantity.sum',13);
    await mutate(create('indirect_tax_account:usd',`name='USD credit',currency=currency:usd,effective_at=${at(1)}`)+
      create('tax_deposit:usd',`tax_account=indirect_tax_account:usd,treasury=treasury:usd,amount=20dec,exchange_rate=1dec,effective_at=${at(17)}`)+
      create('tax_offset:fx',`credit_account=indirect_tax_account:usd,liability_account=indirect_tax_account:vat,amount=0.01dec,exchange_rate=80dec,effective_at=${at(18)}`));
    await value('indirect_tax_account:vat.z_history.summary.measures.payable.sum','3.2');
    await mutate(create('tax_refund:usd',`tax_account=indirect_tax_account:usd,treasury=treasury:inr,amount=8dec,exchange_rate=0.0125dec,effective_at=${at(19)}`));
    await value('indirect_tax_account:usd.z_history.summary.measures.receivable.sum','19.89');
    console.log('PASS analytics reparenting, independent currency totals, and converted tax offsets/refunds');


    await q("CREATE rebase_tenant:other SET name='Other';");
    await mutate(create('currency:hidden', "name='Hidden',code='OTH'").replace('rebase_tenant:default','rebase_tenant:other')+
      create('misc_currency_account:hidden',`name='Hidden charges',currency=currency:hidden,effective_at=${at(1)}`).replace('rebase_tenant:default','rebase_tenant:other'));
    await reject('UPDATE invoice_settlement:charged SET fee_account=misc_currency_account:hidden;',/tenant|TENANT/);
    await reject(create('exchange_pair:hidden','from_resource=currency:usd,to_resource=currency:hidden'),/tenant|TENANT/);
    assert.deepEqual(await writer('SELECT * FROM misc_currency_account:hidden;'),[]);
    const second=await recordClient(server.url,'extension_writer');
    const competing=['a','b'].map(id=>create(`claim_settlement:race_${id}`,`source=account_claim:rent,treasury=treasury:inr,amount=15dec,exchange_rate=1dec,effective_at=${at(24)}`));
    const results=await Promise.allSettled([writer(competing[0]),second(competing[1])]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
    for (let i=0;i<results.length;i++) if (results[i].status==='rejected') {
      assert.match(String(results[i].reason),/conflict|retry|CLAIM_SETTLEMENT_CAPACITY/i);
      await reject(competing[i],/CLAIM_SETTLEMENT_CAPACITY/);
    }
    checkpoints++;verify(await snapshot());
    console.log('PASS authenticated extension writes, tenant isolation and competing claim settlements');
    last='populated identical-schema reapplication';
    const populated=await snapshot();
    await applySchema(q,compiled.bundle);
    assert.deepEqual(await snapshot(),populated);verify(populated);
    console.log('PASS exact populated extension schema reapplication');
    await mutate('UPDATE sales_adjustment_note:credit SET draft=true; UPDATE purchase_adjustment_note:debit SET draft=true;');
    const data=await snapshot(),order=['resource_exchange','production_cost','production','tax_refund','tax_settlement','tax_offset',
      'claim_settlement','account_claim','tax_deposit','payment_refund','payment_adjustment','invoice_settlement',
      'adjustment_tax','tax_adjustment','issue_adjustment','issue_return','issue_net_tax','issue_tax','sales_issue','purchase_issue',
      'sales_adjustment_note','purchase_adjustment_note','exchange_pair','stock_entry','account_entry'];
    for (const type of order) for (const row of data[type].sort((a,b)=>String(b.effective_at??'').localeCompare(String(a.effective_at??'')))) await q(`DELETE ONLY ${row.id};`);
    const empty=await snapshot();verify(empty);checkpoints++;
    for (const type of order) assert.deepEqual(empty[type],[]);
    for (const rows of Object.values(empty)) for (const row of rows) for (const [field,root] of Object.entries(row)) {
      if (['z_history','z_trade','z_trade_by_unit','z_payments','z_exchange_pairs'].includes(field)) assert.equal(root.summary.count,0,`${row.id}.${field} empty`);
    }
    console.log('PASS explicit child-first cleanup of extension records and all financial/analytics histories');
    console.log(`PASS accounting extension slice: ${checkpoints} checkpoints, ${rollbacks} complete rollback snapshots`);
  } catch (error) { console.error("Last extension operation:",last); throw error; } finally { await server.close(); }
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };

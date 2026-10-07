'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { Surreal, Decimal, RecordId } = require('surrealdb');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, recordClient, applySchema } = require('../temporal-tree/harness');
const { tables, money, stocks, snapshot, verify, exact } = require('./source-oracle');

const at = (day, time = '00:00:00') => `d'2027-01-${String(day).padStart(2,'0')}T${time}Z'`;
const create = (id, fields, owner = 'rebase_tenant:default') => `CREATE ${id} SET owned_by=${owner}, ${fields};`;
async function setup(q) {
  await q([
    create('currency:inr', "code='INR', name='Rupee', precision=2"),
    create('currency:usd', "code='USD', name='Dollar', precision=2"),
    create('measure_unit:each', "code='each', name='Each'"),
    ...['raw','finished','scarce'].map(id => create(`item:${id}`, `name='${id}', unit=measure_unit:each`)),
    create('service:labor', `name='Labor', unit=measure_unit:each, available_from=${at(1)}, available_until=${at(31)}, minimum_duration=1h, maximum_duration=2d`),
    create('operating_unit:workshop', "name='Workshop', capacity=2dec"),
    create('operating_unit:store', "name='Store'"),
    ...['customer','supplier','other'].map(id => create(`organization:${id}`, `name='${id}',currency=currency:inr,effective_at=${at(1)}`)),
    create('organization:foreign',`name='Foreign',currency=currency:usd,effective_at=${at(1)}`),
    ...['inr','usd'].map(id => create(`treasury:${id}`,`name='${id}',currency=currency:${id},effective_at=${at(1)}`)),
    create('misc_currency_account:capital',`name='Capital',currency=currency:inr,effective_at=${at(1)}`),
    ...['vat','alternate'].map(id => create(`indirect_tax_account:${id}`,`name='${id}',currency=currency:inr,effective_at=${at(1)}`)),
    create('indirect_tax_account:usd',`name='USD tax',currency=currency:usd,effective_at=${at(1)}`),
    create('direct_tax_account:withheld',`name='Withheld',currency=currency:inr,effective_at=${at(1)}`),
    ...['raw','finished','scarce'].map(id => create(`stock_account:${id}`,`name='${id}',resource=item:${id},operating_unit=operating_unit:workshop,currency=currency:inr,effective_at=${at(1)}`)),
    create('stock_account:usd',`name='USD stock',resource=item:raw,operating_unit=operating_unit:workshop,currency=currency:usd,effective_at=${at(1)}`),
    create('stock_account:labor',`name='Labor',resource=service:labor,operating_unit=operating_unit:workshop,currency=currency:inr,effective_at=${at(1)}`),
    create('misc_stock_account:store',`name='Stored goods',resource=item:finished,operating_unit=operating_unit:store,currency=currency:inr,effective_at=${at(1)}`),
    ...[['raw',100],['usd',10],['scarce',5],['labor',50]].map(([id,n]) => create(`stock_entry:${id}`,`account=stock_account:${id},real=${n}dec,effective_at=${at(1)}`)),
    ...[['inr',1000],['usd',100]].map(([id,n]) => create(`account_entry:${id}`,`account=treasury:${id},real=${n}dec,effective_at=${at(1)}`)),
    ...['sale','empty','fx','move','caps'].map(id => create(`sales_invoice:${id}`,`organization=organization:customer,invoice_date=${at(10)}`)),
    create('sales_invoice:other',`organization=organization:other,invoice_date=${at(10)}`),
    create('sales_invoice:rounding',`organization=organization:customer,invoice_date=${at(20)}`),
    create('purchase_invoice:purchase',`organization=organization:supplier,invoice_date=${at(10)}`),
    "CREATE rebase_user:writer SET name='Writer',parents=[rebase_tenant:default];",
    'DEFINE ACCESS accounting_writer ON DATABASE TYPE RECORD SIGNIN rebase_user:writer;'
  ].join('\n'));
}

async function main() {
  const compiled = generateBundle(loadMaterials({groups:[
    {name:'framework',roots:[path.resolve(__dirname,'../../framework')]},
    {name:'project',roots:[path.resolve(__dirname,'../../designs/all-in-accounting')]},
  ]}));
  const server = await start({engine:'surrealkv'}), q=client(server.url);
  let mutations=0,rejections=0,last='setup';
  const mutate=async(sql,actor=q)=>{last=sql;await actor(sql);mutations++;return verify(await snapshot(q));};
  const reject=async(sql,pattern,actor=q)=>{
    last=sql;const before=await snapshot(q);await assert.rejects(actor(sql),pattern);
    assert.deepEqual(await snapshot(q),before,'rejection restores every source, derived field, root, slot and audit row');rejections++;
  };
  const value=async(expression,expected)=>exact(await q(`RETURN ${expression};`),expected,expression);
  const issue=(id,invoice='sale',fields='')=>create(`sales_issue:${id}`,`invoice=sales_invoice:${invoice},stock_account=stock_account:raw,quantity=10dec,price=10dec,exchange_rate=1dec,effective_at=${at(5)}${fields}`);
  const tax=(id,source,rate=9,day=6,extra='')=>create(`issue_tax:${id}`,`source=sales_issue:${source},tax_account=indirect_tax_account:vat,rate=${rate}dec,exchange_rate=1dec,effective_at=${at(day)}${extra}`);
  const adjustmentTax=(id,taxId,change,day,time='00:00:01')=>create(`adjustment_tax:${id}`,`source_tax=${taxId},adjustment=${change},effective_at=${at(day,time)}`);
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q,compiled.bundle);await setup(q);verify(await snapshot(q));
    const writer=await recordClient(server.url,'accounting_writer');
    await reject(create('misc_stock_account:duplicate',`name='Duplicate',currency=currency:inr,resource=item:raw,operating_unit=operating_unit:workshop,effective_at=${at(30)}`),/TREE_DUPLICATE_VALUE/);
    await reject(create('organization:missing',`name='Missing',effective_at=${at(1)}`),/currency/);
    await reject(create('sales_issue:no_invoice',`stock_account=stock_account:raw,quantity=1dec,price=10dec,exchange_rate=1dec,effective_at=${at(5)}`),/invoice|record/i);
    await reject(create('invoice_settlement:empty',`invoice=sales_invoice:empty,treasury=treasury:inr,amount=1dec,exchange_rate=1dec,effective_at=${at(3)}`),/INVOICE_OVERSETTLED_AT_DATE/);
    await mutate(issue('sale'),writer);
    await mutate(create('invoice_settlement:advance',`invoice=sales_invoice:sale,treasury=treasury:inr,amount=80dec,exchange_rate=1dec,effective_at=${at(3)}`),writer);
    await value("fn::tree::read(sales_invoice:sale,'z_history','before',["+at(4)+']).measures.balance.sum',-80);
    await reject('UPDATE invoice_settlement:advance SET amount=101dec;',/INVOICE_OVERSETTLED_AT_DATE/);
    await reject(`UPDATE sales_issue:sale SET effective_at=${at(11)};`,/ORIGINAL_ON_OR_BEFORE_INVOICE/);
    await reject(`UPDATE sales_invoice:sale SET invoice_date=${at(4)};`,/ORIGINAL_ON_OR_BEFORE_INVOICE|INVOICE_OVERSETTLED_AT_DATE/);
    await reject('UPDATE sales_issue:sale SET exchange_rate=2dec;',/ACCOUNTING_EXCHANGE_RATE/);
    console.log('PASS direct accounts, shared unique dimensions, required invoices and covered advances');

    await mutate(tax('a','sale')+tax('b','sale'));
    await mutate(create('issue_net_tax:net',`source=sales_issue:sale,tax_account=indirect_tax_account:vat,rate=10dec,exchange_rate=1dec,effective_at=${at(8)}`),writer);
    await value('issue_net_tax:net.amount','11.80');
    await mutate(create('issue_net_tax:parallel',`source=sales_issue:sale,tax_account=indirect_tax_account:vat,rate=10dec,exchange_rate=1dec,effective_at=${at(8)}`));
    await value('issue_net_tax:parallel.amount','11.80');await value('issue_net_tax:net.amount','11.80');
    await mutate(create('issue_net_tax:later',`source=sales_issue:sale,tax_account=indirect_tax_account:vat,rate=10dec,exchange_rate=1dec,effective_at=${at(9)}`));
    await value('issue_net_tax:later.amount','14.16');
    await mutate(tax('backdated','sale',5,7));await value('issue_net_tax:net.amount','12.30');await value('issue_net_tax:later.amount','14.76');
    await mutate('UPDATE issue_tax:a SET rate=18dec;');await value('issue_net_tax:net.amount','13.20');
    await mutate('DELETE ONLY issue_net_tax:later; DELETE ONLY issue_net_tax:parallel;');
    await reject(`UPDATE issue_net_tax:net SET effective_at=${at(5)};`,/NET_TAX_REQUIRES_PRIOR_BASIS/);
    await reject('UPDATE issue_tax:a SET lower_bound=5dec,upper_bound=4dec;',/TAX_BOUND_ORDER/);
    console.log('PASS strictly earlier net taxes, parallel equal-time taxes and backdated cascading recalculation');

    await mutate(create('issue_return:return',`source=sales_issue:sale,quantity=1dec,effective_at=${at(9)}`));
    for(const [id,taxId] of [['a','issue_tax:a'],['b','issue_tax:b'],['backdated','issue_tax:backdated'],['net','issue_net_tax:net']]) {
      await mutate(adjustmentTax(`return_${id}`,taxId,'issue_return:return',9,id==='net'?'00:00:02':'00:00:01'));
    }
    await mutate(create('payment_refund:before',`source=invoice_settlement:advance,amount=10dec,effective_at=${at(9)}`));
    await reject(`UPDATE payment_refund:before SET effective_at=${at(11)};`,/ORIGINAL_ON_OR_BEFORE_INVOICE/);
    await reject(create('issue_adjustment:early',`source=sales_issue:sale,quantity_delta=-1dec,effective_at=${at(10)}`),/ADJUSTMENT_AFTER_INVOICE/);
    await mutate(create('issue_adjustment:quantity',`source=sales_issue:sale,quantity_delta=-2dec,effective_at=${at(11)}`));
    for(const [id,taxId] of [['a','issue_tax:a'],['b','issue_tax:b'],['backdated','issue_tax:backdated'],['net','issue_net_tax:net']]) {
      await mutate(adjustmentTax(`quantity_${id}`,taxId,'issue_adjustment:quantity',11,id==='net'?'00:00:02':'00:00:01'));
    }
    await value('adjustment_tax:quantity_net.amount_delta','-2.64');
    await mutate('UPDATE issue_tax:a SET rate=9dec;');await value('adjustment_tax:quantity_a.amount_delta','-1.80');await value('adjustment_tax:quantity_net.amount_delta','-2.46');
    await reject('UPDATE issue_adjustment:quantity SET quantity_delta=-10dec;',/ISSUE_QUANTITY_CAPACITY|ISSUE_VALUE_CAPACITY|TAX_REVERSAL_CAPACITY|INVOICE_OVERSETTLED|ADJUSTMENT_TAX_BASIS_CAPACITY/);
    await reject('UPDATE issue_adjustment:quantity SET price_delta=-1dec;',/ADJUSTMENT_ONE_DIMENSION/);
    await reject(create('issue_return:late',`source=sales_issue:sale,quantity=1dec,effective_at=${at(11)}`),/ORIGINAL_ON_OR_BEFORE_INVOICE/);
    await reject(create('issue_adjustment:overpaid',`source=sales_issue:sale,price_delta=-5dec,effective_at=${at(13)}`),/INVOICE_OVERSETTLED_AFTER_DATE/);
    await mutate(create('payment_adjustment:cash_back',`source=invoice_settlement:advance,amount_delta=-30dec,effective_at=${at(13)}`));
    await mutate(create('issue_adjustment:price',`source=sales_issue:sale,price_delta=-5dec,effective_at=${at(13)}`));
    await mutate(create('issue_adjustment:debit',`source=sales_issue:sale,price_delta=1dec,effective_at=${at(14)}`));
    await reject(create('payment_adjustment:too_much',`source=invoice_settlement:advance,amount_delta=-50dec,effective_at=${at(15)}`),/PAYMENT_REVERSAL_CAPACITY|INVOICE_NEGATIVE_TOTAL/);
    await reject('DELETE ONLY sales_issue:sale;',/reference|referenced/i);
    console.log('PASS return versus adjustment dates, stock reversal, signed debit corrections and reactive adjustment taxes');

    await mutate(issue('caps','caps')+tax('capped','caps',10,6,',lower_bound=2dec,upper_bound=5dec'));
    await mutate(create('issue_adjustment:cap_first',`source=sales_issue:caps,quantity_delta=-2dec,effective_at=${at(11)}`)+adjustmentTax('cap_first','issue_tax:capped','issue_adjustment:cap_first',11));
    await value('adjustment_tax:cap_first.amount_delta',0);
    await mutate(create('issue_adjustment:cap_second',`source=sales_issue:caps,quantity_delta=-4dec,effective_at=${at(12)}`)+adjustmentTax('cap_second','issue_tax:capped','issue_adjustment:cap_second',12));
    await value('adjustment_tax:cap_second.amount_delta',-1);
    await mutate('UPDATE issue_tax:capped SET rate=20dec;');await value('adjustment_tax:cap_second.amount_delta',0);
    await mutate('UPDATE issue_tax:capped SET rate=1dec;');await value('issue_tax:capped.amount',2);
    await reject(adjustmentTax('duplicate_pair','issue_tax:capped','issue_adjustment:cap_first',13),/already contains|unique|duplicate/i);
    await mutate(issue('move','move')+tax('move','move'));
    await mutate('UPDATE sales_issue:move SET invoice=sales_invoice:other;');
    await value('sales_invoice:move.z_history.summary.count',0);await value('sales_invoice:other.z_history.summary.measures.amount.sum',109);
    await mutate('UPDATE issue_tax:move SET tax_account=indirect_tax_account:alternate;');
    await reject(adjustmentTax('wrong_issue','issue_tax:move','issue_adjustment:quantity',15),/ADJUSTMENT_TAX_SOURCE/);
    console.log('PASS marginal capped rules, explicit parent matching and old/new ancestor repair');

    await mutate(create('purchase_issue:receipt',`invoice=purchase_invoice:purchase,stock_account=stock_account:raw,quantity=4dec,price=20dec,exchange_rate=1dec,effective_at=${at(5)}`));
    await mutate(create('invoice_settlement:supplier',`invoice=purchase_invoice:purchase,treasury=treasury:inr,amount=50dec,exchange_rate=1dec,effective_at=${at(3)}`));
    await mutate(create('issue_tax:purchase',`source=purchase_issue:receipt,tax_account=indirect_tax_account:vat,rate=10dec,exchange_rate=1dec,effective_at=${at(6)}`));
    await mutate(create('issue_return:purchase',`source=purchase_issue:receipt,quantity=1dec,effective_at=${at(7)}`)+adjustmentTax('purchase','issue_tax:purchase','issue_return:purchase',7));
    await mutate(create('payment_refund:supplier',`source=invoice_settlement:supplier,amount=5dec,effective_at=${at(8)}`));
    await mutate(create('payment_withholding:supplier',`source=invoice_settlement:supplier,tax_account=direct_tax_account:withheld,amount=5dec,exchange_rate=1dec,effective_at=${at(8)}`));
    await value('direct_tax_account:withheld.z_history.summary.measures.payable.sum',5);
    await reject('UPDATE purchase_issue:receipt SET invoice=sales_invoice:sale;',/purchase_invoice|type|record/i);
    await mutate(create('sales_issue:fx',`invoice=sales_invoice:fx,stock_account=stock_account:usd,quantity=1dec,price=1dec,exchange_rate=80dec,effective_at=${at(5)}`));
    await mutate(create('invoice_settlement:fx',`invoice=sales_invoice:fx,treasury=treasury:usd,amount=0.5dec,exchange_rate=80dec,effective_at=${at(3)}`));
    await mutate(create('issue_tax:fx',`source=sales_issue:fx,tax_account=indirect_tax_account:usd,rate=10dec,exchange_rate=0.0125dec,effective_at=${at(6)}`));
    await value('issue_tax:fx.account_amount','0.10');
    await mutate(create('issue_adjustment:fx',`source=sales_issue:fx,exchange_rate_delta=-8dec,effective_at=${at(11)}`));
    await value('issue_adjustment:fx.amount_delta',-8);
    await mutate(create('resource_exchange:fx',`from_account=treasury:inr,to_account=treasury:usd,from_amount=80dec,exchange_rate=0.0125dec,effective_at=${at(15)}`));
    await value('resource_exchange:fx.to_amount',1);
    console.log('PASS purchase direction, same-family withholding, scalar FX and rate corrections');

    await mutate(create('sales_issue:rounding',`invoice=sales_invoice:rounding,stock_account=stock_account:raw,quantity=3dec,price=0.335dec,exchange_rate=1dec,effective_at=${at(16)}`));
    await mutate(create('issue_return:round_first',`source=sales_issue:rounding,quantity=1dec,effective_at=${at(17)}`));
    await reject(create('issue_return:round_last',`source=sales_issue:rounding,quantity=2dec,effective_at=${at(18)}`),/ISSUE_VALUE_CAPACITY|INVOICE_NEGATIVE_TOTAL/);
    await mutate(create('issue_return:round_last',`source=sales_issue:rounding,quantity=2dec,entered_amount=0.66dec,effective_at=${at(18)}`));
    await value('sales_issue:rounding.z_basis.summary.measures.base.sum',0);
    await reject('UPDATE issue_return:round_last SET entered_amount=0.661dec;',/ACCOUNTING_AMOUNT_PRECISION|ISSUE_VALUE_CAPACITY|INVOICE_NEGATIVE_TOTAL/);
    console.log('PASS exact native rounding and explicit split-return remainder');

    await mutate(create('production:prior',`name='Prior output',starts_at=${at(19)},ends_at=${at(20)}`)+create('production_output:prior',`production=production:prior,stock_account=stock_account:scarce,quantity=10dec`));
    await mutate(create('production:run',`name='Run',starts_at=${at(20)},ends_at=${at(21)}`));
    await reject(create('production_input:self_funded',`production=production:run,stock_account=stock_account:scarce,quantity=6dec`),/PRODUCTION_GROSS_INPUT/);
    await mutate(create('production_input:raw',`production=production:run,stock_account=stock_account:scarce,quantity=5dec`));
    await reject(create('production_input:peer',`production=production:run,stock_account=stock_account:scarce,quantity=1dec`),/PRODUCTION_GROSS_INPUT/);
    await reject('UPDATE stock_entry:scarce SET real=4dec;',/PRODUCTION_GROSS_INPUT/);
    await mutate(create('production_input:service',`production=production:run,stock_account=stock_account:labor,quantity=2dec`));
    await mutate(create('production_output:finished',`production=production:run,stock_account=stock_account:finished,quantity=3dec`));
    await mutate(create('production_cost:cash',`production=production:run,treasury=treasury:inr,amount=10dec`));
    await mutate(create('production_capacity:run',`production=production:run,operating_unit=operating_unit:workshop,service=service:labor,quantity=1.5dec`));
    await value("fn::tree::read(stock_account:finished,'z_history','before',["+at(21)+']).measures.receivable.sum',3);
    await reject(create('resource_exchange:early_output',`from_account=stock_account:finished,to_account=misc_stock_account:store,production_output=production_output:finished,from_amount=1dec,exchange_rate=1dec,effective_at=${at(20,'12:00:00')}`),/EXCHANGE_OUTPUT_SOURCE|PRODUCTION_OUTPUT_CAPACITY|ACCOUNT_BALANCE_FLOOR/);
    await mutate(create('resource_exchange:output',`from_account=stock_account:finished,to_account=misc_stock_account:store,production_output=production_output:finished,from_amount=2dec,exchange_rate=1dec,effective_at=${at(22)}`));
    await reject('UPDATE production_output:finished SET quantity=1dec;',/PRODUCTION_OUTPUT_CAPACITY|ACCOUNT_BALANCE_FLOOR/);
    await mutate(create('production:adjacent',`name='Adjacent',starts_at=${at(21)},ends_at=${at(22)}`)+create('production_capacity:adjacent',`production=production:adjacent,operating_unit=operating_unit:workshop,service=service:labor,quantity=1.5dec`));
    await mutate(create('production:overlap',`name='Overlap',starts_at=${at(20,'12:00:00')},ends_at=${at(21,'12:00:00')}`));
    await reject(create('production_capacity:overlap',`production=production:overlap,operating_unit=operating_unit:workshop,service=service:labor,quantity=1dec`),/OPERATING_CAPACITY/);
    await reject('UPDATE operating_unit:workshop SET capacity=1dec;',/OPERATING_CAPACITY/);
    await reject('UPDATE service:labor SET maximum_duration=12h;',/RESOURCE_DURATION/);
    await reject(`UPDATE service:labor SET available_until=${at(20,'12:00:00')};`,/RESOURCE_AVAILABILITY/);
    await reject(`UPDATE production:run SET ends_at=${at(23)};`,/RESOURCE_DURATION|EXCHANGE_OUTPUT_SOURCE|PRODUCTION_OUTPUT_CAPACITY|OPERATING_CAPACITY|ACCOUNT_BALANCE_FLOOR/);
    await mutate(`UPDATE production:run SET starts_at=${at(20,'01:00:00')};`);
    console.log('PASS future production, gross shared inputs, cash reservation, service windows and half-open capacity');

    await mutate(create('operating_unit:concurrent',"name='Concurrent',capacity=1dec"));
    const second=await recordClient(server.url,'accounting_writer');
    const statements=['a','b'].map(id=>create(`production_capacity:concurrent_${id}`,`production=production:overlap,operating_unit=operating_unit:concurrent,service=service:labor,quantity=0.75dec`,'rebase_user:writer'));
    const results=await Promise.allSettled([writer(statements[0]),second(statements[1])]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1,'one competing capacity booking commits');
    for(let i=0;i<2;i++) if(results[i].status==='rejected') {
      assert.match(String(results[i].reason),/conflict|retry|OPERATING_CAPACITY/i);
      await reject(statements[i],/OPERATING_CAPACITY/);
    }
    verify(await snapshot(q));mutations++;
    const sdk=new Surreal();
    try {
      await sdk.connect(server.url+'/rpc');await sdk.signin({username:'root',password:'root'});await sdk.use({namespace:'temporal_probe',database:'fixture'});
      const result=await sdk.query('CREATE ONLY $id CONTENT $content;',{
        id:new RecordId('account_entry','native_decimal'),content:{owned_by:new RecordId('rebase_tenant','default'),account:new RecordId('misc_currency_account','capital'),real:new Decimal('0.123456789012345678'),effective_at:new Date('2027-01-02T00:00:00Z')},
      });
      assert(result[0].real instanceof Decimal);exact(result[0].real,'0.123456789012345678','SDK decimal');
    } finally {await sdk.close();}
    verify(await snapshot(q));mutations++;
    await mutate(create('sales_issue:protected',`invoice=sales_invoice:sale,stock_account=stock_account:raw,quantity=1dec,price=1dec,exchange_rate=1dec,effective_at=${at(5)},amount=999dec`,'rebase_user:writer'),writer);
    await value('sales_issue:protected.amount',1);
    await q("CREATE rebase_tenant:other SET name='Other tenant';");
    await mutate(create('currency:other',"code='OTH',name='Other'",'rebase_tenant:other')+
      create('organization:hidden',`name='Hidden',currency=currency:other,effective_at=${at(1)}`,'rebase_tenant:other')+
      create('sales_invoice:hidden',`organization=organization:hidden,invoice_date=${at(10)}`,'rebase_tenant:other'));
    await reject(create('sales_issue:cross_tenant',`invoice=sales_invoice:hidden,stock_account=stock_account:raw,quantity=1dec,price=1dec,exchange_rate=1dec,effective_at=${at(5)}`),/tenant|TENANT/);
    console.log('PASS competing sessions, authenticated source writes and native SDK decimals');

    last='identical schema reapplication on populated accounting data';
    const beforeReapply=await snapshot(q);
    console.log('CHECK populated schema reapplication');
    await applySchema(q,compiled.bundle);
    assert.deepEqual(await snapshot(q),beforeReapply,'identical schema reapplication leaves domain and audit unchanged');
    verify(beforeReapply);console.log('PASS exact populated schema reapplication');
    const data=await snapshot(q),order=['resource_exchange','production_capacity','production_cost','production_input','production_output','production',
      'adjustment_tax','tax_adjustment','issue_adjustment','issue_return','payment_withholding','payment_refund','payment_adjustment','invoice_settlement',
      'issue_net_tax','issue_tax','sales_issue','purchase_issue','stock_entry','account_entry'];
    const deletes=order.flatMap(t=>data[t].sort((a,b)=>String(b.effective_at??'').localeCompare(String(a.effective_at??''))).map(row=>`DELETE ONLY ${row.id};`));
    await mutate('BEGIN TRANSACTION;\n'+deletes.join('\n')+'\nCOMMIT TRANSACTION;');
    const empty=await snapshot(q);for(const t of order)assert.deepEqual(empty[t],[],`${t} cleanup`);
    for(const t of [...money,...stocks])for(const row of empty[t])assert.equal(row.z_history.summary.count,0,`${row.id} empty ledger`);
    console.log(`PASS accounting redesign: ${mutations} mutation checkpoints, ${rejections} complete rollback snapshots; explicit child-first cleanup`);
  } catch(error) {console.error('Last accounting operation:',last);throw error;} finally {await server.close();}
}
if(require.main===module)main().catch(error=>{console.error(error.stack||error);process.exitCode=1;});
module.exports={main,setup};

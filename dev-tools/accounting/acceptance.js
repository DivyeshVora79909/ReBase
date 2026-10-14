'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { snapshot, verify, exact, tables } = require('./source-oracle');

const at = (day, time = '00:00:00') => `d'2027-01-${String(day).padStart(2, '0')}T${time}Z'`;
const create = (id, fields, owner = 'rebase_tenant:default') =>
  `CREATE ${id} SET owned_by=${owner}, ${fields};`;

function compile() {
  return generateBundle(loadMaterials({ groups: [
    { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
    { name: 'project', roots: [path.resolve(__dirname, '../../designs/all-in-accounting')] },
  ] }));
}

function acceptance(q, compiled) {
  const slots = Object.fromEntries([...compiled.schema.tables].map(([name, table]) =>
    [name, [...table.fields.values()].filter(field => field.treeNode).map(field => field.name)]));
  const result = { checkpoints: 0, rollbacks: 0, cases: [], last: 'setup' };
  const check = async () => verify(await snapshot(q), slots);
  const mutate = async (sql, actor = q) => {
    result.last = sql;
    await actor(sql);
    const data = await check();
    result.checkpoints++;
    return data;
  };
  const reject = async (sql, pattern, actor = q) => {
    result.last = sql;
    const before = await snapshot(q);
    await assert.rejects(actor(sql), pattern);
    assert.deepEqual(await snapshot(q), before,
      'rejected write restores every source, derived field, slot, root, subscription, fence and audit row');
    result.rollbacks++;
  };
  const value = async (expression, expected) => exact(await q(`RETURN ${expression};`), expected, expression);
  const pass = name => { result.cases.push(name); console.log(`PASS ${name}`); };
  return { q, slots, result, check, mutate, reject, value, pass };
}

async function setup(q) {
  const date = `effective_at=${at(1)}`;
  await q([
    create('currency:inr', "code='INR',name='Rupee',precision=2"),
    create('currency:usd', "code='USD',name='Dollar',precision=2"),
    create('currency:precise', "code='DEC',name='Exact decimals',precision=18"),
    create('measure_unit:each', "code='each',name='Each'"),
    ...['widget', 'finished', 'scarce'].map(id => create(`item:${id}`, `name='${id}',unit=measure_unit:each`)),
    create('service:labor', `name='Labor',unit=measure_unit:each,available_from=${at(1)},available_until=${at(31)},minimum_duration=1h,maximum_duration=2d`),
    create('subsidiary:one', `name='One',currency=currency:inr,${date}`),
    create('subsidiary:two', `name='Two',currency=currency:usd,${date}`),
    create('operating_unit:store', "name='Store',subsidiary=subsidiary:one,capacity=2dec"),
    create('operating_unit:annex', "name='Annex',subsidiary=subsidiary:two,capacity=2dec"),
    ...[['customer', 'one', 'inr'], ['supplier', 'one', 'usd'], ['other', 'one', 'inr'], ['foreign', 'two', 'usd']]
      .map(([id, sub, currency]) => create(`organization:${id}`, `name='${id}',subsidiary=subsidiary:${sub},currency=currency:${currency},${date}`)),
    ...[['usd_inr', 'currency:usd', 'currency:inr', 10], ['inr_usd', 'currency:inr', 'currency:usd', 0.1],
      ['widget_inr', 'item:widget', 'currency:inr', 10], ['widget_usd', 'item:widget', 'currency:usd', 1],
      ['finished_inr', 'item:finished', 'currency:inr', 20], ['scarce_inr', 'item:scarce', 'currency:inr', 1],
      ['labor_inr', 'service:labor', 'currency:inr', 5], ['precise_inr', 'currency:precise', 'currency:inr', 1]]
      .map(([id, from, to, rate]) => create(`exchange_pair:${id}`, `given_resource=${from},received_resource=${to},initial_rate=${rate}dec,${date}`)),
    create('organization_currency_account:customer', `name='Customer INR',organization=organization:customer,currency=currency:inr,${date}`),
    create('organization_currency_account:customer_usd', `name='Customer USD',organization=organization:customer,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,organization_pair=exchange_pair:usd_inr,${date}`),
    create('organization_currency_account:supplier', `name='Supplier USD',organization=organization:supplier,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,${date}`),
    create('organization_currency_account:supplier_inr', `name='Supplier INR',organization=organization:supplier,currency=currency:inr,organization_pair=exchange_pair:inr_usd,${date}`),
    create('organization_currency_account:other', `name='Other INR',organization=organization:other,currency=currency:inr,${date}`),
    create('organization_currency_account:foreign', `name='Foreign USD',organization=organization:foreign,currency=currency:usd,${date}`),
    ...[['customer', 'widget_inr', 'widget_inr'], ['supplier', 'widget_inr', 'widget_usd'],
      ['other', 'widget_inr', 'widget_inr'], ['foreign', 'widget_usd', 'widget_usd']]
      .map(([id, subPair, orgPair]) => create(`organization_resource_account:${id}`, `name='${id} widgets',organization=organization:${id},resource=item:widget,valuation_pair=exchange_pair:${subPair},organization_pair=exchange_pair:${orgPair},${date}`)),
    ...[['cash', 'one', 'inr', ''], ['cash_second', 'one', 'inr', ''], ['usd', 'one', 'usd', ',valuation_pair=exchange_pair:usd_inr'],
      ['foreign', 'two', 'usd', '']].map(([id, sub, currency, pair]) => create(`treasury:${id}`, `name='${id}',subsidiary=subsidiary:${sub},currency=currency:${currency},${date}${pair}`)),
    ...[['fees', 'inr', ''], ['fees_usd', 'usd', ',valuation_pair=exchange_pair:usd_inr'],
      ['precise', 'precise', ',valuation_pair=exchange_pair:precise_inr']]
      .map(([id, currency, pair]) => create(`misc_currency_account:${id}`, `name='${id}',subsidiary=subsidiary:one,currency=currency:${currency},${date}${pair}`)),
    ...[['vat', 'inr', ''], ['alternate', 'inr', ''], ['vat_usd', 'usd', ',valuation_pair=exchange_pair:usd_inr']]
      .map(([id, currency, pair]) => create(`indirect_tax_account:${id}`, `name='${id}',subsidiary=subsidiary:one,currency=currency:${currency},${date}${pair}`)),
    create('direct_tax_account:withheld', `name='Withheld',subsidiary=subsidiary:one,currency=currency:inr,${date}`),
    ...[['widget', 'item:widget', 'widget_inr'], ['finished', 'item:finished', 'finished_inr'],
      ['scarce', 'item:scarce', 'scarce_inr'], ['labor', 'service:labor', 'labor_inr']]
      .map(([id, resource, pair]) => create(`stock_account:${id}`, `name='${id}',subsidiary=subsidiary:one,operating_unit=operating_unit:store,resource=${resource},valuation_pair=exchange_pair:${pair},${date}`)),
    create('stock_account:foreign', `name='Foreign widgets',subsidiary=subsidiary:two,operating_unit=operating_unit:annex,resource=item:widget,valuation_pair=exchange_pair:widget_usd,${date}`),
    create('misc_stock_account:damage', `name='Damage',subsidiary=subsidiary:one,operating_unit=operating_unit:store,resource=item:widget,valuation_pair=exchange_pair:widget_inr,${date}`),
    ...[['cash', 10000], ['usd', 1000], ['foreign', 1000]].map(([id, amount]) => create(`account_entry:${id}`, `account=treasury:${id},real=${amount}dec,${date}`)),
    ...[['widget', 200], ['foreign', 100], ['scarce', 5], ['labor', 10]].map(([id, amount]) => create(`stock_entry:${id}`, `account=stock_account:${id},real=${amount}dec,${date}`)),
    "CREATE rebase_user:writer SET name='Writer',parents=[rebase_tenant:default];",
    'DEFINE ACCESS accounting_writer ON DATABASE TYPE RECORD SIGNIN rebase_user:writer;',
  ].join('\n'));
}

async function cleanup(h) {
  const data = await snapshot(h.q);
  const order = ['resource_exchange', 'production_capacity', 'production_cost', 'production_input', 'production_output', 'production',
    'tax_refund', 'tax_settlement', 'tax_offset', 'claim_settlement', 'account_claim', 'tax_deposit',
    'payment_withholding', 'payment_adjustment', 'invoice_settlement', 'tax_adjustment_net_tax',
    'issue_adjustment_net_tax', 'issue_adjustment_tax', 'net_tax_adjustment', 'tax_adjustment',
    'issue_net_tax', 'issue_tax', 'issue_adjustment', 'sales_issue', 'purchase_issue',
    'sales_adjustment_note', 'purchase_adjustment_note', 'sales_invoice', 'purchase_invoice',
    'stock_entry', 'account_entry', 'exchange_rate'];
  // Each DELETE repairs links and validates before the next row is removed.
  // Consumers precede their funding sources so every intermediate state is valid.
  const deletes = order.flatMap(table => [...data[table]]
    .sort((a, b) => String(b.effective_at ?? '').localeCompare(String(a.effective_at ?? '')))
    .map(row => `DELETE ONLY ${row.id};`));
  // Keep each request bounded too: a large single /sql request can exceed the
  // client's response-header timeout even when every individual delete is valid.
  for (const sql of deletes) {
    h.result.last = sql;
    await h.q(sql);
  }
  const empty = await h.check();
  h.result.checkpoints++;
  for (const table of order) assert.deepEqual(empty[table], [], `${table} cleaned up`);
  for (const table of tables) for (const row of empty[table]) {
    for (const slot of ['z_history', 'z_capacity', 'z_rates', 'z_observations', 'z_gross']) {
      if (row[slot]) assert.equal(row[slot].summary.count, 0, `${row.id}.${slot} is empty`);
    }
  }
  assert.deepEqual(empty.rebase_read, [], 'all calculation and validation reads released');
  assert.deepEqual(empty.rebase_read_frame, [], 'no orphan evaluation generations');
  assert.deepEqual(empty.rebase_read_group, [], 'all reverse groups and interval trees released');
  h.pass('child-first single-record cleanup, empty financial/observation roots and released subscriptions');
}

module.exports = { acceptance, at, compile, create, cleanup, setup };

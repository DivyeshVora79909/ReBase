'use strict';
const path = require('node:path');
const fs = require('node:fs');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('../temporal-tree/harness');
const { snapshot, verify } = require('./source-oracle');

const at = day => `d'2027-01-${String(day).padStart(2, '0')}T00:00:00Z'`;
const create = (id, fields) => `CREATE ${id} SET owned_by=rebase_tenant:default, ${fields};`;
async function main() {
  const root = path.resolve(__dirname, '../..');
  const compiled = generateBundle(loadMaterials({ groups: [
    { name: 'framework', roots: [path.join(root, 'framework')] },
    { name: 'project', roots: [path.join(root, 'designs/all-in-accounting')] },
  ] }));
  const server = await start({ engine: 'surrealkv' });
  const q = client(server.url);
  const slots = Object.fromEntries([...compiled.schema.tables].map(([name, table]) =>
    [name, [...table.fields.values()].filter(field => field.treeNode).map(field => field.name)]));
  const rootSpecs = compiled.temporal.trees.roots.map(({ table, slot }) => ({ table, slot }));
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, compiled.bundle);
    await q([
      create('currency:inr', "code='INR',name='Rupee',precision=2"),
      create('currency:usd', "code='USD',name='Dollar',precision=2"),
      create('currency:eur', "code='EUR',name='Euro',precision=2"),
      create('measure_unit:each', "code='each',name='Each'"),
      create('item:widget', `name='Widget',unit=measure_unit:each`),
      create('subsidiary:f', `name='One',currency=currency:inr,effective_at=${at(1)}`),
      create('operating_unit:f', `name='Store',subsidiary=subsidiary:f,capacity=2dec`),
      create('organization:f', `name='Customer',subsidiary=subsidiary:f,currency=currency:eur,effective_at=${at(1)}`),
      create('exchange_pair:usd_inr', `given_resource=currency:usd,received_resource=currency:inr,initial_rate=10dec,effective_at=${at(1)}`),
      create('exchange_pair:widget_inr', `given_resource=item:widget,received_resource=currency:inr,initial_rate=10dec,effective_at=${at(1)}`),
      create('exchange_pair:usd_eur', `given_resource=currency:usd,received_resource=currency:eur,initial_rate=0.8dec,effective_at=${at(1)}`),
      create('exchange_pair:widget_eur', `given_resource=item:widget,received_resource=currency:eur,initial_rate=0.8dec,effective_at=${at(1)}`),
      create('organization_currency_account:f', `name='Customer',organization=organization:f,currency=currency:usd,valuation_pair=exchange_pair:usd_inr,organization_pair=exchange_pair:usd_eur,effective_at=${at(1)}`),
      create('organization_resource_account:f', `name='Widgets',organization=organization:f,resource=item:widget,valuation_pair=exchange_pair:widget_inr,organization_pair=exchange_pair:widget_eur,effective_at=${at(1)}`),
      create('stock_account:f', `name='Widgets',subsidiary=subsidiary:f,operating_unit=operating_unit:f,resource=item:widget,valuation_pair=exchange_pair:widget_inr,effective_at=${at(1)}`),
      create('stock_entry:f', `account=stock_account:f,real=100dec,effective_at=${at(1)}`),
      create('stock_entry:widget', `account=stock_account:f,real=1dec,effective_at=${at(2)}`),
      create('sales_invoice:f', `account=organization_currency_account:f,invoice_date=${at(15)}`),
      create('sales_invoice:f_late', `account=organization_currency_account:f,invoice_date=${at(15)}`),
    ].join('\n'));
    const check = async label => {
      const data = await snapshot(q, [...compiled.schema.tables.keys()]);
      verify(data, slots, rootSpecs);
      console.log(`PASS ${label}: ${data.rebase_read.length} read registrations`);
      return data;
    };
    await check('minimal setup');
    await q(create('sales_issue:f', `invoice=sales_invoice:f,stock_account=stock_account:f,counterparty_stock=organization_resource_account:f,quantity=10dec,price=5dec,effective_at=${at(5)}`));
    const beforeSecond = await check('first sale');
    await q(create('sales_issue:f_late', `invoice=sales_invoice:f_late,stock_account=stock_account:f,counterparty_stock=organization_resource_account:f,quantity=2dec,price=10dec,effective_at=${at(10)}`));
    try { await check('second sale'); } catch (error) {
      const afterSecond = await snapshot(q, [...compiled.schema.tables.keys()]);
      fs.writeFileSync(process.env.REBASE_B1_SNAPSHOT || '/tmp/rebase-b1-min-snapshots.json', JSON.stringify({ before: beforeSecond, after: afterSecond, error: error.stack }, null, 2));
      throw error;
    }
  } finally { await server.close(); }
}
main().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });

#!/usr/bin/env node
'use strict';
const path = require('node:path');
const { loadClientSchemas } = require('../client-schemas');
const { createModel } = require('../fixtures');
const { recordId } = require('../fixtures/model');
const { build } = require('../index');
const { resolveConfiguration } = require('../../config/environment');
const schemaDirectory = path.resolve(__dirname, '../../designs/all-in-accounting/schemas');
const owned_by = 'rebase_tenant:default';
const row = (table, id, content) => ({table,id:`${table}:${id}`,content:{owned_by,...content}});

// Explicit dependency order. These are ordinary public records; running this
// file validates and binds them without opening a database connection.
const fixture = [
  row('currency','demo_usd',{code:'USD',name:'Dollar',precision:2}),
  row('measure_unit','demo_each',{code:'each',name:'Each'}),
  row('item','demo_item',{name:'Item',unit:'measure_unit:demo_each'}),
  row('subsidiary','demo_business',{name:'Business',currency:'currency:demo_usd',effective_at:'2027-01-01T00:00:00Z'}),
  row('operating_unit','demo_store',{name:'Store',subsidiary:'subsidiary:demo_business'}),
  row('organization','demo_customer',{name:'Customer',subsidiary:'subsidiary:demo_business',currency:'currency:demo_usd',effective_at:'2027-01-01T00:00:00Z'}),
  row('exchange_pair','demo_value',{given_resource:'item:demo_item',received_resource:'currency:demo_usd',initial_rate:'100',effective_at:'2027-01-01T00:00:00Z'}),
  row('organization_currency_account','demo_currency',{name:'Customer USD',organization:'organization:demo_customer',currency:'currency:demo_usd',effective_at:'2027-01-01T00:00:00Z'}),
  row('organization_resource_account','demo_goods',{name:'Customer goods',organization:'organization:demo_customer',resource:'item:demo_item',valuation_pair:'exchange_pair:demo_value',organization_pair:'exchange_pair:demo_value',effective_at:'2027-01-01T00:00:00Z'}),
  row('treasury','demo_cash',{name:'Cash',subsidiary:'subsidiary:demo_business',currency:'currency:demo_usd',effective_at:'2027-01-01T00:00:00Z'}),
  row('stock_account','demo_stock',{name:'Stock',subsidiary:'subsidiary:demo_business',resource:'item:demo_item',operating_unit:'operating_unit:demo_store',valuation_pair:'exchange_pair:demo_value',effective_at:'2027-01-01T00:00:00Z'}),
  row('stock_entry','demo_opening',{account:'stock_account:demo_stock',real:'10',effective_at:'2027-01-01T00:00:00Z'}),
  row('sales_invoice','demo_sale',{account:'organization_currency_account:demo_currency',invoice_date:'2027-01-10T00:00:00Z'}),
  row('sales_issue','demo_issue',{invoice:'sales_invoice:demo_sale',stock_account:'stock_account:demo_stock',counterparty_stock:'organization_resource_account:demo_goods',quantity:'1',price:'100',effective_at:'2027-01-05T00:00:00Z'}),
  row('invoice_settlement','demo_advance',{invoice:'sales_invoice:demo_sale',treasury:'treasury:demo_cash',amount:'80',effective_at:'2027-01-02T00:00:00Z'}),
  row('sales_adjustment_note','demo_note',{account:'organization_currency_account:demo_currency'}),
  row('issue_adjustment','demo_credit',{source:'sales_issue:demo_issue',adjustment_note:'sales_adjustment_note:demo_note',price_delta:'-10',effective_at:'2027-01-11T00:00:00Z'}),
];
let model;
function fixtureModel() {
  return model ||= createModel({
    schema: build({ project: 'all-in-accounting', explain: '*',
      configuration: resolveConfiguration({ NODE_ENV: 'test' }) }),
    schemas: loadClientSchemas(schemaDirectory),
  });
}
function bindValues(table, input) {
  return fixtureModel().bind(table, input);
}
function prepareFixture(rows = fixture) {
  return rows.map(({ table, id, content }) => ({ table, id: recordId(id), content: bindValues(table, content) }));
}
if(require.main===module)console.log(`Validated ${prepareFixture().length} explicit accounting records with native RecordId, Decimal and Date bindings; no database connection opened.`);
module.exports={bindValues,fixture,prepareFixture};

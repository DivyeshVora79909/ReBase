#!/usr/bin/env node
'use strict';
const path = require('node:path');
const { Decimal } = require('surrealdb');
const { assertClientInput, loadClientSchemas } = require('../client-schemas');
const { recordId } = require('../populate');
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
const recordFields = {
  currency:[],measure_unit:[],item:['unit'],subsidiary:['currency'],operating_unit:['subsidiary'],
  organization:['subsidiary','currency'],treasury:['subsidiary','currency'],
  exchange_pair:['given_resource','received_resource'],
  organization_currency_account:['organization','currency','valuation_pair','organization_pair'],
  organization_resource_account:['organization','resource','valuation_pair','organization_pair'],
  stock_account:['subsidiary','resource','operating_unit','valuation_pair'],stock_entry:['account'],sales_invoice:['account'],
  sales_issue:['invoice','stock_account','counterparty_stock'],invoice_settlement:['invoice','treasury','exchange_pair'],
  sales_adjustment_note:['account'],issue_adjustment:['source','adjustment_note'],
};
const decimalFields = {exchange_pair:['initial_rate'],stock_entry:['real','receivable','payable'],sales_issue:['quantity','price'],
  invoice_settlement:['amount'],issue_adjustment:['quantity_delta','price_delta']};
function bindValues(table,input) {
  const bound={...input};
  for(const field of ['owned_by',...(recordFields[table]||[])]) if(bound[field]!==undefined)bound[field]=recordId(bound[field]);
  for(const field of decimalFields[table]||[])if(bound[field]!==undefined)bound[field]=new Decimal(bound[field]);
  for(const field of ['effective_at','invoice_date'])if(bound[field]!==undefined)bound[field]=new Date(bound[field]);
  return bound;
}
function prepareFixture(rows=fixture) {
  const catalog=loadClientSchemas(schemaDirectory);
  return rows.map(({table,id,content})=>{
    assertClientInput(catalog,table,content);
    return {table,id:recordId(id),content:bindValues(table,content)};
  });
}
if(require.main===module)console.log(`Validated ${prepareFixture().length} explicit accounting records with native RecordId, Decimal and Date bindings; no database connection opened.`);
module.exports={bindValues,fixture,prepareFixture};

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
  row('operating_unit','demo_store',{name:'Store'}),
  row('organization','demo_customer',{name:'Customer',currency:'currency:demo_usd',effective_at:'2027-01-01T00:00:00Z'}),
  row('treasury','demo_cash',{name:'Cash',currency:'currency:demo_usd',effective_at:'2027-01-01T00:00:00Z'}),
  row('stock_account','demo_stock',{name:'Stock',currency:'currency:demo_usd',resource:'item:demo_item',operating_unit:'operating_unit:demo_store',effective_at:'2027-01-01T00:00:00Z'}),
  row('stock_entry','demo_opening',{account:'stock_account:demo_stock',real:'10',effective_at:'2027-01-01T00:00:00Z'}),
  row('sales_invoice','demo_sale',{organization:'organization:demo_customer',invoice_date:'2027-01-10T00:00:00Z'}),
  row('sales_issue','demo_issue',{invoice:'sales_invoice:demo_sale',stock_account:'stock_account:demo_stock',quantity:'1',price:'100',exchange_rate:'1',effective_at:'2027-01-05T00:00:00Z'}),
  row('invoice_settlement','demo_advance',{invoice:'sales_invoice:demo_sale',treasury:'treasury:demo_cash',amount:'80',exchange_rate:'1',effective_at:'2027-01-02T00:00:00Z'}),
];
const recordFields = {
  currency:[],measure_unit:[],item:['unit'],operating_unit:[],organization:['currency'],treasury:['currency'],
  stock_account:['currency','resource','operating_unit'],stock_entry:['account'],sales_invoice:['organization'],
  sales_issue:['invoice','stock_account'],invoice_settlement:['invoice','treasury'],
};
const decimalFields = {stock_entry:['real','receivable','payable'],sales_issue:['quantity','price','exchange_rate'],invoice_settlement:['amount','exchange_rate']};
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

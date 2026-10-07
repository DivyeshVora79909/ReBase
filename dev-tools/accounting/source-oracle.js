'use strict';

// Independent chronological replay of authored inputs. No expected balance or
// formula uses a maintained tree, a derived monetary field, or SQL helpers.
const assert = require('node:assert/strict');
const tree = require('../temporal-tree/oracle');
const { instant } = require('../temporal-tree/harness');

const money = ['organization', 'treasury', 'direct_tax_account', 'indirect_tax_account', 'misc_currency_account'];
const stocks = ['stock_account', 'misc_stock_account'];
const tables = ['currency', 'measure_unit', 'item', 'service', 'operating_unit', ...money, ...stocks,
  'sales_invoice', 'purchase_invoice', 'sales_issue', 'purchase_issue', 'account_entry', 'stock_entry',
  'invoice_settlement', 'payment_refund', 'payment_adjustment', 'issue_tax', 'issue_net_tax',
  'issue_adjustment', 'issue_return', 'tax_adjustment', 'adjustment_tax', 'payment_withholding',
  'resource_exchange', 'production', 'production_input', 'production_output', 'production_cost', 'production_capacity'];
const tableOf = id => id.split(':')[0];

// Rational arithmetic keeps the financial oracle independent of SurrealDB's
// decimal implementation, including halfway-to-even currency quantization.
class D {
  constructor(value = 0, denominator) {
    if (denominator !== undefined) {
      this.n = BigInt(value); this.d = denominator;
      let a = this.n < 0n ? -this.n : this.n, b = this.d;
      while (b) [a, b] = [b, a % b];
      this.n /= a; this.d /= a;
      return;
    }
    if (value instanceof D) { this.n = value.n; this.d = value.d; return; }
    const match = String(value).match(/^(-?)(\d+)(?:\.(\d*))?(?:e([+-]?\d+))?$/i);
    assert(match, `decimal input: ${value}`);
    const scale = (match[3]?.length || 0) - Number(match[4] || 0);
    this.n = BigInt((match[1] || '') + match[2] + (match[3] || '')) * 10n ** BigInt(Math.max(-scale, 0));
    this.d = 10n ** BigInt(Math.max(scale, 0));
  }
  add(other) { const b = new D(other); return new D(this.n * b.d + b.n * this.d, this.d * b.d); }
  mul(other) { const b = new D(other); return new D(this.n * b.n, this.d * b.d); }
  neg() { return new D(-this.n, this.d); }
  number() { return Number(this.n) / Number(this.d); }
  cmp(other) { const b = new D(other), n = this.n * b.d - b.n * this.d; return n < 0n ? -1 : n > 0n ? 1 : 0; }
  round(precision) {
    const scale = 10n ** BigInt(precision), sign = this.n < 0n ? -1n : 1n, n = this.n * sign * scale;
    const whole = n / this.d, remainder = n % this.d * 2n;
    return new D(sign * (whole + (remainder > this.d || remainder === this.d && whole % 2n ? 1n : 0n)), scale);
  }
}
const d = value => new D(value ?? 0);
const sum = values => values.reduce((a, b) => a.add(b), d(0));
const exact = (actual, expected, label) => assert.equal(d(actual).cmp(expected), 0, `${label}: ${actual} != ${d(expected).number()}`);
const effects = (real, receivable = 0, payable = 0) => ({ real: d(real).number(), receivable: d(receivable).number(),
  payable: d(payable).number(), net: d(receivable).add(d(payable).neg()).number(), available: d(real).add(d(payable).neg()).number() });
const claim = (sale, amount) => effects(0, sale ? amount : 0, sale ? 0 : amount);
const before = (a, b) => instant(a) < instant(b);
const through = (a, b) => instant(a) <= instant(b);
function nextNanosecond(at) {
  const n = instant(at) + 1n, s = n / 1000000000n, fraction = String(n % 1000000000n).padStart(9, '0').replace(/0+$/, '');
  return new Date(Number(s * 1000n)).toISOString().slice(0, -5) + (fraction ? `.${fraction}` : '') + 'Z';
}
function compare(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const date = i === 0 && /^\d{4}-\d\d-\d\dT/.test(a[i]);
    const left = date ? instant(a[i]) : a[i], right = date ? instant(b[i]) : b[i];
    if (left < right) return -1;
    if (left > right) return 1;
  }
  return a.length - b.length;
}
const snapshot = q => q(`RETURN { ${[...tables, 'audit_mutation'].map(t => `${t}: (SELECT * FROM ${t} WITH NOINDEX ORDER BY id)`).join(',')} };`);

function verify(data) {
  const rows = tables.flatMap(t => data[t]), byId = new Map(rows.map(r => [r.id, r]));
  const get = id => { assert(byId.has(id), `source exists: ${id}`); return byId.get(id); };
  const entries = [], issueValues = new Map(), changeValues = new Map(), taxValues = new Map(), netEvents = [], adjustmentEvents = [];
  const add = (row, slot, owner, root, at, measures = {}, tags = {}, dependent = false, business) => {
    entries.push({ link: { rid: row.id, slot }, owner: { rid: owner, slot: root },
      key: [...(business || [at]), row.id, slot], measures: Object.fromEntries(Object.entries(measures).map(([k,v]) => [k,d(v).number()])), tags, dependent });
  };
  const account = id => {
    const row = get(id), resource = money.includes(tableOf(id)) ? row.currency : row.resource;
    assert.equal(row.resource, resource, `${id} canonical resource`);
    return { row, resource, currency: row.currency, precision: get(row.currency).precision };
  };
  const balance = (row, slot, id, at, value, dependent = false) => {
    const a = account(id); add(row, slot, id, 'z_history', at, value, { currency: a.currency, resource: a.resource }, dependent);
  };
  const context = id => {
    const invoice = get(id), org = get(invoice.organization), currency = get(org.currency);
    return { invoice: id, organization: org.id, currency: currency.id, precision: currency.precision,
      invoice_date: invoice.invoice_date, is_sale: tableOf(id) === 'sales_invoice' };
  };
  const checkContext = (row, ctx) => {
    for (const key of ['invoice', 'organization', 'currency', 'invoice_date', 'is_sale']) assert.equal(row[key], ctx[key], `${row.id}.${key}`);
  };
  const commercial = (row, ctx, amount = 0, paid = 0) => {
    const value = d(amount).add(d(paid).neg());
    balance(row, 'z_organization', ctx.organization, row.effective_at, claim(ctx.is_sale, value));
    add(row, 'z_invoice', ctx.invoice, 'z_history', row.effective_at,
      { ...claim(ctx.is_sale, value), amount, paid, balance: value }, { organization: ctx.organization, currency: ctx.currency });
  };
  const net = (row, issue, value) => netEvents.push({ issue, at: row.effective_at, value: d(value) });
  for (const row of [...money, ...stocks].flatMap(t => data[t])) {
    const a = account(row.id);
    add(row, 'z_currency', row.currency, 'z_accounts', row.effective_at);
    if (stocks.includes(tableOf(row.id))) {
      assert.equal(row.unit, get(row.resource).unit);
      add(row, 'z_resource', a.resource, 'z_accounts', row.effective_at);
      add(row, 'z_operating', row.operating_unit, 'z_accounts', row.effective_at);
      add(row, 'z_identity', row.operating_unit, 'z_account_keys', null, {}, {}, false, [row.currency, row.resource]);
    }
  }
  for (const row of [...data.account_entry, ...data.stock_entry]) balance(row, 'z_account', row.account, row.effective_at, effects(row.real, row.receivable, row.payable));
  for (const row of [...data.sales_issue, ...data.purchase_issue]) {
    const ctx = context(row.invoice), amount = d(row.quantity).mul(row.price).mul(row.exchange_rate).round(ctx.precision);
    checkContext(row, ctx); exact(row.amount, amount, `${row.id}.amount`);
    issueValues.set(row.id, { row, ctx, amount });
    commercial(row, ctx, amount);
    balance(row, 'z_stock', row.stock_account, row.effective_at, effects(d(row.quantity).mul(ctx.is_sale ? -1 : 1)));
    add(row, 'z_base', row.id, 'z_basis', row.effective_at, { base: amount, quantity: row.quantity });
    add(row, 'z_net_self', row.id, 'z_net', row.effective_at, { amount }); net(row, row.id, amount);
  }
  for (const row of [...data.issue_adjustment, ...data.issue_return]) {
    const source = issueValues.get(row.source), { ctx } = source;
    const quantity = tableOf(row.id) === 'issue_return' ? d(row.quantity).neg() : d(row.quantity_delta);
    const amount = tableOf(row.id) === 'issue_return'
      ? (row.entered_amount == null ? d(row.quantity).mul(source.row.price).mul(source.row.exchange_rate).round(ctx.precision) : d(row.entered_amount)).neg()
      : quantity.mul(source.row.price).mul(source.row.exchange_rate)
        .add(d(source.row.quantity).mul(row.price_delta).mul(source.row.exchange_rate))
        .add(d(source.row.quantity).mul(source.row.price).mul(row.exchange_rate_delta)).round(ctx.precision);
    checkContext(row, ctx); exact(row.quantity_delta, quantity, `${row.id}.quantity`); exact(row.amount_delta, amount, `${row.id}.amount`);
    changeValues.set(row.id, { row, ctx, quantity, amount }); commercial(row, ctx, amount);
    if (quantity.cmp(0)) balance(row, 'z_stock', source.row.stock_account, row.effective_at, effects(quantity.mul(ctx.is_sale ? -1 : 1)));
    add(row, 'z_source', row.source, 'z_basis', row.effective_at, { base: amount, quantity });
    add(row, 'z_issue_net', row.source, 'z_net', row.effective_at, { amount }); net(row, row.source, amount);
  }
  const taxRule = (basis, row, precision) => {
    let value = d(basis).mul(row.rate).mul('0.01');
    if (value.cmp(row.lower_bound) < 0) value = d(row.lower_bound);
    if (row.upper_bound != null && value.cmp(row.upper_bound) > 0) value = d(row.upper_bound);
    return value.round(precision);
  };
  const taxEvents = [...data.issue_tax, ...data.issue_net_tax, ...data.tax_adjustment, ...data.adjustment_tax]
    .sort((a,b) => compare([a.effective_at,a.id], [b.effective_at,b.id]));
  for (const row of taxEvents) {
    const type = tableOf(row.id), original = ['issue_tax','issue_net_tax'].includes(type);
    if (original) {
      const source = issueValues.get(row.source), { ctx } = source, isNet = type === 'issue_net_tax';
      const basis = isNet ? sum(netEvents.filter(e => e.issue === row.source && before(e.at,row.effective_at)).map(e => e.value))
        : source.amount.add(sum([...changeValues.values()].filter(e => e.row.source === row.source && through(e.row.effective_at,row.effective_at)).map(e => e.amount)));
      const amount = taxRule(basis,row,ctx.precision), accountAmount = amount.mul(row.exchange_rate).round(account(row.tax_account).precision);
      checkContext(row,ctx); exact(row.basis,basis,`${row.id}.basis`); exact(row.amount,amount,`${row.id}.amount`); exact(row.account_amount,accountAmount,`${row.id}.account_amount`);
      taxValues.set(row.id,{row,ctx,basis,amount,accountAmount,isNet}); commercial(row,ctx,amount);
      balance(row,'z_tax_account',row.tax_account,row.effective_at,claim(!ctx.is_sale,accountAmount));
      if (!isNet) add(row,'z_base_reader',row.source,'z_basis',nextNanosecond(row.effective_at),{}, {},true);
      add(row,'z_issue_net',row.source,'z_net',row.effective_at,{amount},{},isNet); net(row,row.source,amount);
      add(row,'z_self',row.id,'z_capacity',row.effective_at,{amount,account_amount:accountAmount});
    } else {
      const source = taxValues.get(row.source_tax); assert(source,`${row.id} consumes an earlier original tax`);
      const { ctx } = source; let amount;
      if (type === 'tax_adjustment') amount = d(row.amount_delta);
      else {
        const change = changeValues.get(row.adjustment);
        const basisDelta = change.amount.add(source.isNet ? sum(adjustmentEvents.filter(e => e.adjustment === row.adjustment && before(e.at,row.effective_at)).map(e => e.amount)) : 0);
        const basisBefore = source.basis.add(sum(adjustmentEvents.filter(e => e.tax === row.source_tax && before(e.at,row.effective_at)).map(e => e.basis)));
        amount = taxRule(basisBefore.add(basisDelta),source.row,ctx.precision).add(taxRule(basisBefore,source.row,ctx.precision).neg());
        exact(row.basis_before,basisBefore,`${row.id}.basis_before`);exact(row.basis_delta,basisDelta,`${row.id}.basis_delta`);exact(row.amount_delta,amount,`${row.id}.amount_delta`);
        adjustmentEvents.push({adjustment:row.adjustment,tax:row.source_tax,at:row.effective_at,amount,basis:basisDelta});
        add(row,'z_order',row.source_tax,'z_adjustments',row.effective_at,{base:basisDelta},{},true);
        add(row,'z_adjustment',row.adjustment,'z_taxes',row.effective_at,{amount},{},source.isNet);
      }
      const accountAmount = row.entered_account_delta == null ? amount.mul(source.row.exchange_rate).round(account(source.row.tax_account).precision) : d(row.entered_account_delta);
      checkContext(row,ctx);exact(row.account_delta,accountAmount,`${row.id}.account_delta`);commercial(row,ctx,amount);
      balance(row,'z_tax_account',source.row.tax_account,row.effective_at,claim(!ctx.is_sale,accountAmount));
      add(row,'z_source',row.source_tax,'z_capacity',row.effective_at,{amount,account_amount:accountAmount});
      add(row,'z_issue_net',source.row.source,'z_net',row.effective_at,{amount});net(row,source.row.source,amount);
    }
  }
  const payments = new Map();
  for (const row of data.invoice_settlement) {
    const ctx=context(row.invoice),amount=d(row.amount).mul(row.exchange_rate).round(ctx.precision);
    checkContext(row,ctx);exact(row.invoice_amount,amount,`${row.id}.invoice_amount`);payments.set(row.id,{row,ctx,amount});
    commercial(row,ctx,0,amount);balance(row,'z_treasury',row.treasury,row.effective_at,effects(d(row.amount).mul(ctx.is_sale?1:-1)));
    add(row,'z_self',row.id,'z_capacity',row.effective_at,{cash:row.amount,invoice_amount:amount});
  }
  for(const row of [...data.payment_refund,...data.payment_adjustment]) {
    const {row:source,ctx}=payments.get(row.source),refund=tableOf(row.id)==='payment_refund';
    const cash=d(refund?row.amount:row.amount_delta).mul(refund?-1:1);
    const amount=refund ? (row.entered_invoice_amount==null?cash.mul(source.exchange_rate).round(ctx.precision):d(row.entered_invoice_amount).neg())
      : row.entered_invoice_delta==null?cash.mul(source.exchange_rate).round(ctx.precision):d(row.entered_invoice_delta);
    checkContext(row,ctx);exact(row.cash_delta,cash,`${row.id}.cash_delta`);exact(row.invoice_delta,amount,`${row.id}.invoice_delta`);commercial(row,ctx,0,amount);
    balance(row,'z_treasury',source.treasury,row.effective_at,effects(cash.mul(ctx.is_sale?1:-1)));
    add(row,'z_source',row.source,'z_capacity',row.effective_at,{cash,invoice_amount:amount});
  }
  for(const row of data.payment_withholding) {
    const {ctx}=payments.get(row.source),amount=d(row.amount).mul(row.exchange_rate).round(account(row.tax_account).precision);
    checkContext(row,ctx);exact(row.account_amount,amount,`${row.id}.account_amount`);commercial(row,ctx,0,row.amount);
    balance(row,'z_tax_account',row.tax_account,row.effective_at,claim(ctx.is_sale,amount));
  }
  for(const row of data.resource_exchange) {
    const to=account(row.to_account),raw=d(row.from_amount).mul(row.exchange_rate),amount=tableOf(to.resource)==='currency'?raw.round(to.precision):raw;
    exact(row.to_amount,amount,`${row.id}.to_amount`);balance(row,'z_from',row.from_account,row.effective_at,effects(d(row.from_amount).neg()));balance(row,'z_to',row.to_account,row.effective_at,effects(amount));
    if(row.production_output) add(row,'z_output',row.production_output,'z_capacity',row.effective_at,{quantity:d(row.from_amount).neg()});
  }
  for(const type of ['production_input','production_output','production_cost','production_capacity']) for(const row of data[type]) {
    const p=get(row.production),kind=type.slice('production_'.length),q=d(row.quantity??row.amount);
    assert.equal(row.starts_at,p.starts_at);assert.equal(row.ends_at,p.ends_at);
    add(row,'z_production',row.production,'z_lines',['output','cost'].includes(kind)?p.ends_at:p.starts_at,{lines:1},{kind});
    if(kind==='capacity') {
      add(row,'z_start',row.operating_unit,'z_capacity',p.starts_at,{used:q});add(row,'z_end',row.operating_unit,'z_capacity',p.ends_at,{used:q.neg()});
    } else {
      const a=kind==='cost'?row.treasury:row.stock_account;
      balance(row,'z_start',a,p.starts_at,kind==='output'?effects(0,q):effects(0,0,q),kind==='input');
      balance(row,'z_end',a,p.ends_at,kind==='output'?effects(q,q.neg()):effects(q.neg(),0,q.neg()));
      if(kind==='input') add(row,'z_gross',a,'z_gross',p.starts_at,{quantity:q});
      if(kind==='output') add(row,'z_self',row.id,'z_capacity',p.ends_at,{quantity:q});
    }
  }
  tree.verify(rows,rows,entries,compare);
  return data;
}
module.exports={tables,money,stocks,snapshot,verify,exact,D};

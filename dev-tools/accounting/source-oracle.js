'use strict';
const assert=require('node:assert/strict');
const tree=require('../temporal-tree/oracle');
const {instant}=require('../temporal-tree/harness');
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

const money=['treasury','misc_currency_account','direct_tax_account','indirect_tax_account','organization_currency_account'];
const stocks=['stock_account','misc_stock_account','organization_resource_account'];
const originalTaxes=['issue_tax','issue_net_tax'];
const changedTaxes=['tax_adjustment','net_tax_adjustment','issue_adjustment_tax','issue_adjustment_net_tax','tax_adjustment_net_tax'];
const feeTables=['invoice_settlement','payment_adjustment','claim_settlement','tax_settlement','tax_refund','tax_deposit','production_cost','resource_exchange'];
const tables=['currency','measure_unit','item','service','subsidiary','organization','operating_unit','exchange_pair','exchange_rate',...money,...stocks,
  'account_entry','stock_entry','sales_invoice','purchase_invoice','sales_adjustment_note','purchase_adjustment_note','sales_issue','purchase_issue','issue_adjustment',
  ...originalTaxes,...changedTaxes,'invoice_settlement','payment_adjustment','payment_withholding','account_claim','claim_settlement',
  'tax_settlement','tax_deposit','tax_refund','tax_offset','production','production_input','production_output','production_cost','production_capacity','resource_exchange'];
const tb=id=>id.split(':')[0], d=v=>new D(v??0), sum=vs=>vs.reduce((a,b)=>a.add(b),d(0));
const sub=(a,b)=>d(a).add(d(b).neg());
const exact=(a,b,label)=>assert.equal(d(a).cmp(b),0,`${label}: ${a} != ${d(b).number()}`);
const eff=(real=0,r=0,p=0)=>({real:d(real),receivable:d(r),payable:d(p),net:sub(r,p),available:d(real)});
const claim=v=>d(v).cmp(0)>=0?eff(0,v,0):eff(0,0,d(v).neg());
const compare=(a,b)=>{for(let i=0;i<Math.min(a.length,b.length);i++){const date=typeof a[i]==='string'&&/^\d{4}-\d\d-\d\dT/.test(a[i]);const x=date?instant(a[i]):a[i],y=date?instant(b[i]):b[i];if(x<y)return -1;if(x>y)return 1;}return a.length-b.length;};
const before=(a,b)=>instant(a)<instant(b),through=(a,b)=>instant(a)<=instant(b);
const next=at=>{const n=instant(at)+1n,s=n/1000000000n,f=String(n%1000000000n).padStart(9,'0').replace(/0+$/,'');return new Date(Number(s*1000n)).toISOString().slice(0,-5)+(f?'.'+f:'')+'Z';};
const snapshot=(q,tableNames=tables)=>q(`RETURN {${[...new Set([...tableNames,'rebase_tenant','rebase_user','audit_mutation','rebase_read','rebase_read_frame','rebase_read_group','rebase_read_lock'])].map(t=>`${t}:(SELECT * FROM ${t} WITH NOINDEX ORDER BY id)`).join(',')}};`);

function evaluateSource(data,slots={}) {
  const hidden = new Set(['audit_mutation','rebase_read','rebase_read_frame','rebase_read_group','rebase_read_lock']);
  const sourceRows = Object.entries(data).filter(([table])=>!hidden.has(table)).flatMap(([,rows])=>rows||[]);
  const rows=tables.flatMap(t=>data[t]||[]),byId=new Map(sourceRows.map(r=>[r.id,r]));
  const get=id=>{assert(byId.has(id),`missing source ${id}`);return byId.get(id);};
  const all=t=>(data[t]||[]), entries=[], values=new Map(), net=[],states=[],taxAdjustments=[],readInventory=new Map();
  const check=(row,fields)=>{for(const [key,value]of Object.entries(fields))value instanceof D?exact(row[key],value,`${row.id}.${key}`):assert.equal(row[key]??null,value??null,`${row.id}.${key}`);};
  const quant=(amount,resource)=>tb(resource)==='currency'?d(amount).round(get(resource).precision):d(amount);
  const capture=(reader,source_root,source_slot,kind,arguments_,path,fallback,phase='refresh')=>{
    const description={reader,phase,source_root,source_slot,kind,arguments:arguments_,path,fallback};
    const identity=JSON.stringify([reader,description.phase,source_root,source_slot,kind,arguments_,path,
      fallback===undefined?['none']:['value',fallback]]);
    readInventory.set(identity,description);
  };
  const prefix=(reader,owner,slot,measure,at)=>capture(reader,owner,slot,'before',[at],`measures.${measure}.sum`,'0');
  const rate=(reader,pair,from,to,at)=>{
    if(from===to){assert(!pair,'same-unit conversion has no pair');return d(1);}
    const p=get(pair);assert.equal(p.given_resource,from);assert.equal(p.received_resource,to);assert(through(p.effective_at,at));
    capture(reader,pair,'','record',[],'effective_at',undefined);
    capture(reader,pair,'z_rates','latest',[[next(at)]],'measures.rate.sum',undefined);
    const previous=all('exchange_rate').filter(r=>r.pair===pair&&through(r.effective_at,at)).sort((a,b)=>compare([a.effective_at],[b.effective_at])).at(-1);
    if(!previous)capture(reader,pair,'','record',[],'initial_rate',undefined);
    return d(previous?previous.rate:p.initial_rate);
  };
  const account=id=>{
    const a=get(id),org=tb(id).startsWith('organization_')?get(a.organization):null;
    const subsidiary=org?org.subsidiary:a.subsidiary, resource=money.includes(tb(id))?a.currency:a.resource;
    check(a,{resource,subsidiary,reporting_currency:get(subsidiary).currency});
    return {row:a,resource,org,subsidiary,reporting:get(subsidiary).currency};
  };
  const add=(row,slot,owner,root,at,measures={},tags={},dependent=false,business)=>{
    if(!owner)return;
    entries.push({link:{rid:row.id,slot},owner:{rid:owner,slot:root},key:[...(business||[at]),row.id,slot],
      measures:Object.fromEntries(Object.entries(measures).map(([k,v])=>[k,d(v).number()])),tags,dependent});
  };
  const scale=(e,k,currency)=>{
    const convert=n=>d(e[n]).mul(k).round(get(currency).precision),r=convert('real'),reserved=convert('reserved');
    return {...eff(r,convert('receivable'),convert('payable')),reserved,available:sub(r,reserved),expected:convert('expected'),
      sales_value:convert('sales_value'),purchase_value:convert('purchase_value'),payment_value:convert('payment_value'),fees:convert('fees')};
  };
  const post=(row,slot,id,at,e,dependent=false)=>{
    const a=account(id),native={...e,net:sub(e.receivable,e.payable),available:sub(e.real,e.reserved)};
    const v=scale(native,rate(row.id,a.row.valuation_pair,a.resource,a.reporting,at),a.reporting);
    let report;
    if(a.org) report={...eff(0,v.payable,v.receivable),counterparty_real:v.real.neg(),counterparty_receivable:v.payable,counterparty_payable:v.receivable,sales_value:v.sales_value,purchase_value:v.purchase_value,payment_value:v.payment_value};
    else if(['direct_tax_account','indirect_tax_account'].includes(tb(id)))report={...eff(0,v.receivable,v.payable),tax_real:v.real,tax_receivable:v.receivable,tax_payable:v.payable};
    else if(['misc_currency_account','misc_stock_account'].includes(tb(id)))report={...eff(),misc_real:v.real};
    else report={...eff(v.real),owned_real:v.real,fees:v.fees};
    add(row,slot,id,'z_history',at,native,{resource:a.resource,subsidiary:a.subsidiary},dependent);
    add(row,slot+'_subsidiary',a.subsidiary,'z_history',at,report,{currency:a.reporting});

    if(a.org){
      add(row,slot+'_organization',a.org.id,'z_history',at,scale(native,rate(row.id,a.row.organization_pair,a.resource,a.org.currency,at),a.org.currency),{currency:a.org.currency,subsidiary:a.subsidiary});

    }
  };
  const context=id=>{const invoice=get(id),a=account(invoice.account);return {invoice:id,currency_account:a.row.id,organization:a.org.id,subsidiary:a.subsidiary,currency:a.resource,invoice_date:invoice.invoice_date,is_sale:tb(id)==='sales_invoice',precision:get(a.resource).precision};};
  const commercial=(row,c,amount=0,paid=0,note=row.adjustment_note)=>{
    check(row,c);const value=sub(amount,paid),sign=c.is_sale?1:-1;
    const base=['sales_issue','purchase_issue','issue_adjustment'].includes(tb(row.id));
    post(row,'z_counterparty',c.currency_account,row.effective_at,{...claim(value.mul(-sign)),real:d(paid).mul(-sign),
      sales_value:base&&c.is_sale?amount:0,purchase_value:base&&!c.is_sale?amount:0,payment_value:paid});
    add(row,'z_invoice',c.invoice,'z_history',row.effective_at,{...claim(value.mul(sign)),amount,paid,balance:value},{account:c.currency_account,currency:c.currency});
    if(note){check(row,{adjustment_note:note});add(row,'z_note',note,'z_lines',row.effective_at,{amount,paid,positive:value.cmp(0)>0?1:0,negative:value.cmp(0)<0?1:0},{account:c.currency_account,is_sale:c.is_sale});}
  };
  const taxEff=(sale,amount)=>({...claim(d(amount).mul(sale?-1:1)),credit_available:sale?0:amount,liability_available:sale?amount:0});
  const trade=(row,c,at,quantity,amount,org)=>{
    const a=account(c.currency_account),currency=org?a.org.currency:a.reporting,pair=org?a.row.organization_pair:a.row.valuation_pair;
    const value=quant(d(amount).mul(rate(row.id,pair,a.resource,currency,at)),currency);
    return {sales_quantity:c.is_sale?quantity:0,purchase_quantity:c.is_sale?0:quantity,
      sales_reporting_value:c.is_sale?value:0,purchase_reporting_value:c.is_sale?0:value};
  };
  const rule=(basis,row,precision)=>{let v=d(basis).mul(row.rate).mul(d(0.01));if(row.upper_bound!=null&&v.cmp(row.upper_bound)>0)v=d(row.upper_bound);if(v.cmp(row.lower_bound)<0)v=d(row.lower_bound);return v.round(precision);};
  for(const row of all('organization'))add(row,'z_subsidiary',row.subsidiary,'z_organizations',null,{}, {},false,[row.name]);
  for(const row of [...money,...stocks].flatMap(all)){
    const a=account(row.id);add(row,'z_subsidiary',a.subsidiary,'z_accounts',null,{}, {},false,[a.resource]);
    if(a.org)add(row,'z_organization',a.org.id,'z_accounts',null,{}, {},false,[a.resource]);
    if(tb(row.id)==='stock_account')add(row,'z_identity',row.operating_unit,'z_stock_keys',null,{}, {},false,[a.resource]);
  }
  for(const row of all('exchange_rate'))add(row,'z_pair',row.pair,'z_rates',row.effective_at,{rate:row.rate});
  for(const row of [...all('account_entry'),...all('stock_entry')])post(row,'z_account',row.account,row.effective_at,{...eff(row.real,row.receivable,row.payable),credit_available:row.receivable,liability_available:row.payable});
  for(const row of [...all('sales_issue'),...all('purchase_issue')]){
    const c=context(row.invoice),amount=d(row.quantity).mul(row.price).round(c.precision),q=d(row.quantity).mul(c.is_sale?-1:1);
    check(row,{amount});commercial(row,c,amount);
    post(row,'z_stock',row.stock_account,row.effective_at,{...eff(q),...trade(row,c,row.effective_at,row.quantity,amount,false)});
    post(row,'z_goods',row.counterparty_stock,row.effective_at,{...eff(q.neg()),...trade(row,c,row.effective_at,row.quantity,amount,true)});
    const state={quantity:d(row.quantity),price:d(row.price),base:amount};
    add(row,'z_self',row.id,'z_state',row.effective_at,state);add(row,'z_net_self',row.id,'z_net',row.effective_at,{amount});
    states.push({issue:row.id,at:row.effective_at,...state});net.push({issue:row.id,at:row.effective_at,amount});values.set(row.id,{row,c,amount});
  }
  for(const row of all('issue_adjustment').sort((a,b)=>compare([a.effective_at,a.id],[b.effective_at,b.id]))){
    prefix(row.id,row.source,'z_state','quantity',row.effective_at);
    prefix(row.id,row.source,'z_state','price',row.effective_at);
    const src=values.get(row.source),source=src.row,c=src.c,prior=states.filter(e=>e.issue===row.source&&before(e.at,row.effective_at));
    const quantity=sum(prior.map(e=>e.quantity)),price=sum(prior.map(e=>e.price)),qd=d(row.quantity_delta),pd=d(row.price_delta);
    const amount=quantity.add(qd).mul(price.add(pd)).round(c.precision).add(quantity.mul(price).round(c.precision).neg());
    check(row,{quantity_before:quantity,price_before:price,amount_delta:amount,source_at:source.effective_at,stock_account:source.stock_account,counterparty_stock:source.counterparty_stock});
    commercial(row,c,amount);const moved=qd.mul(c.is_sale?-1:1);
    post(row,'z_stock',source.stock_account,row.effective_at,{...eff(moved),...trade(row,c,row.effective_at,qd,amount,false)});
    post(row,'z_goods',source.counterparty_stock,row.effective_at,{...eff(moved.neg()),...trade(row,c,row.effective_at,qd,amount,true)});
    add(row,'z_state',source.id,'z_state',row.effective_at,{quantity:qd,price:pd,base:amount},{},false);add(row,'z_order',source.id,'z_adjustments',row.effective_at);add(row,'z_net',source.id,'z_net',row.effective_at,{amount});
    states.push({issue:source.id,at:row.effective_at,quantity:qd,price:pd,base:amount});net.push({issue:source.id,at:row.effective_at,amount});values.set(row.id,{row,c,amount,issue:source.id});
  }
  for(const row of [...originalTaxes,...changedTaxes].flatMap(all).sort((a,b)=>compare([a.effective_at,a.id],[b.effective_at,b.id]))){
    const kind=tb(row.id),original=originalTaxes.includes(kind),src=original?values.get(row.source):values.get(row.source_tax);
    assert(src,`${row.id} original is earlier`);const c=src.c,issue=original?row.source:src.issue;
    let amount,basis,beforeBasis,delta,sourceTax,parent;
    const isNet=original?kind==='issue_net_tax':kind.endsWith('_net_tax');
    if(original){
      prefix(row.id,row.source,isNet?'z_net':'z_state',isNet?'amount':'base',isNet?row.effective_at:next(row.effective_at));
      basis=isNet?sum(net.filter(e=>e.issue===issue&&before(e.at,row.effective_at)).map(e=>e.amount)):sum(states.filter(e=>e.issue===issue&&through(e.at,row.effective_at)).map(e=>e.base));amount=rule(basis,row,c.precision);check(row,{basis,amount});}
    else {
      sourceTax=src.row;
      if(row.adjustment){parent=values.get(row.adjustment);assert(parent,`${row.id} parent already replayed`);delta=parent.amount;
        if(kind==='issue_adjustment_tax')prefix(row.id,row.source_tax,'z_adjustments','basis',row.effective_at);
        if(kind==='issue_adjustment_net_tax'||kind==='tax_adjustment_net_tax'){
          prefix(row.id,row.adjustment,'z_taxes','amount',row.effective_at);
          prefix(row.id,row.source_tax,'z_adjustments','basis',row.effective_at);
        }
        if(isNet)delta=delta.add(sum(taxAdjustments.filter(e=>e.parent===row.adjustment&&before(e.at,row.effective_at)).map(e=>e.amount)));
        beforeBasis=src.basis.add(sum(taxAdjustments.filter(e=>e.tax===row.source_tax&&before(e.at,row.effective_at)).map(e=>e.delta)));
        amount=rule(beforeBasis.add(delta),sourceTax,c.precision).add(rule(beforeBasis,sourceTax,c.precision).neg());
        check(row,{basis_before:beforeBasis,basis_delta:delta,adjustment_delta:parent.amount,adjustment_note:parent.row.adjustment_note});
      }else amount=d(row.amount_delta);
      check(row,{amount_delta:amount});
    }
    const taxAccount=original?row.tax_account:sourceTax.tax_account,acct=account(taxAccount),pair=original?row.exchange_pair:sourceTax.exchange_pair;
    const fx=rate(row.id,pair,c.currency,acct.resource,row.effective_at),accountAmount=!original&&row.entered_account_delta!=null?d(row.entered_account_delta):quant(amount.mul(fx),acct.resource);
    check(row,{exchange_rate:fx,[original?'account_amount':'account_delta']:accountAmount});
    commercial(row,c,amount,0,parent?parent.row.adjustment_note:row.adjustment_note);post(row,'z_tax',taxAccount,row.effective_at,taxEff(c.is_sale,accountAmount));
    if(original){
      add(row,'z_issue_net',issue,'z_net',row.effective_at,{amount},{},false);
      add(row,'z_self',row.id,'z_capacity',row.effective_at,{amount,account_amount:accountAmount});
    }else{
      add(row,'z_source',row.source_tax,'z_capacity',row.effective_at,{amount,account_amount:accountAmount});add(row,'z_issue_net',issue,'z_net',row.effective_at,{amount});
      if(parent){add(row,'z_order',row.source_tax,'z_adjustments',row.effective_at,{basis:delta},{},false);add(row,'z_adjustment',row.adjustment,'z_taxes',row.effective_at,{amount},{},false);taxAdjustments.push({tax:row.source_tax,parent:row.adjustment,at:row.effective_at,delta,amount});}
    }
    net.push({issue,at:row.effective_at,amount});values.set(row.id,{row,c,amount,accountAmount,basis,issue});
  }
  for(const row of all('invoice_settlement')){
    const c=context(row.invoice),cash=d(row.amount),native=account(row.treasury).resource,fx=rate(row.id,row.exchange_pair,native,c.currency,row.effective_at),amount=quant(cash.mul(fx),c.currency);
    check(row,{exchange_rate:fx,invoice_amount:amount});commercial(row,c,0,amount);post(row,'z_cash',row.treasury,row.effective_at,eff(cash.mul(c.is_sale?1:-1)));
    add(row,'z_self',row.id,'z_capacity',row.effective_at,{cash,invoice_amount:amount});values.set(row.id,{row,c,amount,cash});
  }
  for(const row of all('payment_adjustment')){
    const source=values.get(row.source),c=source.c,cash=d(row.amount_delta),a=account(source.row.treasury),fx=rate(row.id,source.row.exchange_pair,a.resource,c.currency,row.effective_at);
    const amount=row.entered_invoice_delta==null?quant(cash.mul(fx),c.currency):d(row.entered_invoice_delta);
    check(row,{exchange_rate:fx,invoice_delta:amount,treasury:source.row.treasury,exchange_pair:source.row.exchange_pair});commercial(row,c,0,amount);
    post(row,'z_cash',source.row.treasury,row.effective_at,eff(cash.mul(c.is_sale?1:-1)));add(row,'z_source',row.source,'z_capacity',row.effective_at,{cash,invoice_amount:amount});values.set(row.id,{row,c,amount,cash});
  }
  for(const row of all('payment_withholding')){
    const source=values.get(row.source),c=source.c,a=account(row.tax_account),fx=rate(row.id,row.exchange_pair,c.currency,a.resource,row.effective_at),amount=quant(d(row.amount).mul(fx),a.resource);
    check(row,{exchange_rate:fx,account_amount:amount});commercial(row,c,0,row.amount);post(row,'z_tax',row.tax_account,row.effective_at,taxEff(!c.is_sale,amount));
  }
  for(const row of all('account_claim')){
    const r=row.claim_kind==='receivable',amount=d(row.amount);
    post(row,'z_account',row.account,row.effective_at,{...claim(amount.mul(r?1:-1)),credit_available:r?amount:0,liability_available:r?0:amount});add(row,'z_self',row.id,'z_capacity',row.effective_at,{remaining:amount});
  }
  for(const row of all('claim_settlement')){
    const source=get(row.source),a=account(source.account),paid=account(row.paid_account),r=source.claim_kind==='receivable',receive=a.org?!r:r;
    const fx=rate(row.id,row.exchange_pair,paid.resource,a.resource,row.effective_at),amount=quant(d(row.amount).mul(fx),a.resource);
    check(row,{exchange_rate:fx,account_amount:amount,account:source.account,resource:a.resource,paid_resource:paid.resource});
    post(row,'z_paid',row.paid_account,row.effective_at,eff(d(row.amount).mul(receive?1:-1)));
    post(row,'z_account',source.account,row.effective_at,{...claim(amount.mul(r?-1:1)),real:amount.mul(receive?-1:1),credit_available:r?amount.neg():0,liability_available:r?0:amount.neg()});
    add(row,'z_source',row.source,'z_capacity',row.effective_at,{remaining:amount.neg()});
  }
  for(const kind of ['tax_settlement','tax_refund','tax_deposit'])for(const row of all(kind)){
    const a=account(row.tax_account),cash=account(row.treasury),fx=rate(row.id,row.exchange_pair,cash.resource,a.resource,row.effective_at),amount=quant(d(row.amount).mul(fx),a.resource);
    const refund=kind==='tax_refund',deposit=kind==='tax_deposit',signed=amount.mul(refund?-1:1);
    check(row,{exchange_rate:fx,account_amount:amount});post(row,'z_cash',row.treasury,row.effective_at,eff(d(row.amount).mul(refund?1:-1)));
    post(row,'z_tax',row.tax_account,row.effective_at,{...claim(signed),real:signed,credit_available:deposit?amount:refund?amount.neg():0,liability_available:!refund&&!deposit?amount.neg():0});
  }
  for(const row of all('tax_offset')){
    const a=account(row.credit_account),b=account(row.liability_account),fx=rate(row.id,row.exchange_pair,a.resource,b.resource,row.effective_at),amount=quant(d(row.amount).mul(fx),b.resource);
    check(row,{exchange_rate:fx,liability_amount:amount});post(row,'z_credit',row.credit_account,row.effective_at,{...claim(d(row.amount).neg()),credit_available:d(row.amount).neg()});post(row,'z_liability',row.liability_account,row.effective_at,{...claim(amount),liability_available:amount.neg()});
  }
  for(const kind of ['production_input','production_output','production_cost','production_capacity'])for(const row of all(kind)){
    const p=get(row.production);check(row,{starts_at:p.starts_at,ends_at:p.ends_at});
    const type=kind.slice('production_'.length),quantity=d(type==='cost'?row.amount:row.quantity);
    add(row,'z_production',p.id,'z_lines',['output','cost'].includes(type)?p.ends_at:p.starts_at,{lines:1},{kind:type});
    if(type==='capacity'){add(row,'z_start',row.operating_unit,'z_capacity',p.starts_at,{used:quantity});add(row,'z_end',row.operating_unit,'z_capacity',p.ends_at,{used:quantity.neg()});continue;}
    const acc=type==='cost'?row.treasury:row.stock_account;
    if(type==='output'){
      post(row,'z_start',acc,p.starts_at,{...eff(),expected:quantity});post(row,'z_end',acc,p.ends_at,{...eff(quantity),expected:quantity.neg()});add(row,'z_self',row.id,'z_capacity',p.ends_at,{quantity});
    }else{
      post(row,'z_start',acc,p.starts_at,{...eff(),reserved:quantity});post(row,'z_end',acc,p.ends_at,{...eff(quantity.neg()),reserved:quantity.neg()});
      if(type==='input')add(row,'z_gross',acc,'z_gross',p.starts_at,{quantity});
    }
  }
  for(const row of all('resource_exchange')){
    const a=account(row.from_account),b=account(row.to_account),fx=rate(row.id,row.exchange_pair,a.resource,b.resource,row.effective_at),amount=quant(d(row.from_amount).mul(fx),b.resource);
    check(row,{exchange_rate:fx,to_amount:amount,from_resource:a.resource,to_resource:b.resource});post(row,'z_from',row.from_account,row.effective_at,eff(d(row.from_amount).neg()));post(row,'z_to',row.to_account,row.effective_at,eff(amount));
    add(row,'z_output',row.production_output,'z_capacity',row.effective_at,{quantity:d(row.from_amount).neg()});add(row,'z_observation',row.exchange_pair,'z_observations',row.effective_at,{given:row.from_amount,received:amount});values.set(row.id,{row,amount});
  }
  for(const kind of feeTables)for(const row of all(kind)){
    let cash,at=row.effective_at,basis;
    if(kind==='resource_exchange'){
      const a=account(row.from_account),b=account(row.to_account);cash=tb(a.resource)==='currency'?row.from_account:tb(b.resource)==='currency'?row.to_account:null;
      basis=tb(a.resource)==='currency'?d(row.from_amount):values.get(row.id).amount;
    }else if(kind==='claim_settlement'){cash=tb(account(row.paid_account).resource)==='currency'?row.paid_account:null;basis=d(row.amount);}
    else if(kind==='payment_adjustment'){cash=get(row.source).treasury;basis=d(row.amount_delta);}
    else {cash=row.treasury;basis=d(row.amount);if(kind==='production_cost')at=get(row.production).ends_at;}
    if(basis.cmp(0)<0)basis=basis.neg();check(row,{fee_basis:basis,fee_treasury:cash,fee_at:at});
    if(!row.fee_account){check(row,{fee_amount:d(0),fee_tax_amount:d(0),fee_credit_amount:d(0)});continue;}
    const currency=account(cash).resource,precision=get(currency).precision;
    const amount=rule(basis,{rate:row.fee_rate,lower_bound:row.fee_lower_bound,upper_bound:row.fee_upper_bound},precision);
    const tax=rule(amount,{rate:row.fee_tax_rate,lower_bound:row.fee_tax_lower_bound,upper_bound:row.fee_tax_upper_bound},precision),total=amount.add(tax);
    const fx=rate(row.id,row.fee_exchange_pair,currency,account(row.fee_account).resource,at);
    const expense=quant(amount.add(row.fee_tax_creditable?0:tax).mul(fx),account(row.fee_account).resource);
    const credit=row.fee_tax_creditable?quant(tax.mul(rate(row.id,row.fee_tax_exchange_pair,currency,account(row.fee_tax_account).resource,at)),account(row.fee_tax_account).resource):d(0);
    check(row,{fee_amount:amount,fee_tax_amount:tax,fee_account_amount:expense,fee_credit_amount:credit});
    post(row,'z_fee_cash',cash,at,{...eff(total.neg()),reserved:kind==='production_cost'?total.neg():0,fees:total});post(row,'z_fee_account',row.fee_account,at,eff(expense));
    if(row.fee_tax_creditable)post(row,'z_fee_tax',row.fee_tax_account,at,{...eff(credit,credit),credit_available:credit});
    if(kind==='production_cost')post(row,'z_fee_start',cash,get(row.production).starts_at,{...eff(),reserved:total});

  }
  // Validators execute independently from member refreshes. Derive their
  // explicit read calls from the source-backed posting entries and parent rows.
  for(const row of [...all('sales_invoice'),...all('purchase_invoice')]){
    const contributions=entries.filter(entry=>entry.owner.rid===row.id&&entry.owner.slot==='z_history');
    if(!contributions.length)continue;
    const boundary=next(row.invoice_date);
    capture(row.id,row.id,'z_history','before',[boundary],'measures.balance.sum','0','validate');
    const last=contributions.map(entry=>entry.key[0]).sort((a,b)=>compare([a],[b])).at(-1);
    if(instant(last)>=instant(boundary))
      capture(row.id,row.id,'z_history','range',[[boundary],[next(last)]],'measures.balance.instant_min','0','validate');
  }
  for(const row of all('production_input')){
    const stock=get(row.stock_account),production=get(row.production),start=production.starts_at;
    capture(row.id,stock.id,'z_history','before',[start],'measures.available.sum','0','validate');
    capture(row.id,stock.id,'z_gross','range',[[start],[next(start)]],'measures.quantity.sum','0','validate');
  }
  // Schema declaration order chooses coincident-slot representatives. Arithmetic
  // and expected memberships above use only source facts; this is identity metadata.
  entries.sort((a,b)=>a.link.rid.localeCompare(b.link.rid)||((slots[tb(a.link.rid)]?.indexOf(a.link.slot)??0)-(slots[tb(b.link.rid)]?.indexOf(b.link.slot)??0)));
  const grouped=new Map();
  for(const e of entries){
    const key=JSON.stringify([e.link.rid,e.owner,e.key.slice(0,-2)]),old=grouped.get(key);
    if(!old){grouped.set(key,{...e,measures:{...e.measures},tags:{...e.tags}});continue;}
    for(const [k,v]of Object.entries(e.measures))old.measures[k]=d(old.measures[k]).add(v).number();
    for(const [k,v]of Object.entries(e.tags)){if(k in old.tags)assert.deepEqual(old.tags[k],v);old.tags[k]=v;}
    old.dependent ||=e.dependent;
  }
  const groupedEntries=[...grouped.values()];
  return { data, sourceRows, groupedEntries,
    expectedReads:[...readInventory.values()] };
}

function expectedReadInventory(data,slots={}) {
  return evaluateSource(data,slots).expectedReads;
}

function verify(data,slots={},rootSpecs) {
  const model=evaluateSource(data,slots);
  const treeRows=Object.entries(data).filter(([table])=>!['audit_mutation','rebase_read','rebase_read_frame','rebase_read_group','rebase_read_lock'].includes(table)).flatMap(([,rows])=>rows||[]);
  tree.verify(treeRows,treeRows,model.groupedEntries,compare);
  require('../temporal-tree/read-oracle').verifyReads(data,model.sourceRows,model.groupedEntries,compare,
    {rootSpecs,expectedReads:model.expectedReads});
  return data;
}

module.exports={tables,snapshot,verify,expectedReadInventory,D,exact,compare};

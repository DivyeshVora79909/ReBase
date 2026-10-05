'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadMaterials } = require('../compiler/materials');
const { generateBundle } = require('../compiler/pipeline');
const { start, client, applySchema } = require('../temporal-tree/harness');
const treeOracle = require('../temporal-tree/oracle');

const issueId = 'sales_invoice_issue:delivery';
const number = value => Number(String(value ?? 0).replace(/dec$/i, ''));
const decimal = value => {
  const [whole, fraction = ''] = String(value).split('.');
  return { value: BigInt(whole + fraction), scale: fraction.length };
};
const rounded = (value, divisor) => value / divisor + (value % divisor * 2n >= divisor ? 1n : 0n);
function money(value, precision) {
  const input = decimal(value);
  return input.scale > precision ? rounded(input.value, 10n ** BigInt(input.scale - precision))
    : input.value * 10n ** BigInt(precision - input.scale);
}
function product(left, right, precision) {
  const a = decimal(left), b = decimal(right), scale = a.scale + b.scale;
  return scale > precision ? rounded(a.value * b.value, 10n ** BigInt(scale - precision))
    : a.value * b.value * 10n ** BigInt(precision - scale);
}
function rated(units, rate) {
  const parsed = decimal(rate);
  return rounded(units * parsed.value, 10n ** BigInt(parsed.scale));
}

// Force primary source scans: 3.3.0 can duplicate multi-reader rows when its
// optimizer serves ORDER BY id from a secondary index.
const snapshot = q => q(`RETURN {
  issues: (SELECT * FROM sales_invoice_issue WITH NOINDEX ORDER BY id),
  lines: (SELECT * FROM sales_invoice_line WITH NOINDEX ORDER BY id),
  base: (SELECT * FROM sales_delivery_tax WITH NOINDEX ORDER BY id),
  compound: (SELECT * FROM sales_delivery_compound_tax WITH NOINDEX ORDER BY id),
  invoiceTaxes: (SELECT * FROM sales_invoice_tax_component WITH NOINDEX ORDER BY id),
  invoices: (SELECT * FROM sales_invoice WITH NOINDEX ORDER BY id),
  claims: (SELECT * FROM claim_account WITH NOINDEX ORDER BY id),
  deliveries: (SELECT * FROM stock_out WITH NOINDEX ORDER BY id),
  currencies: (SELECT * FROM currency WITH NOINDEX ORDER BY id),
  rules: (SELECT * FROM sales_tax_rule_version WITH NOINDEX ORDER BY id),
  treasuryAccounts: (SELECT * FROM treasury_account WITH NOINDEX ORDER BY id),
  cashins: (SELECT * FROM cash_in WITH NOINDEX ORDER BY id),
  allocations: (SELECT * FROM sales_invoice_cash_allocation WITH NOINDEX ORDER BY id),
  audit: (SELECT * FROM audit_mutation WITH NOINDEX ORDER BY id)
};`);

function verify(data) {
  const invoices = new Map(data.invoices.map(row => [row.id, row]));
  const currencies = new Map(data.currencies.map(row => [row.id, row]));
  const rules = new Map(data.rules.map(row => [row.id, row]));
  const claims = new Map(data.claims.map(row => [row.id, row]));
  const issues = new Map(data.issues.map(row => [row.id, row]));
  const cashins = new Map(data.cashins.map(row => [row.id, row]));
  const treasuryAccounts = new Map(data.treasuryAccounts.map(row => [row.id, row]));
  const entries = [];
  const expectedTaxes = new Map();
  const expectedInvoiceTaxes = new Map();
  const add = (row, slot, owner, root, measures, tags) => entries.push({
    link: { rid: row.id, slot }, owner: { rid: owner, slot: root },
    key: [row.effective_at, row.id, slot], measures, tags, dependent: false,
  });
  for (const issue of data.issues) {
    const invoice = invoices.get(issue.invoice), precision = currencies.get(invoice.currency).precision;
    let invoiceBase = 0n;
    for (const input of issue.lines) {
      const line = data.lines.find(row => row.rebase_managed_source === issue.id && row.rebase_managed_role === input.line_key);
      assert(line, `required delivery line ${input.line_key}`);
      const base = product(input.billed_quantity, input.unit_price, precision);
      invoiceBase += base;
      assert.equal(money(line.amount, precision), base, 'line rounds its own priced delivery');
      assert.equal(line.source, input.source);
      assert.equal(line.invoice, issue.invoice);
      assert.equal(line.effective_at, issue.issued_at);
      const amount = Number(base) / 10 ** precision, currency = { currency: invoice.currency };
      add(line, 'z_claim', invoice.claim_account, 'z_history', { receivable: amount, net: amount }, currency);
      add(line, 'z_invoice', invoice.id, 'z_outstanding', { outstanding: amount }, currency);
      add(line, 'z_taxable_input', invoice.id, 'z_taxable_input', { basis: amount }, currency);
      add(line, 'z_source', input.source, 'z_billing', { billed: number(input.billed_quantity) }, { resource: 'item:unit' });
      const baseTaxes = new Map();
      for (const component of input.tax_components ?? []) {
        const rule = component.rule_version && rules.get(component.rule_version);
        const tax = !rule ? money(component.amount, precision) : rule.kind === 'fixed'
          ? money(rule.fixed_amount, precision) : rated(base, rule.rate);
        baseTaxes.set(component.tax_key, tax);
        expectedTaxes.set(`${line.id}/base/${component.tax_key}`, { line, invoice, component, tax, precision });
      }
      for (const component of input.compound_tax_components ?? []) {
        assert(baseTaxes.has(component.predecessor_tax_key), 'compound predecessor is from this delivery');
        const rule = rules.get(component.rule_version);
        const tax = rated(base + baseTaxes.get(component.predecessor_tax_key), rule.rate);
        expectedTaxes.set(`${line.id}/compound/${component.tax_key}`, { line, invoice, component, tax, precision });
      }
    }
    for (const component of issue.tax_components ?? []) {
      assert.equal(component.aggregate_rule_version ?? null, null,
        'coexistence oracle covers direct invoice tax rows, not published aggregate recipes');
      const rule = component.rule_version && rules.get(component.rule_version);
      const tax = !rule ? money(component.amount, precision) : rule.kind === 'fixed'
        ? money(rule.fixed_amount, precision) : rated(invoiceBase, rule.rate);
      expectedInvoiceTaxes.set(`${issue.id}/tax:${component.tax_key}`, {
        issue, invoice, component, tax, precision,
      });
    }
  }
  assert.equal(data.lines.length, data.issues.reduce((count, issue) => count + issue.lines.length, 0));
  assert.equal(data.base.length + data.compound.length, expectedTaxes.size, 'exact managed component lifecycle');
  for (const [kind, rows] of [['base', data.base], ['compound', data.compound]]) for (const row of rows) {
    const expected = expectedTaxes.get(`${row.line}/${kind}/${row.tax_key}`);
    assert(expected, `unexpected tax child ${row.id}`);
    const { line, invoice, component, tax, precision } = expected;
    assert.equal(money(row.amount, precision), tax, `${kind} uses this delivery's decimal base`);
    assert.equal(row.delivery, line.source, 'tax keeps physical delivery provenance');
    assert.equal(row.invoice, invoice.id);
    assert.equal(row.claim_account, invoice.claim_account);
    assert.equal(row.currency, invoice.currency);
    assert.equal(row.tax_claim_account, component.tax_claim_account);
    assert.equal(row.rule_version, component.rule_version);
    assert.equal(row.rebase_managed_source, line.rebase_managed_source);
    assert.equal(row.effective_at, line.effective_at);
    if (kind === 'compound') {
      const predecessor = data.base.find(base => base.id === row.predecessor);
      assert.equal(predecessor.line, row.line);
      assert.equal(predecessor.tax_key, component.predecessor_tax_key);
    }
    const amount = Number(tax) / 10 ** precision, currency = { currency: invoice.currency };
    add(row, 'z_delivery', row.line, 'z_taxes', { tax: amount }, currency);
    add(row, 'z_invoice', row.invoice, 'z_outstanding', { outstanding: amount }, currency);
    add(row, 'z_customer', row.claim_account, 'z_history', { receivable: amount, net: amount }, currency);
    add(row, 'z_tax', row.tax_claim_account, 'z_history', { payable: amount, net: -amount }, currency);
    assert.equal(claims.get(row.tax_claim_account).currency, row.currency);
  }
  assert.equal(data.invoiceTaxes.length, expectedInvoiceTaxes.size, 'exact legacy invoice tax lifecycle');
  for (const row of data.invoiceTaxes) {
    const expected = expectedInvoiceTaxes.get(`${row.rebase_managed_source}/${row.rebase_managed_role}`);
    assert(expected, `unexpected invoice tax child ${row.id}`);
    const { issue, invoice, component, tax, precision } = expected;
    assert.equal(money(row.amount, precision), tax, 'invoice tax uses the invoice-wide priced base');
    assert.equal(row.invoice, invoice.id);
    assert.equal(row.claim_account, invoice.claim_account);
    assert.equal(row.tax_claim_account, component.tax_claim_account);
    assert.equal(row.rule_version, component.rule_version);
    assert.equal(row.effective_at, issue.issued_at);
    const amount = Number(tax) / 10 ** precision, currency = { currency: invoice.currency };
    add(row, 'z_customer', row.claim_account, 'z_history', { receivable: amount, net: amount }, currency);
    add(row, 'z_invoice', row.invoice, 'z_outstanding', { outstanding: amount }, currency);
    add(row, 'z_tax', row.tax_claim_account, 'z_history', { payable: amount, net: -amount }, currency);
  }
  for (const row of data.cashins) {
    const account = treasuryAccounts.get(row.to_account);
    const amount = number(row.amount), currency = { currency: account.currency };
    add(row, 'z_to', row.to_account, 'z_history', { balance: amount }, currency);
    add(row, 'z_available_grant', row.id, 'z_allocations', { available: amount }, currency);
  }
  for (const row of data.allocations) {
    const issue = issues.get(row.target), invoice = invoices.get(issue.invoice), source = cashins.get(row.source);
    const amount = number(row.amount), currency = { currency: invoice.currency };
    add(row, 'z_claim', invoice.claim_account, 'z_history', { receivable: -amount, net: -amount }, currency);
    add(row, 'z_invoice', invoice.id, 'z_outstanding', { outstanding: -amount }, currency);
    add(row, 'z_source', source.id, 'z_allocations', { allocated: amount, available: -amount },
      { currency: treasuryAccounts.get(source.to_account).currency });
  }
  // Inspect only the participating roots; unrelated stock/return trees retain
  // their own existing source oracle. Every line/tax node is reconstructed here.
  const owners = [
    ...data.claims.map(({ id, z_history }) => ({ id, z_history })),
    ...data.invoices.map(({ id, z_outstanding, z_taxable_input }) => ({ id, z_outstanding, z_taxable_input })),
    ...data.lines.map(({ id, z_taxes }) => ({ id, z_taxes })),
    ...data.deliveries.map(({ id, z_billing }) => ({ id, z_billing })),
    ...data.treasuryAccounts.map(({ id, z_history }) => ({ id, z_history })),
    ...data.cashins.map(({ id, z_allocations }) => ({ id, z_allocations })),
  ];
  treeOracle.verify(owners, [...data.lines, ...data.base, ...data.compound,
    ...data.invoiceTaxes, ...data.cashins, ...data.allocations], entries);
  return data;
}

async function main() {
  const materials = loadMaterials({ groups: [
    { name: 'framework', roots: [path.resolve(__dirname, '../../framework')] },
    { name: 'project', roots: [path.resolve(__dirname, '../../designs/all-in-accounting')] },
  ] });
  const compiled = generateBundle(materials);
  const server = await start({ engine: 'surrealkv' }), q = client(server.url);
  let mutations = 0, rejections = 0;
  const mutate = async (sql, actor = q) => { await actor(sql); mutations++; return verify(await snapshot(q)); };
  const reject = async (sql, pattern) => {
    const before = await snapshot(q);
    await assert.rejects(q(sql), pattern);
    assert.deepEqual(await snapshot(q), before, 'rejection restores inputs, all tree paths, children and audit');
    verify(before); rejections++;
  };
  const patch = operations => `UPDATE ONLY ${issueId} PATCH [${operations.join(',')}];`;
  const replace = (field, value) => `{ op:'replace', path:'${field}', value:${value} }`;
  try {
    await q('DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture; USE DB fixture;');
    await applySchema(q, compiled.bundle);
    await q(`
      CREATE rebase_tenant:foreign SET name='Foreign tenant';
      CREATE organization:entity SET owned_by=rebase_tenant:default, name='Entity';
      CREATE organization:customer SET owned_by=rebase_tenant:default, name='Customer';
      CREATE organization:authority SET owned_by=rebase_tenant:default, name='Authority';
      CREATE organization:foreign_entity SET owned_by=rebase_tenant:foreign, name='Foreign entity';
      CREATE organization:foreign_customer SET owned_by=rebase_tenant:foreign, name='Foreign customer';
      CREATE organization:foreign_authority SET owned_by=rebase_tenant:foreign, name='Foreign authority';
      CREATE currency:usd SET owned_by=rebase_tenant:default, code='USD', name='Dollar', precision=2;
      CREATE currency:jpy SET owned_by=rebase_tenant:default, code='JPY', name='Yen', precision=0;
      CREATE currency:foreign_jpy SET owned_by=rebase_tenant:foreign, code='JPY', name='Foreign yen', precision=0;
      CREATE measure_unit:each SET owned_by=rebase_tenant:default, code='each', name='Each', dimension='count';
      CREATE item:unit SET owned_by=rebase_tenant:default, name='Unit', unit=measure_unit:each;
      CREATE operating_unit:store SET owned_by=rebase_tenant:default, economic_entity=organization:entity, name='Store';
      CREATE stock_account:stock SET owned_by=rebase_tenant:default, economic_entity=organization:entity,
        operating_unit=operating_unit:store, resource=item:unit;
      CREATE stock_in:seed SET owned_by=rebase_tenant:default, from_party=organization:customer,
        to_account=stock_account:stock, quantity=20dec, effective_at=d'2026-06-01';
      CREATE stock_out:a SET owned_by=rebase_tenant:default, from_account=stock_account:stock,
        to_party=organization:customer, quantity=4dec, effective_at=d'2026-07-01';
      CREATE stock_out:b SET owned_by=rebase_tenant:default, from_account=stock_account:stock,
        to_party=organization:customer, quantity=4dec, effective_at=d'2026-07-01';
      CREATE stock_out:c SET owned_by=rebase_tenant:default, from_account=stock_account:stock,
        to_party=organization:customer, quantity=4dec, effective_at=d'2026-07-01';
      CREATE tax_account:levy SET owned_by=rebase_tenant:default, authority=organization:authority,
        jurisdiction=organization:entity, label='Delivery levy';
      CREATE tax_account:extra SET owned_by=rebase_tenant:default, authority=organization:authority,
        jurisdiction=organization:entity, label='Compound levy';
      CREATE tax_account:foreign_levy SET owned_by=rebase_tenant:foreign, authority=organization:foreign_authority,
        jurisdiction=organization:foreign_entity, label='Foreign levy';
      CREATE treasury:settlement SET owned_by=rebase_tenant:default, name='Settlement';
      CREATE treasury_account:settlement SET owned_by=rebase_tenant:default,
        economic_entity=organization:entity, treasury=treasury:settlement, currency=currency:jpy, minimum_balance=0dec;
      CREATE claim_account:foreign_customer SET owned_by=rebase_tenant:foreign,
        economic_entity=organization:foreign_entity, opponent=organization:foreign_customer, currency=currency:foreign_jpy;
      CREATE claim_account:foreign_levy SET owned_by=rebase_tenant:foreign,
        economic_entity=organization:foreign_entity, opponent=tax_account:foreign_levy, currency=currency:foreign_jpy;
      CREATE sales_invoice:foreign SET owned_by=rebase_tenant:foreign,
        claim_account=claim_account:foreign_customer, number='DELIVERY-FOREIGN';
      CREATE sales_tax_rule_version:foreign_rate SET owned_by=rebase_tenant:foreign,
        component_key='rate', version='foreign', tax_claim_account=claim_account:foreign_levy,
        regime='fixture', provision='foreign per delivery', valid_from=d'2026-07-01', valid_until=d'2027-01-01',
        kind='proportional', rate=0.10dec;
      CREATE rebase_user:writer SET name='Writer', parents=[rebase_tenant:default];
      DEFINE ACCESS delivery_writer ON DATABASE TYPE RECORD SIGNIN rebase_user:writer;
    `);
    for (const currency of ['usd', 'jpy']) {
      await q(`CREATE claim_account:customer_${currency} SET owned_by=rebase_tenant:default,
          economic_entity=organization:entity, opponent=organization:customer, currency=currency:${currency};
        CREATE claim_account:levy_${currency} SET owned_by=rebase_tenant:default,
          economic_entity=organization:entity, opponent=tax_account:levy, currency=currency:${currency};
        CREATE claim_account:extra_${currency} SET owned_by=rebase_tenant:default,
          economic_entity=organization:entity, opponent=tax_account:extra, currency=currency:${currency};
        CREATE sales_invoice:${currency} SET owned_by=rebase_tenant:default,
          claim_account=claim_account:customer_${currency}, number='DELIVERY-${currency}';`);
      for (const [key, claim, rate] of [['rate', 'levy', '0.10'], ['extra', 'extra', '0.05']]) await q(`
        CREATE sales_tax_rule_version:${key}_${currency} SET owned_by=rebase_tenant:default,
          component_key='${key}', version='delivery', tax_claim_account=claim_account:${claim}_${currency},
          regime='fixture', provision='per delivery', valid_from=d'2026-07-01', valid_until=d'2027-01-01',
          kind='proportional', rate=${rate}dec;`);
    }
    await q(`CREATE sales_invoice:usd_second SET owned_by=rebase_tenant:default,
        claim_account=claim_account:customer_usd, number='DELIVERY-USD-2';
      CREATE sales_tax_rule_version:fixed SET owned_by=rebase_tenant:default,
        component_key='fixed', version='delivery', tax_claim_account=claim_account:levy_usd,
        regime='fixture', provision='per delivery fixed', valid_from=d'2026-07-01', valid_until=d'2027-01-01',
        kind='fixed', fixed_amount=1.25dec;
      CREATE sales_tax_rule_version:tiny SET owned_by=rebase_tenant:default,
        component_key='rate', version='tiny', tax_claim_account=claim_account:levy_usd,
        regime='fixture', provision='zero rejection', valid_from=d'2026-07-01', valid_until=d'2027-01-01',
        kind='proportional', rate=0.000001dec;`);
    const signin = await fetch(`${server.url}/signin`, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ ns: 'temporal_probe', db: 'fixture', ac: 'delivery_writer' }) });
    const { token } = await signin.json(); assert(token);
    const writer = client(server.url, 'fixture', token);
    let data = await mutate(`CREATE ONLY ${issueId} SET owned_by=rebase_user:writer,
      invoice=sales_invoice:usd, issued_at=d'2026-07-02', lines=[
        {line_key:'first', source:stock_out:a, billed_quantity:2dec, unit_price:5.03dec,
          tax_components:[{tax_key:'rate', tax_claim_account:claim_account:levy_usd, rule_version:sales_tax_rule_version:rate_usd}],
          compound_tax_components:[{tax_key:'extra', tax_claim_account:claim_account:extra_usd,
            rule_version:sales_tax_rule_version:extra_usd, predecessor_tax_key:'rate'}]},
        {line_key:'split', source:stock_out:a, billed_quantity:2dec, unit_price:5.04dec,
          tax_components:[{tax_key:'rate', tax_claim_account:claim_account:levy_usd, rule_version:sales_tax_rule_version:rate_usd}]},
        {line_key:'second', source:stock_out:b, billed_quantity:2dec, unit_price:5.04dec,
          tax_components:[{tax_key:'rate', tax_claim_account:claim_account:levy_usd, rule_version:sales_tax_rule_version:rate_usd},
            {tax_key:'manual', tax_claim_account:claim_account:levy_usd, amount:0.25dec},
            {tax_key:'fixed', tax_claim_account:claim_account:levy_usd, rule_version:sales_tax_rule_version:fixed}]}
      ];`, writer);
    const splitSourceLines = data.lines.filter(row => row.source === 'stock_out:a');
    const splitSourceTaxes = data.base.filter(row => row.delivery === 'stock_out:a' && row.tax_key === 'rate');
    const splitSourceQuantity = number(data.deliveries.find(row => row.id === 'stock_out:a').quantity);
    assert.equal(splitSourceLines.length, 2, 'one physical source is billed under two distinct line keys');
    assert.equal(splitSourceLines.reduce((sum, row) => sum + number(row.billed_quantity), 0), 4,
      'split billed quantity reaches, but does not exceed, source quantity');
    assert.equal(splitSourceLines.reduce((sum, row) => sum + number(row.billed_quantity), 0), splitSourceQuantity,
      'shared billed quantity equals the source ceiling');
    assert.equal(splitSourceTaxes.length, 2);
    assert.equal(new Set(splitSourceTaxes.map(row => row.line)).size, 2,
      'each priced portion has its own tax output');
    assert.deepEqual(splitSourceTaxes.map(row => number(row.amount)).sort(), [1.01, 1.01],
      'each priced portion rounds its own tax');
    assert.equal(splitSourceTaxes.reduce((sum, row) => sum + number(row.amount), 0), 2.02,
      'the two source portions round independently instead of taxing their 20.14 combined base once');
    const stable = [...data.base, ...data.compound].map(row => row.id).sort();
    const second = data.lines.find(row => row.rebase_managed_role === 'second').z_taxes;
    data = await mutate(patch([replace('/lines/0/unit_price', '11.06dec')]), writer);
    assert.deepEqual(data.lines.find(row => row.rebase_managed_role === 'second').z_taxes, second, 'other delivery root is unchanged');
    assert.deepEqual([...data.base, ...data.compound].map(row => row.id).sort(), stable, 'line/role identities are stable');
    await mutate(patch([replace('/lines/0/compound_tax_components', '[]')]));
    await mutate(patch([replace('/lines/0/compound_tax_components', `[{tax_key:'extra', tax_claim_account:claim_account:extra_usd,
      rule_version:sales_tax_rule_version:extra_usd, predecessor_tax_key:'rate'}]`)]));
    await mutate(patch([`{op:'remove',path:'/lines/2/tax_components/0/rule_version'}`,
      `{op:'add',path:'/lines/2/tax_components/0/amount',value:1.40dec}`]));
    await mutate(patch([`{op:'remove',path:'/lines/2/tax_components/0/amount'}`,
      `{op:'add',path:'/lines/2/tax_components/0/rule_version',value:sales_tax_rule_version:rate_usd}`]));
    console.log('PASS native issue creation, exact delivery rounding, typed compound dependency, stable IDs and manual/rule transitions');

    await reject(patch([replace('/lines/0/compound_tax_components/0/predecessor_tax_key', "'fixed'")]), /PREDECESSOR|referenc|exist/i);
    await reject(patch([replace('/lines/0/tax_components/0/tax_claim_account', 'claim_account:levy_jpy')]), /DIMENSION|RULE_MISMATCH/);
    await reject(patch([replace('/lines/0/tax_components/0/rule_version', 'sales_tax_rule_version:tiny')]), /amount|ASSERT|assert/i);
    await reject(patch([replace('/issued_at', "d'2027-02-01'")]), /RULE_MISMATCH/);
    await reject(patch([replace('/lines/2/tax_components/1/tax_key', "'rate'")]), /DUPLICATE/);
    await reject(patch([replace('/invoice', 'sales_invoice:foreign')]), /REBASE_TENANT_REFERENCE_MISMATCH|TENANT/);
    await reject(patch([
      replace('/lines/0/tax_components/0/tax_claim_account', 'claim_account:foreign_levy'),
      replace('/lines/0/tax_components/0/rule_version', 'sales_tax_rule_version:foreign_rate'),
    ]), /REBASE_TENANT_REFERENCE_MISMATCH|TENANT/);
    await reject('UPDATE claim_account:customer_usd SET net_ceiling=0dec;', /CEILING/);
    await reject(patch([replace('/lines/1/billed_quantity', '2.01dec')]), /OVERBILLED/);
    await mutate(patch([replace('/lines/0/source', 'stock_out:c')]));
    data = await mutate(`UPDATE ONLY ${issueId} SET invoice=sales_invoice:usd_second;`);
    assert.equal(number(data.invoices.find(row => row.id === 'sales_invoice:usd').z_outstanding.summary.measures.outstanding?.sum), 0);

    data = await mutate(`UPDATE ONLY ${issueId} SET invoice=sales_invoice:jpy, lines=[
      {line_key:'first', source:stock_out:c, billed_quantity:1dec, unit_price:100.6dec,
        tax_components:[{tax_key:'rate', tax_claim_account:claim_account:levy_jpy, rule_version:sales_tax_rule_version:rate_jpy}],
        compound_tax_components:[{tax_key:'extra', tax_claim_account:claim_account:extra_jpy,
          rule_version:sales_tax_rule_version:extra_jpy, predecessor_tax_key:'rate'}]},
      {line_key:'second', source:stock_out:b, billed_quantity:2dec, unit_price:50.6dec,
        tax_components:[{tax_key:'rate', tax_claim_account:claim_account:levy_jpy, rule_version:sales_tax_rule_version:rate_jpy}]}
    ];`);
    assert(data.base.every(row => row.currency === 'currency:jpy'));
    assert.equal(number(data.invoices.find(row => row.id === 'sales_invoice:jpy').z_outstanding.summary.measures.outstanding.sum), 228);
    await mutate(patch([replace('/issued_at', "d'2026-08-01'")]));
    console.log('PASS foreign-tenant/date/quantity rollback and delivery/invoice/currency moves');

    const rateInput = `{tax_key:'rate', tax_claim_account:claim_account:levy_jpy,
      rule_version:sales_tax_rule_version:rate_jpy}`;
    const modeLines = lineTax => `[
      {line_key:'mode_a', source:stock_out:c, billed_quantity:1dec, unit_price:100.6dec,
        tax_components:${lineTax ? `[${rateInput}]` : '[]'}, compound_tax_components:[]},
      {line_key:'mode_b', source:stock_out:b, billed_quantity:2dec, unit_price:50.6dec,
        tax_components:${lineTax ? `[${rateInput}]` : '[]'}, compound_tax_components:[]}
    ]`;
    const invoiceRateInput = `[${rateInput}]`;
    const taxModes = [
      { name: 'empty', lineTax: false, invoiceTax: false, outstanding: 202 },
      { name: 'line-only', lineTax: true, invoiceTax: false, outstanding: 222 },
      { name: 'invoice-only', lineTax: false, invoiceTax: true, outstanding: 222 },
      { name: 'both', lineTax: true, invoiceTax: true, outstanding: 242 },
    ];
    for (const mode of taxModes) {
      data = await mutate(`UPDATE ONLY ${issueId} SET lines=${modeLines(mode.lineTax)},
        tax_components=${mode.invoiceTax ? invoiceRateInput : '[]'};`);
      const lineTaxTotal = data.base.reduce((sum, row) => sum + number(row.amount), 0);
      const invoiceTaxTotal = data.invoiceTaxes.reduce((sum, row) => sum + number(row.amount), 0);
      assert.equal(data.compound.length, 0, `${mode.name} mode has no compound inputs`);
      assert.equal(data.base.length, mode.lineTax ? 2 : 0, `${mode.name} delivery output count`);
      assert.equal(data.invoiceTaxes.length, mode.invoiceTax ? 1 : 0, `${mode.name} legacy invoice output count`);
      assert.equal(lineTaxTotal, mode.lineTax ? 20 : 0, `${mode.name} delivery tax total`);
      assert.equal(invoiceTaxTotal, mode.invoiceTax ? 20 : 0, `${mode.name} invoice-wide tax total`);
      assert.equal(number(data.invoices.find(row => row.id === 'sales_invoice:jpy')
        .z_outstanding.summary.measures.outstanding.sum), mode.outstanding, `${mode.name} invoice outstanding`);
    }
    console.log('PASS empty, line-only, invoice-only and additive combined tax modes');

    data = await mutate(`CREATE ONLY cash_in:delivery_settlement SET owned_by=rebase_tenant:default,
      from_party=organization:customer, to_account=treasury_account:settlement,
      amount=242dec, effective_at=d'2026-08-01';`);
    data = await mutate(`CREATE ONLY sales_invoice_cash_allocation:delivery_settlement SET owned_by=rebase_tenant:default,
      source=cash_in:delivery_settlement, target=${issueId}, amount=242dec, effective_at=d'2026-08-01';`);
    const settlement = data.allocations.find(row => row.id === 'sales_invoice_cash_allocation:delivery_settlement');
    const issuedAt = data.issues.find(row => row.id === issueId).issued_at;
    assert.equal(new Date(settlement.effective_at).valueOf(), new Date(issuedAt).valueOf(),
      'settlement may be effective at the exact issue timestamp');
    assert.equal(new Date(settlement.source_at).valueOf(), new Date(issuedAt).valueOf(),
      'settlement also matches the cash receipt timestamp');
    assert.equal(new Date(settlement.target_at).valueOf(), new Date(issuedAt).valueOf(),
      'allocation target timestamp matches the issue');
    assert.equal(number(data.invoices.find(row => row.id === 'sales_invoice:jpy')
      .z_outstanding.summary.measures.outstanding.sum ?? 0), 0, 'same-time allocation settles the additive total');
    assert.equal(number(data.claims.find(row => row.id === 'claim_account:customer_jpy')
      .z_history.summary.measures.receivable.sum ?? 0), 0, 'same-time allocation settles the customer claim');
    assert.equal(number(data.cashins.find(row => row.id === 'cash_in:delivery_settlement')
      .z_allocations.summary.measures.available.sum), 0, 'settlement consumes the full cash receipt');
    console.log('PASS exact-issue-time settlement of invoice and customer claim');
    await mutate('DELETE ONLY sales_invoice_cash_allocation:delivery_settlement;');
    data = await mutate('DELETE ONLY cash_in:delivery_settlement;');
    assert.equal(data.allocations.length, 0);
    assert.equal(data.cashins.length, 0);

    const before = await snapshot(q);
    await applySchema(q, compiled.bundle);
    assert.deepEqual(await snapshot(q), before, 'populated schema reapplication retains sources, outputs and audit');
    const tax = before.base[0];
    for (const sql of [
      `CREATE sales_delivery_tax:forged SET owned_by=rebase_tenant:default, line=${tax.line}, tax_key='forged', entered_amount=1dec, tax_claim_account=claim_account:levy_jpy;`,
      `UPDATE ${tax.id} SET entered_amount=999dec;`, `DELETE ${tax.id};`,
    ]) {
      const before = await snapshot(q);
      try { await writer(sql); } catch (error) { assert.match(String(error), /permission|not allowed/i); }
      assert.deepEqual(await snapshot(q), before, 'record user cannot mutate managed delivery taxes directly');
    }
    const visible = await writer(`SELECT * FROM ONLY ${issueId};`);
    assert.equal(visible.lines[0].source, 'stock_out:c', 'public source projection retains delivery provenance');
    assert.equal(await q("RETURN fn::accounting::delivery_tax_role('base','a:b','c') = fn::accounting::delivery_tax_role('base','a','b:c');"), false);
    await mutate(patch([replace('/lines', `[{line_key:'second', source:stock_out:b, billed_quantity:2dec, unit_price:50.6dec,
      tax_components:[{tax_key:'rate', tax_claim_account:claim_account:levy_jpy, rule_version:sales_tax_rule_version:rate_jpy}]}]`)]));
    await mutate(`DELETE ONLY ${issueId};`, writer);
    data = await snapshot(q);
    assert.equal(data.issues.length, 0, 'the authenticated source owner deletes the issue');
    assert.equal(data.base.length + data.compound.length + data.invoiceTaxes.length + data.lines.length, 0);
    console.log(`PASS delivery taxes: ${mutations} mutation checkpoints, ${rejections} full rollback snapshots, source/currency moves, four-root topology oracle, native managed-write denial and dependent-first cleanup`);
  } finally { await server.close(); }
}

if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = { main };

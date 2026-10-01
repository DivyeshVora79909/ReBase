'use strict';
const assert = require('node:assert/strict');
const { compareKey } = require('./harness');
const { verify, equal, scan, identity } = require('./oracle');
const money = [
  'payment',
  'settlement',
  'tax_remittance',
  'tax_recovery',
  'money_adjustment',
  'money_refund',
  'money_charge',
  'money_parent_charge',
  'asset_allocation',
  'asset_parent_allocation',
];
const delivery = [
  'delivery',
  'delivery_adjustment',
  'delivery_return',
  'delivery_charge',
  'delivery_parent_charge',
  'delivery_charge_adjustment',
];
const tax = ['tax_assessment', 'tax_adjustment'];
const facts = [...money, ...delivery, ...tax];
const tables = [
  'organization',
  'currency',
  'currency_exchange',
  'operating_unit',
  'misc_inventory_node',
  'item',
  'service',
  'treasury_account',
  'misc_account',
  'tax_asset',
  'tax_receivable',
  'tax_payable',
  'money_account',
  'stock_account',
  'invoice',
  'adjustment_note',
  'calculation_rule',
  ...facts,
];
const type = (r) => (typeof r === 'string' ? r : r.id).split(':')[0];
async function snapshot(q) {
  return q(
    `RETURN array::concat(${tables.map((t) => `(SELECT * FROM ${t})`).join(',')});`,
  );
}
const clean = (o) =>
  Object.fromEntries(
    Object.entries(o).filter(([, v]) => v !== undefined && v !== null),
  );

// Reconstruct only from authoritative inputs. This scan deliberately knows no AVL
// algorithm and never trusts stored contexts, ancestor references, or memberships.
function inspect(rows) {
  const byId = new Map(rows.map((r) => [r.id, r])),
    get = (id) => byId.get(id);
  const entries = [],
    histories = new Map(),
    contexts = new Map();
  const org = (endpoint) =>
    type(endpoint) === 'organization'
      ? endpoint
      : get(endpoint)?.a_organization;
  const party = (account) => {
    const a = get(account),
      entity = get(a.a_entity),
      o = org(entity.id);
    return type(entity) === 'organization'
      ? a.id
      : rows.find(
          (r) =>
            type(r) === 'money_account' &&
            r.a_entity === o &&
            r.a_currency === a.a_currency,
        )?.id;
  };
  const invoice = (id) => {
    const r = get(id);
    return (
      r && {
        issuer: r.a_issuer,
        recipient: r.a_recipient,
        currency: get(r.a_issuer).a_currency,
        issued_at: r.a_effective_at,
      }
    );
  };
  const total = (id, metric, key) =>
    scan(
      (histories.get(`${id}/z_history`) || []).filter(
        (e) => compareKey(e.key, key) < 0,
      ),
    ).measures[metric]?.sum || 0;
  const round = (n, currency) =>
    (Math.sign(n) *
      Math.round(
        (Math.abs(n) + Number.EPSILON) *
          10 ** Number(get(currency).a_precision),
      )) /
    10 ** Number(get(currency).a_precision);
  const convert = (n, currency, exchange) =>
    round(n * Number(get(exchange)?.a_rate ?? 1), currency);
  function rule(row, basis, currency) {
    const r = get(row.a_rule),
      raw = Number(r.a_fixed) + Number(r.a_rate) * basis;
    const amount = round(
      r.a_cap == null ? raw : Math.min(raw, Number(r.a_cap)),
      currency,
    );
    return { basis, amount };
  }
  function baseMoney(
    row,
    from = row.a_from,
    to = row.a_to,
    amount = Number(row.a_amount),
    credit,
    exchange = row.a_exchange,
  ) {
    const fc = get(from).a_currency,
      tc = get(to).a_currency;
    return {
      from,
      to,
      from_currency: fc,
      to_currency: tc,
      from_party: party(from),
      to_party: party(to),
      origin: row.id,
      origin_at: row.a_effective_at,
      from_amount: amount,
      to_amount: credit ?? convert(amount, tc, exchange),
      exchange,
      exchange_at: get(exchange)?.a_effective_at,
      invoice_leg: 0,
      invoice_amount: 0,
      claim_kind: '',
      claim_amount: 0,
      parent_kind: '',
    };
  }
  function context(row) {
    if (contexts.has(row.id)) return contexts.get(row.id);
    const t = type(row);
    let c;
    if (
      ['payment', 'settlement', 'tax_remittance', 'tax_recovery'].includes(t)
    ) {
      c = baseMoney(row);
      if (t === 'settlement') {
        const v = invoice(row.a_invoice),
          leg = c.to_currency === v.currency ? 2 : 1;
        Object.assign(c, {
          invoice: row.a_invoice,
          invoice_at: v.issued_at,
          invoice_currency: v.currency,
          issuer: v.issuer,
          recipient: v.recipient,
          invoice_leg: leg,
          invoice_amount: leg === 1 ? c.from_amount : c.to_amount,
        });
      }
      if (t.startsWith('tax_'))
        Object.assign(c, {
          claim: row.a_tax_account,
          claim_party: party(row.a_tax_account),
          claim_kind: t === 'tax_remittance' ? 'payable' : 'receivable',
          claim_amount: -c.from_amount,
        });
    } else if (['money_adjustment', 'money_refund'].includes(t)) {
      const b = context(get(row.a_original)),
        amount =
          t === 'money_adjustment'
            ? Number(row.a_from_delta)
            : -Number(row.a_amount);
      const exchange = row.a_exchange ?? b.exchange,
        credit =
          convert(amount, b.to_currency, exchange) + Number(row.a_to_delta);
      c = {
        ...b,
        from_amount: amount,
        to_amount: credit,
        exchange,
        exchange_at: get(exchange)?.a_effective_at,
        invoice_amount:
          b.invoice_leg === 1 ? amount : b.invoice_leg === 2 ? credit : 0,
        claim_amount: b.claim ? -amount : 0,
      };
    } else if (money.includes(t)) {
      const b = context(get(row.a_original)),
        allocation = t.startsWith('asset_'),
        live = !t.includes('parent');
      const basis = live
        ? total(b.origin, allocation ? 'to_amount' : 'basis', [
            row.a_effective_at,
            row.id,
            'z_parent',
          ])
        : allocation
          ? b.to_amount
          : b.from_amount;
      const r = rule(row, basis, allocation ? b.to_currency : b.from_currency);
      c = {
        ...baseMoney(
          row,
          allocation ? b.to : b.from,
          row.a_to,
          r.amount,
          r.amount,
          null,
        ),
        parent: b.origin,
        parent_at: b.origin_at,
        parent_kind: allocation ? 'allocation' : 'charge',
        parent_from_currency: b.from_currency,
        parent_to_currency: b.to_currency,
      };
      equal(row.z10_basis, r.basis, `basis ${row.id}`);
      equal(row.z11_amount, r.amount, `rule ${row.id}`);
    } else if (t === 'delivery') {
      const a = get(row.a_from),
        b = get(row.a_to),
        v = invoice(row.a_invoice);
      c = {
        from: a.id,
        to: b.id,
        subject: a.a_subject,
        from_unit:
          type(a.a_endpoint) === 'operating_unit' ? a.a_endpoint : undefined,
        to_unit:
          type(b.a_endpoint) === 'operating_unit' ? b.a_endpoint : undefined,
        quantity: Number(row.a_quantity),
        amount: Number(row.a_value),
        currency: row.a_currency,
        origin: row.id,
        origin_at: row.a_effective_at,
        invoice: row.a_invoice,
        invoice_at: v?.issued_at,
        issuer: v?.issuer,
        recipient: v?.recipient,
        tax_kind: '',
        capacity_amount: 0,
      };
    } else if (['delivery_charge', 'delivery_parent_charge'].includes(t)) {
      const b = context(get(row.a_original));
      const basis =
        t === 'delivery_charge'
          ? total(b.origin, 'amount', [
              row.a_effective_at,
              row.id,
              'z_original',
            ])
          : b.amount;
      const r = rule(row, basis, b.currency),
        account = get(row.a_tax_account);
      c = {
        ...b,
        quantity: 0,
        amount: r.amount,
        tax_account: account.id,
        tax_party: party(account.id),
        tax_kind:
          type(account.a_entity) === 'tax_receivable'
            ? 'receivable'
            : 'payable',
        capacity: row.id,
        capacity_at: row.a_effective_at,
        capacity_amount: r.amount,
      };
      equal(row.z10_basis, r.basis, `basis ${row.id}`);
      equal(row.z11_amount, r.amount, `rule ${row.id}`);
    } else if (delivery.includes(t)) {
      const b = context(get(row.a_original || row.a_charge)),
        quantity =
          t === 'delivery_return'
            ? -Number(row.a_quantity)
            : Number(row.a_quantity_delta || 0);
      const amount = Number(row.a_value_delta ?? row.a_delta ?? 0);
      c = { ...b, quantity, amount, capacity_amount: b.capacity ? amount : 0 };
    } else if (t === 'tax_assessment') {
      const a = get(row.a_tax_account);
      c = {
        origin: row.id,
        origin_at: row.a_effective_at,
        account: a.id,
        party: party(a.id),
        kind: type(a.a_entity) === 'tax_receivable' ? 'receivable' : 'payable',
        currency: a.a_currency,
        amount: Number(row.a_amount),
      };
    } else c = { ...context(get(row.a_original)), amount: Number(row.a_delta) };
    contexts.set(row.id, c);
    return c;
  }
  function projections(row, c) {
    const out = [];
    function add(
      slot,
      owner,
      root,
      measures,
      tags = {},
      spans = {},
      dependent = false,
      at = row.a_effective_at,
    ) {
      if (!owner) return;
      out.push({
        link: { rid: row.id, slot },
        owner: { rid: owner, slot: root },
        key: [at, row.id, slot],
        measures,
        tags: clean(tags),
        spans,
        dependent,
      });
    }
    const t = type(row);
    if (money.includes(t)) {
      add(
        'z_from',
        c.from,
        'z_book',
        { asset: -c.from_amount, outflow: c.from_amount },
        { currency: c.from_currency },
      );
      add(
        'z_to',
        c.to,
        'z_book',
        { asset: c.to_amount, inflow: c.to_amount },
        { currency: c.to_currency },
      );
      if (c.from_party !== c.from)
        add(
          'z_from_party',
          c.from_party,
          'z_book',
          { asset: -c.from_amount, outflow: c.from_amount },
          { currency: c.from_currency },
        );
      if (c.to_party !== c.to)
        add(
          'z_to_party',
          c.to_party,
          'z_book',
          { asset: c.to_amount, inflow: c.to_amount },
          { currency: c.to_currency },
        );
      add(
        'z_original',
        c.origin,
        'z_history',
        {
          from_amount: c.from_amount,
          to_amount: c.to_amount,
          basis: c.from_amount,
        },
        { from_currency: c.from_currency, to_currency: c.to_currency },
      );
      add(
        'z_parent',
        c.parent,
        'z_history',
        c.parent_kind === 'allocation'
          ? { to_amount: -c.from_amount }
          : { basis: c.from_amount },
        {
          from_currency: c.parent_from_currency,
          to_currency: c.parent_to_currency,
        },
        {},
        ['money_charge', 'asset_allocation'].includes(t),
      );
      add(
        'z_invoice',
        c.invoice,
        'z_book',
        { amount: -c.invoice_amount, settled: c.invoice_amount },
        {
          currency: c.invoice_currency,
          issuer: c.issuer,
          recipient: c.recipient,
        },
        { settlement: row.a_effective_at },
      );
      add(
        'z_issuer',
        c.issuer,
        'z_book',
        { receivable: -c.invoice_amount, settled_in: c.invoice_amount },
        { currency: c.invoice_currency },
      );
      add(
        'z_recipient',
        c.recipient,
        'z_book',
        { payable: -c.invoice_amount, settled_out: c.invoice_amount },
        { currency: c.invoice_currency },
      );
      add(
        'z_claim',
        c.claim,
        'z_book',
        { [c.claim_kind]: c.claim_amount },
        { currency: c.from_currency },
      );
      add(
        'z_claim_party',
        c.claim_party,
        'z_book',
        { [c.claim_kind]: c.claim_amount },
        { currency: c.from_currency },
      );
      add(
        'z_exchange',
        c.exchange,
        'z_usage',
        { source: c.from_amount, target: c.to_amount },
        { from_currency: c.from_currency, to_currency: c.to_currency },
      );
      add(
        'z_note',
        row.a_note,
        'z_book',
        { amount: c.from_amount },
        { currency: c.from_currency, invoice: c.invoice ?? false },
      );
    } else if (delivery.includes(t)) {
      if (c.quantity !== 0) {
        add(
          'z_from',
          c.from,
          'z_book',
          { quantity: -c.quantity },
          { subject: c.subject },
        );
        add(
          'z_to',
          c.to,
          'z_book',
          { quantity: c.quantity },
          { subject: c.subject },
        );
        add('z_from_unit', c.from_unit, 'z_activity', {
          [c.quantity > 0 ? 'outbound' : 'inbound']: 1,
        });
        add('z_to_unit', c.to_unit, 'z_activity', {
          [c.quantity > 0 ? 'inbound' : 'outbound']: 1,
        });
      }
      const at =
        c.invoice_at && compareKey([c.invoice_at], [row.a_effective_at]) > 0
          ? c.invoice_at
          : row.a_effective_at;
      add(
        'z_original',
        c.origin,
        'z_history',
        { quantity: c.quantity, amount: c.amount },
        { subject: c.subject, currency: c.currency },
        {},
        t === 'delivery_charge',
      );
      const line = [
        'delivery',
        'delivery_charge',
        'delivery_parent_charge',
      ].includes(t);
      add(
        'z_invoice',
        c.invoice,
        'z_book',
        { amount: c.amount, billed: c.amount },
        { currency: c.currency, issuer: c.issuer, recipient: c.recipient },
        { [line ? 'line' : 'amendment']: row.a_effective_at },
      );
      add(
        'z_issuer',
        c.issuer,
        'z_book',
        { receivable: c.amount, billed_out: c.amount },
        { currency: c.currency },
        {},
        false,
        at,
      );
      add(
        'z_recipient',
        c.recipient,
        'z_book',
        { payable: c.amount, billed_in: c.amount },
        { currency: c.currency },
        {},
        false,
        at,
      );
      add(
        'z_tax',
        c.tax_account,
        'z_book',
        { [c.tax_kind]: c.amount },
        { currency: c.currency },
        {},
        false,
        at,
      );
      add(
        'z_tax_party',
        c.tax_party,
        'z_book',
        { [c.tax_kind]: c.amount },
        { currency: c.currency },
        {},
        false,
        at,
      );
      add(
        'z_capacity',
        c.capacity,
        'z_history',
        { amount: c.capacity_amount },
        { currency: c.currency },
      );
      add(
        'z_note',
        row.a_note,
        'z_book',
        { amount: c.amount },
        { currency: c.currency, invoice: c.invoice ?? false },
      );
    } else {
      add(
        'z_claim',
        c.account,
        'z_book',
        { [c.kind]: c.amount },
        { currency: c.currency },
      );
      add(
        'z_party',
        c.party,
        'z_book',
        { [c.kind]: c.amount },
        { currency: c.currency },
      );
      add(
        'z_original',
        c.origin,
        'z_history',
        { amount: c.amount },
        { currency: c.currency },
      );
      add(
        'z_note',
        row.a_note,
        'z_book',
        { amount: c.amount },
        { currency: c.currency, invoice: false },
      );
    }
    // Independently net endpoint contributions at each owner, retaining one count.
    const grouped = new Map();
    for (const e of out) {
      const key = identity(e.owner),
        existing = grouped.get(key);
      if (!existing) {
        grouped.set(key, e);
        continue;
      }
      assert.equal(existing.key[0], e.key[0]);
      for (const [k, v] of Object.entries(e.measures))
        existing.measures[k] = (existing.measures[k] || 0) + v;
      for (const [k, v] of Object.entries(e.tags)) {
        if (k in existing.tags) assert.equal(existing.tags[k], v);
        existing.tags[k] = v;
      }
      for (const [k, v] of Object.entries(e.spans)) {
        if (k in existing.spans) assert.equal(existing.spans[k], v);
        existing.spans[k] = v;
      }
      existing.dependent ||= e.dependent;
    }
    return [...grouped.values()];
  }
  for (const row of rows) {
    if (type(row) === 'money_account')
      equal(
        row.z10_party,
        party(row.id) === row.id ? undefined : party(row.id),
        `party ${row.id}`,
      );
    if (type(row) === 'stock_account')
      equal(row.z10_organization, org(row.a_endpoint), `stock party ${row.id}`);
    if (type(row) === 'invoice')
      equal(row.z20_ctx, clean(invoice(row.id)), `invoice ${row.id}`);
  }
  for (const row of rows
    .filter((r) => facts.includes(type(r)))
    .sort((a, b) =>
      compareKey([a.a_effective_at, a.id], [b.a_effective_at, b.id]),
    )) {
    contexts.delete(row.id);
    const c = context(row);
    equal(row.z20_ctx, clean(c), `context ${row.id}`);
    if (
      [
        'payment',
        'settlement',
        'tax_remittance',
        'tax_recovery',
        'money_adjustment',
        'money_refund',
      ].includes(type(row))
    )
      equal(row.z10_credit, c.to_amount, `conversion ${row.id}`);
    for (const entry of projections(row, c)) {
      entries.push(entry);
      const key = identity(entry.owner);
      if (!histories.has(key)) histories.set(key, []);
      histories.get(key).push(entry);
    }
  }
  return verify(rows, rows, entries);
}
module.exports = { facts, tables, snapshot, inspect };

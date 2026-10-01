#!/usr/bin/env node
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs'),
  os = require('node:os'),
  path = require('node:path');
const { start, client, applySchema } = require('./temporal-tree/harness');
const { compileFromArgs } = require('./compiler/cli');
const { snapshot, inspect } = require('./temporal-tree/accounts-oracle');
const { equal, scan } = require('./temporal-tree/oracle');
const root = 'rebase_group:root',
  date = (day) => new Date(Date.UTC(2026, 0, 1 + day)).toISOString();
async function main({ writeOnly = process.argv.includes('--write-only') } = {}) {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'rebase-entities-'));
  const compiled = compileFromArgs({
    projectDir: 'designs/all-in-one',
    frameworkDir: 'framework',
    outputDir: output,
  });
  const server = await start(),
    q = client(server.url);
  async function create(id, day, fields) {
    await q(
      `CREATE ${id} SET owned_by=${root},a_effective_at=d'${date(day)}',${fields};`,
    );
  }
  async function check() {
    return inspect(await snapshot(q));
  }
  async function reject(sql, pattern) {
    const before = await snapshot(q);
    await assert.rejects(q(sql), pattern);
    assert.deepEqual(
      await snapshot(q),
      before,
      'failed edit must roll back facts, shadows, all roots and timestamps',
    );
  }
  async function value(id, measure) {
    return Number(
      await q(`RETURN ${id}.z_book.summary.measures.${measure}.sum ?? 0dec;`),
    );
  }
  try {
    await q(
      'DEFINE NAMESPACE temporal_probe; USE NS temporal_probe; DEFINE DATABASE fixture;',
    );
    await applySchema(q, compiled.bundle);
    for (const [id, code] of [
      ['inr', 'INR'],
      ['usd', 'USD'],
    ])
      await q(
        `CREATE currency:${id} SET owned_by=${root},a_code='${code}',a_name='${code}';`,
      );
    for (const name of [
      'company',
      'customer',
      'vendor',
      'authority',
      'other',
    ]) {
      await q(`CREATE organization:${name} SET owned_by=${root},a_name='${name}';
    CREATE money_account:${name} SET owned_by=${root},a_entity=organization:${name},a_currency=currency:inr,a_nonnegative=false;`);
    }
    for (const name of ['company', 'vendor'])
      await q(
        `CREATE money_account:${name}_usd SET owned_by=${root},a_entity=organization:${name},a_currency=currency:usd,a_nonnegative=false;`,
      );
    for (const name of ['bank', 'other_bank'])
      await q(`CREATE treasury_account:${name} SET owned_by=${root},a_name='${name}',a_organization=organization:company;
    CREATE money_account:${name} SET owned_by=${root},a_entity=treasury_account:${name},a_currency=currency:inr;`);
    await q(`CREATE money_account:bank_usd SET owned_by=${root},a_entity=treasury_account:bank,a_currency=currency:usd;
   CREATE misc_account:funding SET owned_by=${root},a_name='Funding source';
   CREATE money_account:funding SET owned_by=${root},a_entity=misc_account:funding,a_currency=currency:inr,a_nonnegative=false;`);
    for (const [kind, name] of [
      ['asset', 'direct'],
      ['payable', 'output'],
      ['receivable', 'input'],
    ])
      await q(`CREATE tax_${kind}:${name} SET owned_by=${root},a_name='${name}',a_organization=organization:company;
    CREATE money_account:${name} SET owned_by=${root},a_entity=tax_${kind}:${name},a_currency=currency:inr;`);
    for (const name of ['warehouse', 'outlet', 'customer'])
      await q(
        `CREATE operating_unit:${name} SET owned_by=${root},a_name='${name}',a_organization=organization:${name === 'customer' ? 'customer' : 'company'};`,
      );
    await q(`CREATE misc_inventory_node:source SET owned_by=${root},a_name='Stock source';
   CREATE item:widget SET owned_by=${root},a_name='Widget';
   CREATE service:consulting SET owned_by=${root},a_name='Consulting',a_unit='hour';
   CREATE calculation_rule:rate SET owned_by=${root},a_name='10 percent',a_rate=0.1dec;
   CREATE calculation_rule:cap SET owned_by=${root},a_name='Capped fee',a_rate=0.1dec,a_cap=5dec;`);
    for (const [name, endpoint, subject, nonnegative] of [
      ['source', 'misc_inventory_node:source', 'item:widget', false],
      ['warehouse', 'operating_unit:warehouse', 'item:widget', true],
      ['outlet', 'operating_unit:outlet', 'item:widget', true],
      ['customer', 'operating_unit:customer', 'item:widget', true],
      ['vendor', 'organization:vendor', 'item:widget', false],
      ['other', 'organization:other', 'item:widget', false],
      [
        'service_source',
        'misc_inventory_node:source',
        'service:consulting',
        false,
      ],
      ['service_unit', 'operating_unit:warehouse', 'service:consulting', true],
      [
        'service_customer',
        'operating_unit:customer',
        'service:consulting',
        true,
      ],
    ])
      await q(
        `CREATE stock_account:${name} SET owned_by=${root},a_endpoint=${endpoint},a_subject=${subject},a_nonnegative=${nonnegative};`,
      );
    await create(
      'currency_exchange:quote',
      -20,
      'a_from=currency:inr,a_to=currency:usd,a_rate=0.02dec',
    );
    await create(
      'currency_exchange:refund',
      -20,
      'a_from=currency:inr,a_to=currency:usd,a_rate=0.01dec',
    );
    await create(
      'adjustment_note:money',
      90,
      "a_reason='Corrections and reversals',a_currency=currency:inr",
    );
    await create(
      'adjustment_note:usd',
      90,
      "a_reason='Dollar corrections',a_currency=currency:usd",
    );
    await reject(
      `CREATE money_account:duplicate SET owned_by=${root},a_entity=treasury_account:bank,a_currency=currency:inr;`,
      /already contains|unique|index/i,
    );
    await create(
      'payment:fund',
      -10,
      'a_from=money_account:funding,a_to=money_account:bank,a_amount=1000dec',
    );
    await create(
      'payment:spend',
      0,
      'a_from=money_account:bank,a_to=money_account:vendor,a_amount=100dec',
    );
    await create(
      'money_adjustment:spend',
      2,
      'a_original=payment:spend,a_note=adjustment_note:money,a_from_delta=20dec',
    );
    await create(
      'money_refund:spend',
      4,
      'a_original=payment:spend,a_note=adjustment_note:money,a_amount=35dec',
    );
    await create(
      'money_charge:fee',
      3,
      'a_original=payment:spend,a_rule=calculation_rule:rate,a_to=money_account:authority',
    );
    await create(
      'money_parent_charge:cap',
      5,
      'a_original=payment:spend,a_rule=calculation_rule:cap,a_to=money_account:authority',
    );
    await create(
      'money_adjustment:fee',
      6,
      'a_original=money_charge:fee,a_note=adjustment_note:money,a_from_delta=-1dec',
    );
    await check();
    equal(
      await q(
        'RETURN payment:spend.z_history.summary.measures.from_amount.sum;',
      ),
      85,
    );
    equal(
      await q('RETURN payment:spend.z_history.summary.measures.basis.sum;'),
      101,
    );
    await reject(
      `CREATE money_refund:bad SET owned_by=${root},a_original=payment:spend,a_note=adjustment_note:money,a_amount=200dec,a_effective_at=d'${date(7)}';`,
      /CAPACITY/,
    );
    await reject(
      `CREATE money_refund:wrong_direction SET owned_by=${root},a_original=payment:spend,a_note=adjustment_note:money,a_amount=1dec,a_to_delta=2dec,a_effective_at=d'${date(7)}';`,
      /REFUND_DIRECTION/,
    );
    await reject(
      `CREATE money_adjustment:early SET owned_by=${root},a_original=payment:spend,a_note=adjustment_note:money,a_from_delta=10dec,a_effective_at=d'${date(-1)}';`,
      /CHILD_BEFORE_ORIGINAL/,
    );
    await reject(
      `CREATE payment:no_fx SET owned_by=${root},a_from=money_account:bank,a_to=money_account:vendor_usd,a_amount=100dec,a_effective_at=d'${date(0)}';`,
      /EXCHANGE_REQUIRED/,
    );
    await create(
      'payment:fx',
      0,
      'a_from=money_account:bank,a_to=money_account:vendor_usd,a_amount=150dec,a_exchange=currency_exchange:quote',
    );
    await create(
      'money_adjustment:fx',
      2,
      'a_original=payment:fx,a_note=adjustment_note:money,a_from_delta=10dec,a_to_delta=0.1dec',
    );
    await reject(
      `CREATE money_refund:fx_bad SET owned_by=${root},a_original=payment:fx,a_note=adjustment_note:money,a_amount=100dec,a_to_delta=-2.5dec,a_effective_at=d'${date(3)}';`,
      /CAPACITY/,
    );
    await create(
      'money_refund:fx',
      3,
      'a_original=payment:fx,a_note=adjustment_note:money,a_amount=100dec,a_exchange=currency_exchange:refund',
    );
    await create(
      'money_adjustment:target_only',
      4,
      'a_original=payment:fx,a_note=adjustment_note:money,a_to_delta=-0.2dec',
    );
    await q('UPDATE currency_exchange:quote SET a_rate=0.025dec;');
    await check();
    equal(await q('RETURN money_refund:fx.z10_credit;'), -1);
    await reject(
      `UPDATE currency_exchange:quote SET a_effective_at=d'${date(1)}';`,
      /EXCHANGE_AFTER_USAGE/,
    );
    await create(
      'payment:same',
      1,
      'a_from=money_account:bank,a_to=money_account:bank,a_amount=2000dec',
    );
    assert.equal(await q('RETURN payment:same.z_to;'), null);
    await create(
      'payment:internal_fx',
      7,
      'a_from=money_account:bank,a_to=money_account:bank_usd,a_amount=40dec,a_exchange=currency_exchange:quote',
    );
    await create(
      'payment:other_fund',
      -10,
      'a_from=money_account:funding,a_to=money_account:other_bank,a_amount=1000dec',
    );
    await q('UPDATE payment:spend SET a_from=money_account:other_bank;');
    await check();
    await q('UPDATE payment:spend SET a_from=money_account:bank;');
    await check();
    await reject(
      'UPDATE payment:fund SET a_amount=1dec;',
      /NEGATIVE_ASSET_HISTORY/,
    );
    await reject(
      `CREATE money_adjustment:no_note SET owned_by=${root},a_original=payment:spend,a_from_delta=1dec,a_effective_at=d'${date(8)}';`,
      /a_note|record/i,
    );
    await reject(
      `CREATE money_adjustment:wrong_note SET owned_by=${root},a_original=payment:spend,a_note=adjustment_note:usd,a_from_delta=1dec,a_effective_at=d'${date(8)}';`,
      /NOTE_CURRENCY/,
    );
    console.log(
      'PASS entity/currency dimensions, FX quote reactivity, independent refund legs, target-only corrections, shared-owner coalescing and atomic solvency',
    );

    await create(
      'payment:income',
      7,
      'a_from=money_account:customer,a_to=money_account:bank,a_amount=100dec',
    );
    await create(
      'asset_allocation:withheld',
      8,
      'a_original=payment:income,a_rule=calculation_rule:rate,a_to=money_account:direct',
    );
    await create(
      'payment:recovery',
      9,
      'a_from=money_account:direct,a_to=money_account:bank,a_amount=2dec',
    );
    equal(
      await q(
        'RETURN payment:income.z_history.summary.measures.to_amount.sum;',
      ),
      90,
    );
    await reject(
      `CREATE money_refund:allocated SET owned_by=${root},a_original=payment:income,a_note=adjustment_note:money,a_amount=91dec,a_effective_at=d'${date(10)}';`,
      /CAPACITY/,
    );
    await create(
      'money_refund:allocation',
      10,
      'a_original=asset_allocation:withheld,a_note=adjustment_note:money,a_amount=3dec',
    );
    equal(
      await q(
        'RETURN payment:income.z_history.summary.measures.to_amount.sum;',
      ),
      93,
    );
    await check();
    console.log(
      'PASS direct-tax asset allocation, accountable destination, independent recovery and linked reversal capacity',
    );

    await create(
      'delivery:stock',
      -5,
      'a_from=stock_account:source,a_to=stock_account:warehouse,a_quantity=50dec,a_value=500dec,a_currency=currency:inr',
    );
    await create(
      'invoice:sale',
      10,
      'a_issuer=money_account:company,a_recipient=money_account:customer',
    );
    await create(
      'invoice:purchase',
      10,
      'a_issuer=money_account:vendor,a_recipient=money_account:company',
    );
    await create(
      'invoice:other',
      12,
      'a_issuer=money_account:company,a_recipient=money_account:customer',
    );
    await create(
      'adjustment_note:sale',
      90,
      "a_reason='Sale correction',a_currency=currency:inr,a_invoice=invoice:sale",
    );
    await create(
      'delivery:purchase',
      -2,
      'a_from=stock_account:vendor,a_to=stock_account:warehouse,a_quantity=5dec,a_value=50dec,a_currency=currency:inr,a_invoice=invoice:purchase',
    );
    await create(
      'delivery_parent_charge:input',
      -1,
      'a_original=delivery:purchase,a_rule=calculation_rule:rate,a_tax_account=money_account:input',
    );
    await create(
      'delivery:sale',
      0,
      'a_from=stock_account:warehouse,a_to=stock_account:customer,a_quantity=10dec,a_value=100dec,a_currency=currency:inr,a_invoice=invoice:sale',
    );
    await create(
      'delivery_parent_charge:tax',
      1,
      'a_original=delivery:sale,a_rule=calculation_rule:rate,a_tax_account=money_account:output',
    );
    await create(
      'delivery_adjustment:sale',
      2,
      'a_original=delivery:sale,a_note=adjustment_note:sale,a_quantity_delta=2dec,a_value_delta=20dec',
    );
    await create(
      'delivery_charge:tax',
      3,
      'a_original=delivery:sale,a_rule=calculation_rule:rate,a_tax_account=money_account:output',
    );
    await create(
      'delivery_charge:cap',
      5,
      'a_original=delivery:sale,a_rule=calculation_rule:cap,a_tax_account=money_account:output',
    );
    await create(
      'delivery_charge_adjustment:tax',
      4,
      'a_charge=delivery_parent_charge:tax,a_note=adjustment_note:sale,a_delta=-2dec',
    );
    await create(
      'delivery_return:sale',
      6,
      'a_original=delivery:sale,a_note=adjustment_note:sale,a_quantity=3dec',
    );
    await check();
    equal(await value('invoice:sale', 'amount'), 146);
    equal(await value('stock_account:warehouse', 'quantity'), 46);
    equal(
      await q(
        'RETURN operating_unit:warehouse.z_activity.summary.measures.inbound.sum;',
      ),
      3,
    );
    equal(
      await q(
        'RETURN operating_unit:warehouse.z_activity.summary.measures.outbound.sum;',
      ),
      2,
    );
    equal(
      await q(
        `RETURN fn::tree::read(money_account:company,'z_book','before',[d'${date(10)}']).measures.receivable.sum ?? 0dec;`,
      ),
      0,
    );
    equal(await value('money_account:company', 'receivable'), 151); // sale + input-tax claim
    equal(await value('money_account:company', 'payable'), 81); // purchase + output-tax claim
    assert.equal(
      await q('RETURN delivery_adjustment:sale.z_note.owner.rid;'),
      'adjustment_note:sale',
    );
    assert.equal(
      await q('RETURN delivery_adjustment:sale.z_from_unit.owner.rid;'),
      'operating_unit:warehouse',
    );
    await reject(
      'UPDATE delivery:sale SET a_invoice=invoice:other;',
      /NOTE_INVOICE/,
    );
    await reject(
      `CREATE money_adjustment:unlinked_note SET owned_by=${root},a_original=payment:spend,a_note=adjustment_note:sale,a_from_delta=1dec,a_effective_at=d'${date(8)}';`,
      /NOTE_INVOICE/,
    );
    await reject(
      'UPDATE money_adjustment:spend SET a_note=adjustment_note:sale;',
      /NOTE_INVOICE/,
    );
    await reject(
      'UPDATE delivery_adjustment:sale SET a_original=delivery:stock;',
      /NOTE_INVOICE/,
    );
    // An unscoped note may group corrections; assigning an invoice must validate
    // every existing entry, including those with no invoice of their own.
    await q('UPDATE adjustment_note:sale SET a_invoice=NONE;');
    await q('UPDATE money_adjustment:spend SET a_note=adjustment_note:sale;');
    await check();
    await reject(
      'UPDATE adjustment_note:sale SET a_invoice=invoice:sale;',
      /NOTE_INVOICE/,
    );
    await q('UPDATE money_adjustment:spend SET a_note=adjustment_note:money;');
    await q('UPDATE adjustment_note:sale SET a_invoice=invoice:sale;');
    await check();
    await reject(
      `UPDATE delivery:sale SET a_effective_at=d'${date(11)}';`,
      /CHILD_BEFORE_ORIGINAL|LINE_AFTER_INVOICE/,
    );
    await reject(
      `CREATE delivery:future SET owned_by=${root},a_from=stock_account:warehouse,a_to=stock_account:customer,a_quantity=1dec,a_value=1dec,a_currency=currency:inr,a_invoice=invoice:sale,a_effective_at=d'${date(11)}';`,
      /LINE_AFTER_INVOICE/,
    );
    await reject(
      'UPDATE delivery:sale SET a_to=stock_account:other;',
      /INVOICE_DELIVERY_PARTIES/,
    );
    await reject(
      'UPDATE delivery:sale SET a_currency=currency:usd;',
      /INVOICE_CURRENCY/,
    );
    await reject(
      `CREATE delivery_return:bad SET owned_by=${root},a_original=delivery:sale,a_note=adjustment_note:sale,a_quantity=20dec,a_effective_at=d'${date(7)}';`,
      /CAPACITY|NEGATIVE_STOCK/,
    );
    await reject(
      `UPDATE adjustment_note:sale SET a_effective_at=d'${date(5)}';`,
      /CORRECTION_AFTER_NOTE/,
    );
    await create(
      'delivery:grant',
      -3,
      'a_from=stock_account:service_source,a_to=stock_account:service_unit,a_quantity=10dec,a_value=0dec,a_currency=currency:inr',
    );
    await create(
      'delivery:service',
      2,
      'a_from=stock_account:service_unit,a_to=stock_account:service_customer,a_quantity=3dec,a_value=30dec,a_currency=currency:inr',
    );
    await create(
      'delivery:internal',
      3,
      'a_from=stock_account:warehouse,a_to=stock_account:outlet,a_quantity=2dec,a_value=20dec,a_currency=currency:inr',
    );
    await check();
    console.log(
      'PASS inbound/outbound invoices, issue-time claim recognition, stock/service capacity, unit ancestry, correction-note invoice scope and live compound assessments',
    );

    await create(
      'settlement:partial',
      11,
      'a_from=money_account:customer,a_to=money_account:bank,a_amount=60dec,a_invoice=invoice:sale',
    );
    await create(
      'money_refund:partial',
      12,
      'a_original=settlement:partial,a_note=adjustment_note:sale,a_amount=10dec',
    );
    await create(
      'money_adjustment:partial',
      13,
      'a_original=settlement:partial,a_note=adjustment_note:sale,a_from_delta=5dec',
    );
    await create(
      'settlement:purchase',
      11,
      'a_from=money_account:bank,a_to=money_account:vendor,a_amount=20dec,a_invoice=invoice:purchase',
    );
    equal(await value('invoice:sale', 'amount'), 91);
    equal(await value('invoice:purchase', 'amount'), 35);
    await create(
      'tax_assessment:standalone',
      14,
      'a_tax_account=money_account:output,a_amount=20dec',
    );
    await create(
      'tax_adjustment:standalone',
      15,
      'a_original=tax_assessment:standalone,a_note=adjustment_note:money,a_delta=-2dec',
    );
    await create(
      'tax_remittance:tax',
      16,
      'a_from=money_account:bank,a_to=money_account:authority,a_amount=5dec,a_tax_account=money_account:output',
    );
    await create(
      'money_refund:remit',
      17,
      'a_original=tax_remittance:tax,a_note=adjustment_note:money,a_amount=1dec',
    );
    await create(
      'tax_assessment:credit',
      14,
      'a_tax_account=money_account:input,a_amount=10dec',
    );
    await create(
      'tax_recovery:credit',
      17,
      'a_from=money_account:authority,a_to=money_account:bank,a_amount=4dec,a_tax_account=money_account:input',
    );
    await check();
    equal(await value('money_account:output', 'payable'), 40);
    equal(await value('money_account:input', 'receivable'), 11);
    equal(await value('money_account:output', 'asset'), 0);
    await reject(
      `CREATE tax_remittance:bad SET owned_by=${root},a_from=money_account:bank,a_to=money_account:authority,a_amount=41dec,a_tax_account=money_account:output,a_effective_at=d'${date(19)}';`,
      /NEGATIVE_CLAIM_HISTORY/,
    );
    await reject(
      `CREATE payment:claim_cash SET owned_by=${root},a_from=money_account:bank,a_to=money_account:output,a_amount=1dec,a_effective_at=d'${date(19)}';`,
      /CLAIM_IS_NOT_CASH/,
    );
    await reject(
      `CREATE tax_recovery:wrong_kind SET owned_by=${root},a_from=money_account:authority,a_to=money_account:bank,a_amount=1dec,a_tax_account=money_account:output,a_effective_at=d'${date(19)}';`,
      /TAX_CLAIM_KIND/,
    );
    await reject(
      `UPDATE invoice:sale SET a_effective_at=d'${date(12)}';`,
      /SETTLEMENT_BEFORE_INVOICE/,
    );
    await reject(
      `UPDATE invoice:sale SET a_effective_at=d'${date(4)}';`,
      /LINE_AFTER_INVOICE/,
    );
    await reject(
      'UPDATE delivery:sale SET a_value=20dec;',
      /INVOICE_OVERSETTLED|NEGATIVE_CLAIM_HISTORY/,
    );
    await q('UPDATE delivery:sale SET a_value=105dec;');
    await check();
    await q(`UPDATE invoice:sale SET a_effective_at=d'${date(9)}';`);
    await check();
    await q('UPDATE calculation_rule:rate SET a_rate=0.12dec;');
    await check();
    await q('DELETE delivery_charge:cap;');
    await check();
    await reject('DELETE payment:spend;', /reference|referenced/i);
    await reject(
      'DELETE money_account:company;',
      /reference|referenced|OWNER_NOT_EMPTY/i,
    );
    const before = await snapshot(q);
    await q('UPDATE delivery:sale SET system_ping=time::now();');
    assert.equal(
      (await snapshot(q)).find((r) => r.id === 'delivery:sale').updated_at,
      before.find((r) => r.id === 'delivery:sale').updated_at,
    );
    const groups = await check(),
      sale = groups.get('invoice:sale/z_book');
    equal(
      await q(
        `RETURN fn::tree::read(invoice:sale,'z_book','range',[[d'${date(0)}'],[d'${date(7)}']]);`,
      ),
      scan(
        sale.entries.filter((e) => e.key[0] < date(7).replace('.000Z', 'Z')),
      ),
    );
    console.log(
      'PASS assets versus receivables/payables, partial settlements, standalone tax claims, remittance/recovery, mutable histories, rollback, range queries and timestamps',
    );

    if (!writeOnly) {
      await q(
        `CREATE rebase_user:actor SET name='Actor',parents=[${root}];DEFINE ACCESS accounts_probe ON DATABASE TYPE RECORD SIGNIN rebase_user:actor;`,
      );
      const response = await fetch(`${server.url}/signin`, {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ns: 'temporal_probe',
          db: 'fixture',
          ac: 'accounts_probe',
        }),
      });
      const { token } = await response.json();
      assert(token);
      const actor = client(server.url, 'fixture', token);
      await actor(
        `CREATE payment:authenticated SET owned_by=rebase_user:actor,a_from=money_account:bank,a_to=money_account:vendor,a_amount=10dec,a_effective_at=d'${date(21)}',z_history={summary:{count:999}};`,
      );
      await actor(
        `CREATE money_charge:authenticated SET owned_by=rebase_user:actor,a_original=payment:authenticated,a_rule=calculation_rule:rate,a_to=money_account:authority,a_effective_at=d'${date(22)}',z11_amount=999dec;`,
      );
      await check();
      equal(
        await actor(
          "RETURN fn::tree::read(payment:authenticated,'z_history','summary',[]).measures.basis.sum;",
        ),
        11.2,
      );
    }
    const populated = await snapshot(q);
    await applySchema(q, compiled.bundle);
    assert.deepEqual(
      await snapshot(q),
      populated,
      'schema reapplication preserves data and maintained state',
    );
    await check();
    if (!writeOnly)
      console.log(
        'PASS authenticated writes, protected derived metadata and populated schema reapplication',
      );
    else console.log('PASS populated schema reapplication');
    console.log(
      'entity calculation suite: all independent source/AVL checks passed',
    );
  } finally {
    await server.close();
    fs.rmSync(output, { recursive: true, force: true });
  }
}
if (require.main === module)
  main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
  });
module.exports = { main };

# Complete accounting fixture

[`accounting-complete.js`](accounting-complete.js) creates a repeatable learning
dataset covering all 48 public accounting input tables. It also creates one
login-disabled user, one email address and one phone number. Use a development
database with the current `all-in-accounting` schema already installed and a
privileged connection. Install development dependencies with `npm ci` first.

## Populate from your existing REPL connection

Run these commands from the repository root in the workbench. If you already
have `c.db`, keep using that connection:

```js
const complete = require('./dev-tools/fixtures/examples/accounting-complete')
const config = { seed: 'complete-demo', tenant: 'rebase_tenant:default', startAt: '2027-01-01T00:00:00Z', salesCount: 3 }
const demo = await complete.populateComplete(c.db, config)
console.log({ scenario: demo.scenario, reused: demo.reused, inserted: demo.created.length, counts: demo.counts })
```

For a new workbench session:

```sh
node --env-file=.env.local dev-tools/workbench.js --project all-in-accounting
```

```js
const c = await connect()
```

If this is a fresh disposable database, install its schema before population:

```js
const built = build({ project: 'all-in-accounting' })
await prepare(c.db, { schema: built.bundle })
```

The helper creates the selected tenant if absent, then inserts the scenario in
one transaction. A failure cancels the transaction. The default recipe contains
109 explicit records, excluding tenant creation and records maintained by the
schema. The result exposes named record IDs in `demo.ids`, making the dataset
easy to explore without copying generated IDs.

## Configuration and repeat runs

| Option | Default | Meaning |
| --- | --- | --- |
| `seed` | `'complete-demo'` | Nonempty string controlling generated names and scenario identity. |
| `tenant` | `'rebase_tenant:default'` | Tenant record ID; created if absent. `tenantName` can supply its initial name. |
| `startAt` | `'2027-01-01T00:00:00Z'` | Date/time for day 1; all scenario dates move together. |
| `salesCount` | `3` | Integer from 1 to 20; each sale adds an invoice, issue, base tax, compound tax and payment. |

The configuration, including tenant and normalized start time, determines stable
IDs and unique dimension codes. Repeating the same configuration finds the
complete scenario and inserts no scenario records: `reused` is `true` and
`created` is empty. Your edits to those records are preserved. This checks
record presence and tenant membership; it does not restore their original
values or verify that edited accounting totals still match the recipe.

Use a new seed to add an independent scenario alongside the first:

```js
const secondDemo = await complete.populateComplete(c.db, { ...config, seed: 'second-demo' })
```

If only some expected records exist, population fails rather than rebuilding
the missing portion. Choose a new seed to keep existing data. For a full reset,
the following command deletes **all database records**, including other
scenarios, tenants, credentials, configuration and audit history. It retains
schema definitions. Use it only in a disposable development database with
application writers and workers paused; see the [preparation guide](../../README.md#database-preparation)
for clearing requirements.

```js
await prepare(c.db, { clear: true })
const resetDemo = await complete.populateComplete(c.db, config)
```

## Preview without a database

Model compilation and planning open no connection and write no database records.
The plan validates public inputs and binds native SDK values. Database events
calculate accounting amounts and enforce aggregate constraints during insertion,
so an offline plan is not a substitute for database validation.

The three exported functions are ordinary, composable functions:

- `createCompleteModel()` loads accounting input schemas plus the three contact
  input schemas declared in this example. Reuse its result across plans/runs.
- `completeOptions({ model, ...config })` returns a fixture recipe, initial tenant
  space, stable `ids` and `scenario`. Inspect or extend `recipe` before planning.
- `populateComplete(db, { model?, tenantName?, ...config })` handles tenant
  creation and repeat detection, then calls the existing `fixtures.populate`.
  It returns `rows`, `created`, `space`, `ids`, `counts` and `reused`. `counts`
  describes the whole scenario even when a repeated run inserts nothing.
  On reuse, `rows` and `created` are empty and `space` contains only the tenant
  input; use the stable `ids` to query the current records in either case.

```js
const { plan } = require('./dev-tools/fixtures')
const previewModel = complete.createCompleteModel()
const previewOptions = complete.completeOptions({ ...config, model: previewModel })
const preview = await plan(previewOptions)
preview.rows.length
preview.rows.map(row => ({ table: row.table, id: String(row.id), content: row.content }))
```

## Command line

Run from the repository root, using the profile for your already-deployed
development database:

```sh
node --env-file=.env.local dev-tools/fixtures/examples/accounting-complete.js \
  --seed complete-demo \
  --tenant rebase_tenant:default \
  --start 2027-01-01T00:00:00Z \
  --sales 3
```

The CLI uses the existing connection configuration, prints scenario IDs and
counts, then closes its connection. It does not install or clear the schema.
`--start` maps to `startAt`; `--sales` maps to `salesCount`.

## Walk through the eleven stages

Recipe order is explicit, including dependencies caused by balances and
reservations. Dates describe business events; insertion order also demonstrates
how earlier FX quotes can update existing history.

1. **Dimensions:** two currencies, a measure unit, raw and finished items,
   labor service, two subsidiaries, operating units, counterparties and six
   directed exchange pairs. The two currency directions are authored separately.
2. **Accounts:** customer/supplier currency and resource accounts, treasuries,
   fee accounts, direct/indirect tax accounts, stock accounts and a damage account.
3. **Opening balances:** cash and stock funding precedes consumption; a separate
   tax pool supplies both credit and liability capacity.
4. **Sales:** each invoice starts with 100 principal, 10 base tax and 11 compound
   tax, plus a partial settlement with a fee and creditable fee tax. These are
   initial amounts; subsequent adjustments change the first sale.
5. **Purchase:** a USD invoice receives stock and is partially paid from INR
   using an explicitly directed conversion pair.
6. **Adjustments:** repeated sales credits, a purchase credit, linked tax
   adjustments, payment withholding, a refund and manual tax credits. Linked
   compound-tax adjustments follow base-tax adjustments by one second.
7. **Claims and tax cash:** monetary and goods claims receive partial
   settlements; the tax pool demonstrates payment, deposit, refund and offset.
8. **Transfers:** damaged stock, cross-subsidiary cash and goods movements, and
   an FX trade with a fee.
9. **Production:** material/labor inputs reserve resources, output becomes
   available at completion, cash pays production cost, workshop capacity is
   reserved, and a later exchange sells some finished output.
10. **Dated exchange rates:** quotes are inserted after their consumers to
    demonstrate automatic revaluation of affected history. A reverse quote is
    independent of the forward quote.
11. **Contacts:** one `rebase_user` has `login_access: false`; its email uses
    `example.test` and its phone uses the unassigned `+999` prefix.

The 48 accounting tables covered are:

| Area | Tables |
| --- | --- |
| Dimensions | `currency`, `measure_unit`, `item`, `service`, `subsidiary`, `operating_unit`, `organization`, `exchange_pair`, `exchange_rate` |
| Accounts | `organization_currency_account`, `organization_resource_account`, `treasury`, `misc_currency_account`, `direct_tax_account`, `indirect_tax_account`, `stock_account`, `misc_stock_account` |
| Entries and claims | `account_entry`, `stock_entry`, `account_claim`, `claim_settlement` |
| Invoices and issues | `sales_invoice`, `purchase_invoice`, `sales_issue`, `purchase_issue`, `invoice_settlement`, `issue_tax`, `issue_net_tax` |
| Adjustments | `sales_adjustment_note`, `purchase_adjustment_note`, `issue_adjustment`, `issue_adjustment_tax`, `issue_adjustment_net_tax`, `tax_adjustment`, `net_tax_adjustment`, `tax_adjustment_net_tax`, `payment_adjustment`, `payment_withholding` |
| Tax cash and transfers | `tax_settlement`, `tax_deposit`, `tax_refund`, `tax_offset`, `resource_exchange` |
| Production | `production`, `production_input`, `production_output`, `production_cost`, `production_capacity` |

Accounting amounts, reporting projections, `z_*` trees, dependency indexes and
`audit_mutation` rows are maintained by the installed schema. The fixture does
not write those outputs directly. Audit records increase the total database
row count beyond the explicit recipe count.

The contact examples do not create authentication challenges, delivery tasks,
passkeys, passkey challenges or passkey exchanges. Verification, credentials,
login ceremonies and delivery configuration require their normal workflows;
they are not fabricated as fixture data.

## Inspect the records using native RecordId bindings

`demo.ids` contains readable ID strings. Convert them to native SDK `RecordId`
values before using them as query parameters:

```js
const { recordId } = require('./dev-tools/fixtures/model')
const demoIds = Object.fromEntries(Object.entries(demo.ids).map(([name, id]) => [name, recordId(id)]))
```

Inspect the first sales invoice and its original and adjusted taxes:

```js
await c.db.query('SELECT id, invoice_date, z_history.summary FROM ONLY $id;', { id: demoIds.sale1 })
await c.db.query('SELECT * FROM $ids;', { ids: [demoIds.saleIssue1, demoIds.saleTax1, demoIds.saleNetTax1, demoIds.firstCredit, demoIds.firstCreditTax, demoIds.firstCreditNetTax] })
```

Inspect treasury balances and the FX pair, its dated quotes and converted trade:

```js
await c.db.query('SELECT id, currency, z_history.summary FROM $ids;', { ids: [demoIds.cash, demoIds.dollars, demoIds.foreignCash] })
await c.db.query('SELECT * FROM $ids;', { ids: [demoIds.usdInr, demoIds.earlyQuote, demoIds.laterQuote, demoIds.inrUsd, demoIds.reverseQuote, demoIds.fxTrade] })
```

Inspect the production interval, its lines and remaining finished stock:

```js
await c.db.query('SELECT * FROM $ids;', { ids: [demoIds.production, demoIds.productionMaterial, demoIds.productionLabor, demoIds.productionOutput, demoIds.productionCost, demoIds.productionCapacity, demoIds.outputSale] })
await c.db.query('SELECT id, z_history.summary FROM ONLY $id;', { id: demoIds.finishedStock })
```

When finished with a connection you opened, run `await c.close()`.

## Verify the example itself

With the repository's supported `surreal` executable on `PATH`:

```sh
node dev-tools/fixtures/examples/accounting-complete.probe.js
```

This opt-in integration check starts and removes its own SurrealKV database.
It does not use your application profile. It checks deterministic planning,
native accounting calculations and tree/dependency integrity, automatic audit,
repeat runs, independent seeds, incomplete-run detection and transaction
rollback after an aggregate constraint rejects a write. Initial schema
installation is the slow part; normal population against your already-installed
schema does not redeploy it.

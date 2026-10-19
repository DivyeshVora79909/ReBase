# Complete accounting fixture

[complete.js](complete.js) creates a repeatable learning dataset covering all 48
public accounting input tables, plus one login-disabled user, email and phone.
The default scenario has **109 explicit records across 51 tables**. Native events
calculate outputs, trees and audit records. Use the current installed accounting
schema and a privileged development connection.

## Files and build output

| Authoring file | Purpose |
| --- | --- |
| [complete.defaults.json](complete.defaults.json) | Seed, tenant, initial tenant name, starting date, sale count and recipe version. |
| [complete.js](complete.js) | Explicit scenario stages and transaction callbacks. |
| [schemas/](schemas/) | Three fixture-only contact input schemas; the user schema requires login to stay disabled. |
| [../schemas/](../schemas/) | The 48 public accounting input schemas, shared with applications. |

`npm run build:all-in-accounting` copies this directory unchanged to
`build/all-in-accounting/fixtures/`. Public schemas remain under `client/schemas/`;
fixture schemas never become public client inputs. The build does not execute
recipes. Change authored files, then rebuild; build check mode detects stale or
removed fixture files. Bump the version in defaults when changing the scenario
in a way that should allocate new identities.

Monoids, memberships, query bounds and invariants remain in their native authored
functions and annotations. They are not copied into fixture rules. The compiler's
`devtools.json` and `inspector.html` make those facts and source functions browsable.
The fixture contributes only valid source inputs and example values.

## Populate from the workbench

From the repository root, use your existing connection as `c` or open one with
`const c = await connect()`. The following loads the built inputs without another
compilation or connection:

```js
const model = fixtures.loadModel('build/all-in-accounting')
const complete = require('./build/all-in-accounting/fixtures/complete')
const config = { seed: 'complete-demo' } // omitted settings come from complete.defaults.json
const options = complete.populationOptions({ ...config, model })
const demo = await fixtures.populate(c.db, options)
console.log({ scenario: options.scenario, reused: options.reused,
  inserted: demo.created.length, counts: options.expectedCounts, ids: options.ids })
```

For a new session:

```sh
node --env-file=.env.local dev-tools/workbench.js --project all-in-accounting
```

For a fresh disposable database, build and install its schema first:

```js
const built = build({ project: 'all-in-accounting' })
const c = await connect()
await prepare(c.db, { schema: built.bundle })
```

`populationOptions` composes the existing `space(transaction)` and `recipe()`
callbacks. Tenant creation, repeat detection and insertion use one transaction;
a failure cancels all of them. The module imports only Node's hashing function
and its local defaults. It has no source-checkout paths, compiler calls, SDK
imports, or connection setup. The transaction callback's native SQL is the
explicit SurrealDB-specific part.

## Configuration and repeat runs

| Option | Default | Meaning |
| --- | --- | --- |
| `seed` | `'complete-demo'` | Generated names and scenario identity. |
| `tenant` | `'rebase_tenant:default'` | Record ID string; created if absent. Use the same spelling on repeat runs. |
| `tenantName` | `'Default Tenant'` | Initial name for a new tenant; existing names are preserved. |
| `startAt` | `'2027-01-01T00:00:00Z'` | Day 1; all dates move together. |
| `salesCount` | `3` | Integer 1–20; each sale adds five records. |

Recipe version, tenant, seed, normalized start time and sale count determine
stable IDs and unique dimension codes. Repeating that configuration inserts
nothing, sets `options.reused` to true, and preserves developer edits. This checks
record presence and tenant membership; it does not restore original values or
verify edited accounting totals. `options.ids` and `options.expectedCounts`
always describe the intended scenario; `demo.rows` and `demo.created` describe
this call's writes and are empty on reuse.

Use a fresh options object for each run. A new seed adds an independent scenario:

```js
const secondOptions = complete.populationOptions({ ...config, model, seed: 'second-demo' })
const secondDemo = await fixtures.populate(c.db, secondOptions)
```

A partial scenario is rejected. Choose a new seed to preserve existing data.
For a full disposable-database reset, `await prepare(c.db, { clear: true })`
deletes all records, including other tenants, credentials and audit history;
then populate again with a fresh options object. See the
[preparation guide](../../../dev-tools/README.md#database-preparation).

## Offline preview and command line

```js
const previewOptions = complete.options({ ...config, model })
const preview = await fixtures.plan(previewOptions)
preview.rows.map(row => ({ table: row.table, id: String(row.id), content: row.content }))
```

`options` returns a plain recipe and initial tenant space. Planning validates
JSON inputs and binds native values without connecting. Native events still
provide the authoritative aggregate and accounting checks when inserted.

The shared runner consumes a built module. `--config` accepts a JSON object of
option overrides; defaults are beside the recipe. Without `--preview`, it uses
the process profile's already-deployed database and closes its connection.
It never installs or clears a schema.

```sh
node dev-tools/fixtures/run.js build/all-in-accounting/fixtures/complete.js --preview
node --env-file=.env.local dev-tools/fixtures/run.js build/all-in-accounting/fixtures/complete.js --config /path/to/demo.json
```

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

`options.ids` contains readable ID strings. Convert them to native SDK `RecordId`
values before using them as query parameters:

```js
const { recordId } = require('./dev-tools/fixtures/model')
const demoIds = Object.fromEntries(Object.entries(options.ids).map(([name, id]) => [name, recordId(id)]))
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
npm run probe:fixtures-complete
```

This opt-in integration check starts and removes its own SurrealKV database.
It does not use your application profile. It checks deterministic planning,
native accounting calculations and tree/dependency integrity, automatic audit,
repeat runs, independent seeds, incomplete-run detection and transaction
rollback after an aggregate constraint rejects a write. Initial schema
installation is the slow part; normal population against your already-installed
schema does not redeploy it.

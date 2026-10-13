# Worked accounting inputs

[fixture-example.js](../../dev-tools/accounting/fixture-example.js) contains
17 explicit records in dependency order. It creates a USD subsidiary, an
organization's currency/resource positions, owned treasury/stock, a directed
item valuation pair, opening stock, a sale, a covered earlier advance and a
later price adjustment. The invoice ends with amount 90, paid 80 and balance 10.

```bash
node dev-tools/accounting/fixture-example.js
```

This command validates the public inputs and binds native `RecordId`, `Decimal`
and `Date` values without opening a connection. The accounting acceptance probe
also executes the example in a disposable database under its own tenant.
The fixture's small binding map covers the fields in that example; extend it
explicitly for other inputs.

```js
const { prepareFixture } = require('./dev-tools/accounting/fixture-example');
for (const row of prepareFixture()) {
  await db.query('CREATE ONLY $id CONTENT $content;', {
    id: row.id, content: row.content,
  });
}
```

The caller supplies a connected/authenticated SDK client and a tenant it may
write. Handle the SDK's query responses/errors before reporting success. Bind
values instead of interpolating them into SurrealQL.

For the product-difference case, 10 units at price 10 have amount 100. A quantity
change −1 and price change +1 produce 9 × 11 − 10 × 10 = −1. At a 10% base tax
and 10% net tax, linked adjustments are −0.10 and −0.11. With a payment of 90,
the invoice's directional receivable/payable totals are 121 and 91.21, leaving
29.79. The acceptance probe checks these values, rule edits and chronological
changes against an independent source replay.

The [developer guide](developer-guide.md) has executable forward/inverse reference
queries, exact native-account lookup, pagination, interval summaries and corrected
average prices. [Function reactivity](../rebase-system/function-reactivity.md)
explains how an authored calculation receives dated invalidations.

# Accounting as explicit calculation records

The October 7 redesign, extended October 8, uses strict SurrealDB tables, explicit account effects,
ordered validators and reactive formulas. Organization, treasury, direct tax,
indirect tax, stock, miscellaneous stock and miscellaneous currency records are
actual currency-bearing accounts. Invoices only validate their descendants.

Start with the [blueprint](blueprint.md), [worked examples](examples.md), and
[implementation handoff](implementation-handoff.md). The [execution plan](redesign-2026-10-07.md)
records how the request was interpreted; [verification](verification.md) records
fresh evidence and its limits.

The [extension contract](extension-contract.md) adds adjustment-note groups, tax
cash/credit offsets, independent claims, inline charges, directed exchange pairs
and optional trade/payment analytics. Read its
[verification](extension-verification.md) for the current acceptance packet.

The profile includes required invoice parents, covered advance payments,
base/net taxes, bounded percentage rules, quantity/price/FX corrections,
rule-linked adjustment taxes, returns/refunds, withholding, resource exchange,
and future production with stock, cash, service and operating-capacity checks.
There are no generated business children or dependency arrays to maintain.

```bash
npm run build:all-in-accounting
npm run verify:accounting
node dev-tools/accounting/fixture-example.js
```

There are 43 authored public create schemas in `schemas/`. The compiler exports
these unchanged to `build/all-in-accounting/client/schemas/`; derived values,
authorization internals and tree slots are not public inputs. Send native SDK
`RecordId`, `Decimal` and date values in bound queries.

`designs/accounting-recipes` and its obsolete commands/probes were removed at the
user's request. Historical H1–H8 and October 5 evidence remains in Git and the
system evidence directory; it does not validate this API. MetaSol's separate
frontend still needs to adopt the current table and input contracts. This work
changes the accounting profile, not a deployed database.

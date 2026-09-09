# ReBase all-in-one design

Status: Accounts kernel implemented, including explicit two-leg
`money_exchange` support; CRM, HRM, and later domains remain sibling
extensions planned for future passes.

This is the deployable profile root for the calculation suite.  `core/` owns
the single principal pair and `accounts/` owns the first calculation domain.
Future domains (CRM, HRM, warehouse, manufacturing, ecommerce, and
productivity) should be added as sibling directories with explicit table and
view names; they must not redefine the principal tables.

The compiler recursively loads SurrealQL files below this directory:

```sh
npm run build -- --project designs/all-in-one --output build/all-in-one
```

The focused runtime proof is `npm run probe:accounts`. It uses a disposable
on-disk SurrealKV instance and covers position guards, mutable deltas,
effective-time prefix replay, tax and settlement propagation, references,
locks, and concurrent retries.

`organization_finance_profile` supplies optional functional/reporting currency
metadata for future domains; it never supplies an implicit transaction
currency.

No frontend or MetaSol material is part of this tree.

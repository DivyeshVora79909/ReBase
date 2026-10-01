# ReBase calculation suite v2

This profile composes entities and dated interactions using one intrusive AVL
engine. An entity supplies identity; a dimension account owns aggregates and
constraints; an interaction contributes to each relevant owner. An interaction
can also own the history of its corrections. Business records store the tree
memberships, and field dependencies refresh derived facts.

The [compact contract](../../research/rebase/temporal-trees.md) records the
algebra, compiler annotations, causal rules, complexities, and measured limits.

| Source | Composition |
|---|---|
| [core/schema.surql](./core/schema.surql) | `rebase_user` / `rebase_group` principals. |
| [accounts/schema.surql](./accounts/schema.surql) | Entities, currency/resource accounts, FX quotes, correction notes, rules and guards. |
| [accounts/money.surql](./accounts/money.surql) | Asset movements, FX, invoice/tax settlement, corrections/refunds, cash charges, direct-tax allocations. |
| [accounts/logistics.surql](./accounts/logistics.surql) | Item/service capacity, delivery values, corrections/returns, independent/compound assessments, direct unit and party participation. |
| [accounts/billing.surql](./accounts/billing.surql) | Two-party invoices, standalone indirect-tax claims, claim corrections. |
| [crm/schema.surql](./crm/schema.surql) | Cases, chronological close/reopen constraints, interactions and effort by organization. |
| [hrm/schema.surql](./hrm/schema.surql) | Employment, leave/service allowances, dated grants/usage, employment boundaries and unit activity. |

`money_account(a_entity,a_currency)` is unique by the pair; one entity can have
many currencies. Create the organization's currency account before its treasury
or tax dimensions. The dimension resolves and protects its organization account
through a native indexed lookup. Use `a_nonnegative=false` for a funding source
or an external party whose asset availability is not modeled. Opening funds are
ordinary payments. Stock/service grants follow the same principle.

Invoices explicitly name issuer and recipient organization/currency accounts.
Original lines must precede issue; settlements must follow it. Party and tax
claims appear at `max(line effective time, issue time)`. Later corrections retain
their date. `asset`, `receivable`, and `payable` are separate measures, so an
assessment never produces cash. `tax_asset` receives actual allocations;
`tax_receivable` / `tax_payable` receive claims that tax recovery/remittance
consumes while moving real assets. Tax labels, eligibility, rates, and ordering
are client configuration. Cash fees have real receiving asset accounts.

A payment supplies `a_amount` in its source currency and an optional
`a_exchange`. Without an exchange, currencies must agree. Corrections use a
source delta plus an independent destination residual (`a_to_delta`); refunds
can use their own quote or inherit the original. Both original leg capacities
remain guarded. Corrections/refunds/returns require `a_note`; note dates,
currencies and optional invoice association are validated by their own trees.
An unscoped note can group corrections in its currency. Setting `a_invoice`
requires every correction to belong to that invoice, including existing entries.

Only required owners get trees. Unit activity counts interactions without adding
incompatible quantities or currencies. CRM and HRM are usable small compositions,
not a complete sales pipeline, payroll product, or calendar scheduler. Dated
facts are explicit; passage of time alone does not create grants or trigger rules.

```sh
npm run build:all-in-one
npm run probe:temporal-tree
npm run probe:accounts
npm run probe:suite
npm run verify
```

The compiler builds 48 tables and no aggregate views. Probes use disposable
SurrealKV databases and independent source reconstructions for every maintained
membership and aggregate. The generated schema exceeds the default HTTP `/sql`
body limit; use SurrealDB's import interface, or split DDL on statement boundaries
as the probe harness does. Schema reapplication preserves populated state.

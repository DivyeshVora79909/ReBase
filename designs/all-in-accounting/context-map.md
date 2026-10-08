# Accounting source map

| Source | Responsibility |
|---|---|
| `core/schema.surql` | Typed descriptors, decimal algebra, membership helpers, timing and capacity validation |
| `core/accounts.surql` | Seven account families, dimensions, descriptor indexes, account bounds |
| `postings/issues.surql` | Required invoice ancestry, source bases and invoice-date solvency |
| `postings/taxes.surql` | Bounded rules, base and strictly prior net taxes |
| `postings/corrections.surql` | Physical returns, signed quantity/price/FX changes, manual and rule-linked tax corrections |
| `postings/payments.surql` | Converted settlements, refunds, post-date cash reversals and source capacity |
| `postings/withholding.surql` | Same-family transfer to a direct-tax account |
| `postings/exchange.surql` | Explicit two-account resource/currency exchange and optional output linkage |
| `postings/production.surql` | Normalized inputs, outputs, cash reservations and operating/service capacity |
| `postings/entries.surql` | Minimal monetary and resource extension examples |
| `postings/adjustment-notes.surql` | Sales/purchase document dimensions, sign and finalization guards |
| `postings/tax-cash.surql` | Tax cash settlement, deposits, refunds, offsets and chronological credit/liability floors |
| `postings/claims.surql` | Explicit non-invoice claims and source-specific cash settlement |
| `postings/zz-payment-charges.surql` | Shared bounded inline charges, optional tax credit and production reservations |
| `postings/analytics.surql` | Directed pair contexts, opt-in trade/payment measures and query units |
| `../../dev-tools/accounting/extension-probe.js` | Source-derived extension acceptance and complete rollback snapshots |
| `schemas/` | Forty-three public create-input schemas |
| `../../dev-tools/accounting/source-oracle.js` | Independent rational arithmetic, chronological replay and structural oracle |
| `../../dev-tools/accounting/probe.js` | Compiled, disposable acceptance with complete rollback snapshots |
| `../../dev-tools/accounting/fixture-example.js` | Eleven editable public inputs and native SDK bindings |

Read the [blueprint](blueprint.md), then only the source relevant to a change.
The shared compiler remains under `dev-tools/compiler/`; authorization remains
under `framework/`. Domain code does not replace either with its own runtime.

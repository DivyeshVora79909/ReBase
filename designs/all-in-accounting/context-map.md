# Accounting source map

| Source | Responsibility |
| --- | --- |
| `core/schema.surql` | Descriptor tables, decimal algebra and native-unit helpers |
| `core/accounts.surql` | Subsidiaries, organizations, sparse positions and linear root bounds |
| `core/exchange-rates.surql` | Directed pairs, dated rates, predecessor lookup and authored impacts |
| `core/projections.surql` | Explicit native and reporting contributions with unit/perspective conversion |
| `postings/invoices.surql` | Invoice and note roots, commercial directions and linear capacity |
| `postings/issues.surql` | Original resource/value facts and additive trade measures |
| `postings/issue-adjustments.surql` | Chronological quantity/price product differences |
| `postings/taxes.surql` | Original base and strictly prior net-tax bases/rules |
| `postings/tax-adjustments.surql` | Five strict tax-adjustment tables and marginal capped rules |
| `postings/payments.surql` | Converted settlements, unified payment adjustments and reversal capacity |
| `postings/tax-cash.surql` | Tax settlement/deposit/refund/offset and withholding |
| `postings/claims.surql` | Independent monetary/resource claims and source-specific settlements |
| `postings/exchange.surql` | Paired native real movements and separate rate observations |
| `postings/production.surql` | Native reservations, gross inputs, output and operating capacity |
| `postings/entries.surql` | Minimal explicit native effects and extension example |
| `postings/zz-fees.surql` | Inline bounded fee/tax inputs, derived values and memberships |
| `schemas/` | Forty-eight public create-input contracts |
| `../../dev-tools/accounting/acceptance.js` | Disposable fixture, source-oracle checkpoints and rollback snapshots |
| `../../dev-tools/accounting/source-oracle.js` | Independent rational source replay and full tree-structure verification |
| `../../dev-tools/accounting/probe.js` | Accounting model, dated rates and lifecycle acceptance |
| `../../dev-tools/accounting/extension-probe.js` | Financial, production, permissions and developer-example acceptance |
| `../../dev-tools/accounting/fixture-example.js` | Seventeen public inputs with native SDK binding |

Read the [developer guide](developer-guide.md), then the relevant source file.
The shared compiler and temporal coordinator remain under `dev-tools/compiler/`;
authorization remains under `framework/`.

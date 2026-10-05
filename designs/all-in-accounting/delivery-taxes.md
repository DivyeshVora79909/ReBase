# Delivery tax calculation contract

Updated 2026-10-05. Sales delivery taxes are declared on the individual priced
lines of `sales_invoice_issue`. Each managed tax record references its
`sales_invoice_line`, the underlying `stock_out` delivery, the invoice, the
customer claim, and the tax claim. Tax identities are ordinary `tax_account`
entities; their monetary position is the selected currency-specific claim.

Integration passed in the complete `npm run verify:accounting` suite on
2026-10-05: **20 mutation checkpoints and nine complete rollback snapshots**.
Dependency-based cleanup, accounting-specific tenant rejection and populated
schema reapplication passed. See the [backend handoff](../rebase-system/tenant-tree-handoff.md)
and [recorded evidence](../rebase-system/evidence/2026-10-05-tenant-tree-verification.json).

```surql
CREATE sales_invoice_issue:example SET
    owned_by = rebase_tenant:example,
    invoice = sales_invoice:example,
    issued_at = d'2026-10-04',
    lines = [{
        line_key: 'delivery-a', source: stock_out:delivery_a,
        billed_quantity: 2dec, unit_price: 5.04dec,
        tax_components: [{
            tax_key: 'levy', tax_claim_account: claim_account:levy,
            rule_version: sales_tax_rule_version:levy_v1
        }],
        compound_tax_components: [{
            tax_key: 'extra', tax_claim_account: claim_account:extra,
            rule_version: sales_tax_rule_version:extra_v1,
            predecessor_tax_key: 'levy'
        }]
    }];
```

Both nested component arrays are optional. Omission normalizes to `[]` during
creation and replacement of the line array. A base component selects exactly
one entered positive `amount` or immutable `rule_version`. A version supplies a
fixed amount or proportional rate. Components have unique keys within their
line. The optional compound layer contains at most one component and references
one base component from the same line; it cannot reference another delivery or
another compound stage.

## Amounts and roots

The line's base is its billed quantity multiplied by unit price, rounded in its
invoice currency. Each base tax rounds its selected fixed/manual amount or
`line.amount * rate`. The compound tax rounds
`(line.amount + predecessor.amount) * rate`. All inputs and intermediate amounts
are native decimals. Currency precision zero uses whole-unit rounding. A
component that rounds to zero is rejected, preserving the declared positive
component contract.

For example, delivery bases of 10.06 and 10.08 at ten percent each produce 1.01
and 1.01. The combined tax is 2.02. Applying the rate once to 20.14 would produce
2.01; the delivery contract deliberately retains the separate calculations.

Each output uses four maintained slots:

| Root | Contribution |
|---|---|
| Priced delivery line `z_taxes` | Tax sum and exact currency tag. |
| Invoice `z_outstanding` | Additional customer outstanding amount. |
| Customer claim `z_history` | Receivable and positive net claim. |
| Tax claim `z_history` | Payable and negative net claim. |

The invoice remains an aggregate and settlement-validation root. The line's
ordinary `amount` is independent of `z_taxes`, so reading that amount to calculate
tax does not create aggregate feedback. Line, invoice and claim root guards
validate the final transaction state. A physical stock delivery can be billed
in several currency-specific portions; grouping tax under its priced line
preserves the unit of measure rather than summing different currencies in one
undimensioned delivery total.

The issue timestamp remains the accounting recognition date of its billed
lines and their taxes. `delivery` preserves the physical movement's identity;
its source timestamp still limits how early the line can be recognized.

## Lifecycle, permissions and provenance

`sales_delivery_tax` and `sales_delivery_compound_tax` are private managed
outputs of the issue's existing required-output recipe. They use stable
`(issue ID, role)` record IDs. Roles encode the full pair of line key and tax key;
embedded separators do not cause identity collisions. An amount, rule, invoice,
currency or delivery-reference edit retains the same output IDs when those
business keys remain unchanged.

Inputs produce the lines first, then base taxes, then compound taxes. The typed
predecessor and line references enforce causality and referential integrity.
The compiler orders managed output creation from declared `REFERENCE` edges and
removes outputs in reverse dependency order: compound taxes, base taxes, then
removed lines. The probe checks this lifecycle by removing a line and a whole
issue. Managed outputs cannot themselves own nested recipes.

Record users edit the authorized issue. Direct creation, editing and deletion
of managed tax rows are denied. The readable issue retains each line's physical
`source` and selected tax inputs. Backend output records retain explicit `line`,
`delivery`, `invoice`, `currency`, `tax_key` and selected rule/predecessor
provenance; they do not widen existing output-table read permissions. Frontend
presentation of these inputs and totals belongs to the deferred tenant frontend
update.

All references obey tenant boundaries. Tax claims must share the invoice's
currency and economic entity and must point to a tax identity. Selected rules
must match their component key, tax claim and recognition-date validity window.
Changing a line refreshes its own base and compound calculations. Moving an
issue to a different invoice/currency also requires matching tax claims and
versions; the transaction either refreshes every contribution or rolls back.

## Existing invoice-level policies

The older **top-level** `sales_invoice_issue.tax_components` and
`compound_tax_components` retain their explicitly invoice-wide fixed,
proportional, published-aggregate and compound policies. They remain separate
calculation examples and existing contracts. They are not automatically converted
to delivery taxes. New delivery calculations belong in the nested line arrays;
selecting both levels intentionally posts both sets of components.

This slice covers sales delivery taxes. Existing assessed purchase tax,
supplier withholding and recognition recipes keep their own source/lifecycle
contracts. The rules are calculation inputs, not jurisdictional compliance rules.

## Verification and cost

Run `node dev-tools/accounting/delivery-tax-probe.js`. It compiles the real
accounting profile into a disposable SurrealKV database, performs native
record-user writes, and reconstructs every line/tax node and participating root
from source inputs using an independent decimal and tree oracle. Cases include
fixed/manual/proportional choices, compound dependency, stable IDs, an unchanged
peer delivery, tax/date/quantity rejection with audit rollback, delivery/invoice/
currency moves, output-write denial, reapplication, line removal and issue
cleanup. The added acceptance cases split one physical source across two priced
lines (checking per-portion rounding and the shared quantity ceiling), reject
foreign-tenant invoice and paired tax-claim/rule references atomically, and
settle at the exact issue timestamp. Empty, line-only, invoice-only, and both
input modes check that line taxes and the existing invoice-wide tax output are
additive; the independent oracle includes both output families and settlement
roots. The focused `delivery-03` pass and the final `accounting-02` suite both
completed these cases, including native issue deletion and complete cleanup.

Source snapshots use `WITH NOINDEX ORDER BY id`. In the multi-reader managed-root
fixture, an indexed ID-order scan returned a duplicate row on SurrealDB 3.3.0;
unindexed and unordered scans agreed on the two stored records. The reproduction
and limits are in the backend evidence. The oracle compares complete results
without deduplication, and makes no indexed-performance claim.

Four slots per tax bound each output's tree participation. The number of
lines/taxes remains a developer-controlled source fan-out, and a whole issue
replacement reconciles its selected outputs. This correctness probe does not
establish throughput, a universally small fan-out, or a migration of existing
deployed invoice records.

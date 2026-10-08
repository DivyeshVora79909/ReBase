# Accounting extension contract — October 8

This extends the [base accounting contract](blueprint.md) using the same native
records, dependency coordinator and ordered trees. The [execution plan](expansion-2026-10-08.md)
records the scope; [extension verification](extension-verification.md) records
fresh evidence. Public inputs are in `schemas/`; no generated business rows are
required. The profile has 43 domain tables, including nine new record types.

## Adjustment notes are validators

`sales_adjustment_note` and `purchase_adjustment_note` have a required organization,
its derived currency, optional number/description and `draft` (default true).
`issue_adjustment`, `tax_adjustment` and `payment_adjustment` can select a note.
`adjustment_tax` inherits the note from its issue adjustment. Returns stay under
the original invoice and cannot select a post-invoice adjustment note.

The note's `z_lines` checks organization, currency, commercial side and sign.
Every nonzero line must be positive, or every nonzero line negative. A capped tax
correction of zero is neutral. Even drafts reject mixed signs or dimensions.
Set `draft=false` after authoring the lines: finalization rejects an empty note
or one containing only zero contributions. A finalized note can change only if
it remains valid. Reopen it explicitly before removing its last effective line.
This draft flag supports statement-by-statement validation, not a statutory
posting/approval workflow. It is the implementation assumption presented to the
user while work continued.

Commercial `amount` and cash `settlement` totals are separate measures. A -100
price correction and -100 cash return describe a -100 commercial adjustment and
100 returned cash; adding them into a -200 document value would double count.
Line sign uses its commercial amount, or its settlement delta for a cash line.
Ungrouped corrections remain valid. A document may span several invoices of the
same organization and side. The note does not post account effects itself.

## Cash, tax credit and independent claims

All values below are positive inputs; destination amounts use the explicit
exchange rate and destination currency precision. Equal currencies require rate
one. The tax account's real measure records cash delivered to it, independently
of credit and liability. Its complete-time receivable/payable floors are zero.

| Fact | Treasury real | Tax real | Tax receivable | Tax payable |
| --- | ---: | ---: | ---: | ---: |
| `tax_settlement` | -amount | +converted | 0 | -converted |
| `tax_deposit` | -amount | +converted | +converted | 0 |
| `tax_refund` | +amount | -converted | -converted | 0 |
| `tax_offset` | 0 | 0 | -credit amount | -converted liability amount |

The first three select a tax account and treasury/miscellaneous currency account.
An offset selects credit and liability accounts; they may be the same account.
Its rate is liability-currency units per credit-currency unit. Offsets never
create treasury cash. Backdating, deletion and edits must preserve every later
tax capacity, not just the final balance. These are calculation capabilities;
the application chooses which tax accounts can legally offset each other.

`account_claim` creates an explicit non-invoice receivable or payable against an
organization or tax account. It has `claim_kind`, positive `amount`, effective
time and optional description. Rent, interest, penalties and other obligations
can use this fact without inventing a new table for each description.
`claim_settlement` consumes its dated `z_capacity` and moves actual treasury cash.
Settlement cannot precede the claim or consume more than its remaining amount.
Organization real remains unchanged; tax real records the cash direction above.
Tax-pool settlements/offsets do not allocate themselves to independent claim
roots or invoices. Select the source-specific settlement when that allocation
is required.

No automatic write-off, interest schedule, accrual subsystem or bank matching is
introduced. Author future facts and explicit amounts, or use the existing
scheduler to create them when that is the application's desired behavior.

## One payment, one optional charge rule

The following cash facts support the same inline fields:
`invoice_settlement`, `payment_refund`, `payment_adjustment`, `claim_settlement`,
`tax_settlement`, `tax_deposit`, `tax_refund`, `resource_exchange`, `production_cost`.
A `payment_withholding` moves claims without cash and has no payment charge.

| Input | Meaning |
| --- | --- |
| `fee_account` | Miscellaneous currency account receiving paid cost; absent means no charge |
| `fee_rate`, `fee_lower_bound`, `fee_upper_bound` | Percentage and optional bounded rule in treasury currency |
| `fee_exchange_rate` | Charge-account currency units per treasury-currency unit |
| `fee_tax_rate`, `fee_tax_lower_bound`, `fee_tax_upper_bound` | Bounded percentage rule applied to the computed charge |
| `fee_tax_creditable` | Explicit application choice, default false |
| `fee_tax_account`, `fee_tax_exchange_rate` | Required indirect-tax account and conversion when creditable |

Rates/lower bounds default to zero; conversion rates to one; upper bounds are
optional. Bounds are nonnegative, ordered and currency-quantized. The formulas
use native decimals and ties-to-even currency rounding, including precision zero:

```text
fee = round(clamp(abs(gross cash) * fee_rate / 100, fee_lower_bound, fee_upper_bound))
fee tax = round(clamp(fee * fee_tax_rate / 100, fee_tax_lower_bound, fee_tax_upper_bound))
treasury real -= fee + fee tax
charge account real += converted(fee + noncreditable fee tax)
creditable tax account real += converted(fee tax)
creditable tax account receivable += converted(fee tax)
```

The original invoice/claim settlement stays gross. Net treasury movement can be
smaller than received settlement cash. Fees require a distinct cost account;
unused fee/tax configuration rejects. Computed values are protected native VALUE
fields, never client inputs. Refunds/adjustments can have their own charge; they
do not automatically refund the original fee. Independently negotiated 1:N
components remain explicit facts instead of becoming a fixed child generator.

A resource exchange charges its outgoing currency leg when present, otherwise
its incoming currency leg. A resource-to-resource barter has no cash leg and
cannot carry this inline charge. Production costs reserve base cash plus charge
and tax at the start, release that reservation and pay everything at the end.
Fee tax credit becomes effective at payment, not at reservation.

## Transfers and exchange contexts

`resource_exchange` already moves real between any selected treasury,
miscellaneous currency, stock and miscellaneous stock accounts. It covers cash
transfers, FX, resource exchange and movement between operating units. Same
resource requires rate one. A damage location can be a miscellaneous stock
account at a distinct logical operating unit. Two stock/miscellaneous stock
accounts cannot duplicate `(operating_unit, currency, resource)`.

`exchange_pair` is the reusable directed context, with immutable `from_resource`
and `to_resource` (currency, item or service). They must differ. The source
descriptor's unique `z_exchange_pairs` is keyed by destination descriptor; every
pair owns a dated `z_history`. The pair is explicitly authored and selected:

| Producer | Selection and orientation |
| --- | --- |
| Issue `price_pair` | Item/service units → invoice currency value |
| Issue `fx_pair` | Stock pricing currency value → invoice currency value |
| Cash settlement/deposit/refund `fx_pair` | Treasury currency → claim/tax currency |
| Resource exchange `exchange_pair` | From-account resource → to-account resource |

Issue corrections and payment corrections inherit the original selections.
They change signed `from_amount` and `to_amount`, but do not introduce observed
rates. An FX-only correction changes the numerator with a zero denominator
change. A price correction does not invent a new quantity. Original positive
volume contributes `observations`, `observed_from`, `observed_to` and rate extrema.
`corrections` counts correction facts. Sales, purchase, settlement and exchange
also have separate `<kind>_from`, `<kind>_to`, and observed `<kind>_rate` measures.
Use a relevant family's ratio for its net effective rate; use observed volumes
for a weighted original rate. The generic `rate.sum` is not a useful average.
No automatic inverse quote, FX gain/loss, valuation basis or legal tax rate is
inferred from the observations.

## Analytics enrollment and units

`include_analytics` defaults to false. Issues select it and their corrections
inherit it. Cash facts select it independently, including production cost.
Selecting a pair is separate from selecting trade/payment analytics.

| Root | Source measures and unit |
| --- | --- |
| Stock/miscellaneous stock `z_trade` | Separate net/gross sales/purchase quantity and local price value; one resource and pricing currency |
| Item/service `z_trade` | Net/gross sales/purchase quantities in that resource's unit |
| Currency `z_trade` | Net/gross sales/purchase invoice value, excluding taxes; one currency |
| Currency `z_trade_by_unit` | Same monetary measures, keyed `[operating_unit, effective_at]` |
| Organization `z_trade` | Same monetary measures in the organization's currency |
| Operating unit `z_trade` | Count/index and currency/resource uniformity tags; no mixed-unit numeric total |
| Treasury/miscellaneous currency and currency `z_payments` | Gross in/out, charges, charge tax and net cash in one currency |

`sales_lines` and `purchase_lines` count original issues, not corrections or
invoices. Gross measures preserve original activity; signed corrections change
net measures. Stock local value is quantity times price before invoice FX and
quantization; an explicitly allocated invoice rounding remainder remains in
invoice-currency analytics. These averages describe trade prices, not an
inventory-costing method or a profit measure. Payment analytics cover selected
single-cash facts; transfers keep both legs in account histories and their pair.
They are not silently folded into sales turnover or customer-payment volume.

```surql
-- [start, end) turnover for one operating unit, in exactly one currency.
RETURN fn::tree::read(currency:inr, 'z_trade_by_unit', 'range',
    [[operating_unit:shop, d'2027-01-01'], [operating_unit:shop, d'2027-02-01']]);
LET $s = fn::tree::read(stock_account:goods, 'z_trade', 'summary', []);
RETURN fn::accounting::ratio($s.measures.sales_value.sum, $s.measures.sales_quantity.sum);
```

Ratios return NONE when the denominator is zero or negative. Aggregate the
numerator and denominator first; never combine already-calculated averages.
Counts, sums, extrema and uniformity tags use the existing associative summaries.
Source membership is explicit; account subtotals are not reposted into the same
sum. Additional indexes should serve an actual leading-partition/range query,
not every permutation of dimensions.

Analytics and pair nodes carry `@rebase-tree-no-reader`. Enrollment does not
broaden source visibility. Root-summary visibility still needs a deliberate
owner/permission policy: a visible aggregate can reveal private children's
combined values. It is not automatically filtered for each reading user.

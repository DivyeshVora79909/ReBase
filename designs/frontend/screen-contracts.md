# Accounting screen contracts

These contracts describe the current [MetaSol](../../MetaSol/README.md) pages and
native inputs, with [verification](verification.md) tracked separately. All 43
public accounting record types are represented below. A visible action still
requires native permission, valid references and successful backend validation.
Ownership and calculation results are separate from the user's screen filters.

## Page-to-table coverage

Paths below follow `/w/:profile/:tenant/`. Every listed source has authored
create/edit/delete forms, subject to immutable dimensions and native guards.
Invoice corrections also appear in the invoice's source list; adjustment notes
provide an optional grouping. Each record type is counted once in this table.

| Page | Public record types | Surface |
| --- | --- | --- |
| `directory` (6) | `currency`, `measure_unit`, `item`, `service`, `operating_unit`, `exchange_pair` | Names/codes, precision, resource unit, optional availability/duration/capacity and directed pairs |
| `accounts`, `accounts/:id` (9) | `treasury`, `organization`, `direct_tax_account`, `indirect_tax_account`, `misc_currency_account`, `stock_account`, `misc_stock_account`, `account_entry`, `stock_entry` | Seven account families, policies/dimensions, recorded/as-of positions, contributing history and signed entries |
| `invoices`, `invoices/:id` (10) | `sales_invoice`, `purchase_invoice`, `sales_issue`, `purchase_issue`, `issue_tax`, `issue_net_tax`, `invoice_settlement`, `payment_withholding`, `issue_return`, `payment_refund` | Headers, independently authored issues/taxes/payments/returns, settlement and server totals |
| `adjustments` and invoice details (6) | `sales_adjustment_note`, `purchase_adjustment_note`, `issue_adjustment`, `tax_adjustment`, `adjustment_tax`, `payment_adjustment` | Signed corrections, optional notes, separate commercial/cash totals, finalize/reopen |
| `claims` (2) | `account_claim`, `claim_settlement` | Explicit receivable/payable claim and source-specific cash settlement |
| `taxes` (4) | `tax_settlement`, `tax_deposit`, `tax_refund`, `tax_offset` | Liability payments, credit deposits/refunds and cash-free offsets |
| `exchange` (1) | `resource_exchange` | Cash/resource transfers and scalar conversion, optional pair/production-output links |
| `production`, `production/:id` (5) | `production`, `production_input`, `production_output`, `production_cost`, `production_capacity` | Parent interval and independently authored stock, cash and service-capacity records |

The data functions live in [`directory.js`](../../MetaSol/src/data/directory.js),
[`accounts.js`](../../MetaSol/src/data/accounts.js),
[`invoices.js`](../../MetaSol/src/data/invoices.js),
[`adjustments.js`](../../MetaSol/src/data/adjustments.js),
[`claims.js`](../../MetaSol/src/data/claims.js),
[`taxes.js`](../../MetaSol/src/data/taxes.js),
[`exchange.js`](../../MetaSol/src/data/exchange.js) and
[`production.js`](../../MetaSol/src/data/production.js).

Overview shows bounded treasury, organization and stock account panels with their
own units and links to source pages. Analytics reads public roots without creating
another business record family. Users list/detail is read-only. Settings owns
appearance, density, accent, display zone, compact navigation and token-storage
choice. The shell supplies tenant sign-in, connection recovery and recent activity.

## Accounts, references and time

Regular lists fetch 26 rows, display 25 and expose Next using the extra row.
Search, kind, page and view are bounded URL state. Sorted scans use an ID
tie-breaker and `WITH NOINDEX`. Lookups display 12 of 13 fetched choices and
hydrate at most 50 selections. Their finite table set, native IDs and descriptive
labels distinguish similarly named records. Custom picker searches include the
parent invoice/note/source in both their bound query and reactive cache scope.

Recorded positions include all dated facts, including future ones. The Account
Before control uses a typed exclusive instant on `z_history`; it excludes every
contribution at that exact time. The contributing-record list always covers the
whole timeline, independently of that balance cutoff. It pages newest-first by
full typed keys. One source can contribute at several times; those rows remain
visible. An observed revision change restarts paging with a notice.

Monetary accounts show their currency; resource accounts show the resource unit
and pricing currency separately. Entry controls stay locked to the selected
account so their displayed units remain correct. `net = receivable - payable`
is a server-derived measure. Account floors/ceilings are editable policies checked
throughout the recorded timeline. Resource identity and account dimensions remain
fixed in editors. Device-local date input preserves milliseconds; display uses
the chosen time zone. Optional durations remain native Duration values.

## Invoices and corrections

An invoice header selects an organization and invoice date. Issues, taxes,
payments and corrections are separate explicit records. Header edits revalidate
descendants; the UI never generates a hidden line bundle or edits tree outputs.
Issues specify stock account, quantity, price, scalar FX and effective time.
Base/net taxes select an issue, tax account, percentage, optional bounds and FX.
A net tax needs an earlier taxable basis; the backend controls compounding and
rounding. Forms expose only authored inputs, while lists show calculated values.

Original issues, taxes, returns and payment refunds belong on or before the
invoice date; post-invoice adjustments belong after it. Returns consume source
quantity, refunds consume a payment, and an issue adjustment changes one signed
dimension: quantity, price or FX. Tax adjustments and taxes on corrections have
explicit source links. Native source-capacity and date guards decide acceptance.

Adjustment notes optionally group compatible corrections across invoices of the
same organization and side. Draft notes still validate dimensions and sign.
Finalization requires a nonzero contribution; reopen before removing the last
one. Commercial adjustment and settlement totals are shown separately so a price
reduction and cash return are not counted twice. Notes do not post extra effects.

## Cash, claims, tax and transfers

Invoice and claim settlements author actual cash movements. Independent claims
retain their own dated remaining capacity; a tax-pool transaction does not
silently settle a selected claim. Settlement lists distinguish gross cash from
the converted invoice/claim/tax amount. Withholding consumes a payment source
and transfers claim value without a cash charge.

Tax settlement pays a liability; deposit creates credit; refund consumes credit.
An offset consumes tax credit against a liability and has no cash, inline charge
or analytics enrollment. The same credit/liability account may be selected when
the native contract permits it. Future and historical capacity remain authoritative.

Nine cash facts share optional inline charge and charge-tax fields through
`FeeFields`: invoice settlement/refund/payment adjustment, claim settlement,
tax settlement/deposit/refund, resource exchange and production cost. Clearing
the charge account clears dependent inputs. Fees preserve gross settlement;
signed net cash subtracts charge and charge tax from the base cash direction.
Creditable charge tax requires an indirect-tax account and explicit conversion.
Refund/correction charges are authored independently of the original charge.

Transfers select two cash/resource accounts and a scalar rate. Same-resource
movement requires one. An optional directed exchange pair records the selected
context; no inverse quote is inferred. An optional production output consumes
that source's remaining quantity. Charge fields apply to the outgoing currency
leg when present, otherwise the incoming currency leg; barter has no cash charge.
The page shows base sent/received values and the charged leg's signed net cash.

## Production and analytics

Production owns name/start/end. Inputs reserve stock at start and consume it at
end; outputs record expected quantity then real stock. Costs reserve base cash
plus charges at start and pay at end. Capacity records select an operating unit,
service and quantity over the interval. Each line is independently editable and
removable; parent changes revalidate later uses and availability. The app derives
no status from the clock and has no recipe or assembly generator.

Analytics selects a readable root and typed `[start, end)` range. Datetime bounds
are `[[start], [end]]`; operating-unit bounds are `[[unit, start], [unit, end]]`.
Trade/payment enrollment is explicit where the source exposes it. Pair selection
is independent; transfers retain both account legs and pair history. Reports keep
currencies/resources separate; operating-unit roots have no mixed-unit money sum.
Rates divide summed values by summed quantities through the native ratio helper;
a nonpositive denominator has no rate. These observations do not define costing.
Published summaries follow root visibility policy and can include contributions
whose source rows the viewer cannot read. CSV exports only displayed projections.

## Shared interaction and limits

Editors preserve their original snapshot across refetch. Dirty/pending navigation
requires confirmation; busy dialogs cannot close. A 20-second unconfirmed write
keeps its stable reference and offers current-record inspection, with no automatic
retry. Session and mounted-form fences prevent late callbacks from changing a new
session or route. Refresh failures can retain cached rows with an explicit error.

Pickers support keyboard selection, dialogs restore focus, mobile navigation is
inert while closed, and tables scroll within their panel. Recent activity keeps
up to 30 confirmed updates in this session's memory, with local unread state and
accessible announcements. It is not a durable inbox. Gateway auth flows, live data,
persistent notifications and other extensions are tracked in
[deferred work](deferred-work.md). See the [developer guide](developer-guide.md)
for composing another page and [verification](verification.md) for actual checks.

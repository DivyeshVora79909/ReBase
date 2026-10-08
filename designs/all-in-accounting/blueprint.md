# Accounting calculation contract — October 7, extended October 8

The [October 8 extension contract](extension-contract.md) specifies adjustment
notes, tax cash/credit capacity, independent claims, inline charges, exchange
contexts and analytics. Tax account R/P now have intrinsic complete-time zero
floors in addition to the configurable account policies below.

A source record is an authored fact. It can contribute to several accounts and
validator roots. A validator need not post a transaction; a participant need not
impose its own business rule. References describe dependencies, node slots
specify participation, and the existing coordinator settles the affected closure
inside the source transaction.

## Accounts, descriptors and units

| Kind | Tables | Meaning |
|---|---|---|
| Descriptors | `currency`, `measure_unit`, `item`, `service`, `operating_unit` | Typed identity and explicit configuration; no economic postings |
| Monetary accounts | `organization`, `treasury`, `direct_tax_account`, `indirect_tax_account`, `misc_currency_account` | Balances in the required currency |
| Resource accounts | `stock_account`, `misc_stock_account` | Balances in the required item/service unit; also require currency and operating unit |

Every account has `effective_at`, `currency` and `z_history`. Its measures are
independent `real`, `receivable`, `payable`; `net = receivable - payable` and
`available = real - payable` are derived measures. Resource quantity is never
summed into money. Resource accounts in different pricing currencies are separate
positions, not automatically synchronized representations of one physical stock.
An organization record is the commercial account; there is no entity-account or
claim-account wrapper and no compulsory artificial organization for a treasury.
Authorization ownership remains the existing user/group/tenant contract.

Account floors and net limits are explicit settings. Treasury and resource
accounts default to zero real/available floors; resource R/P also default to
zero floors. Organization R/P can be signed: a covered advance appears as a
negative balance in the same claim family until its issue becomes effective.
Adding a nonnegative organization R/P floor is an explicit policy that can
exclude advances. Extrema include the empty zero prefix, so floor settings are
relative to that baseline.

Accounts explicitly participate in `currency.z_accounts` by effective time.
Resource accounts additionally join `item/service.z_accounts`,
`operating_unit.z_accounts`, and the operating unit's unique `z_account_keys`.
The latter key is `[currency, resource]`, giving shared cross-table uniqueness
for `(currency, resource, operating_unit)`, within the tenant. Effective time is
excluded from uniqueness. These indexes carry counts and ordering, not a second
copy of every financial balance. Broader owner/tenant analytics remain opt-in
schema declarations; native authorization/lookup indexes remain in use.

## Transactions and participation

| Record | Account effects | Validators/readers |
|---|---|---|
| `sales_issue` | Stock real decreases; organization R increases | Required sales invoice; own base, quantity and net trees |
| `purchase_issue` | Stock real increases; organization P increases | Required purchase invoice; same source trees |
| `issue_tax`, `issue_net_tax` | Organization claim increases; tax account gets opposite family | Invoice, issue input/net reader, own reversal capacity |
| `invoice_settlement` | Organization claim decreases; treasury real moves in sale/purchase direction | Invoice and own cash/converted-value reversal capacity |
| `issue_return` | Reverses original quantity and value | Source quantity/value capacity; invoice; before/on invoice date |
| `issue_adjustment` | Signed quantity, price or FX correction; quantity changes also reverse/move stock | Same capacities; after invoice date |
| `tax_adjustment` | Explicit signed tax correction in both accounts | Original tax capacity; invoice; after invoice date |
| `adjustment_tax` | Rule-derived tax correction in both accounts | Required correction plus original tax; temporal correction readers |
| `payment_refund`, `payment_adjustment` | Signed reversal/correction of the selected settlement | Settlement capacities, treasury and invoice |
| `payment_withholding` | Transfers the same claim family from organization to direct-tax account | Invoice claim capacity; selected settlement reference |
| `resource_exchange` | Two real movements in explicitly selected account units | Both account histories; optional production-output capacity |
| `account_entry`, `stock_entry` | Explicit real/R/P inputs | Selected account; minimal extension examples |

All monetary conversions have an explicit positive scalar rate with a documented
orientation. An issue price is in the stock account's currency and its rate
converts to organization currency. Settlement amount is in treasury currency and
its rate converts to invoice currency. Taxes convert invoice currency to their
tax account currency. Equal currencies require exactly one. Corrections inherit
the original conversion; they do not silently select a new quote. A resource
exchange rate is destination resource units per source unit, and an identical
resource transfer requires one. Entries and reservations within one account do
not introduce a conversion leg.

Amounts use native decimals. Currency quantization uses nearest, ties to even.
Payments must already fit their treasury currency. Explicit reversal values
must fit their destination currency. Generic account entries retain arbitrary
native decimal precision as an explicit primitive.

## Invoice date and temporal integrity

An invoice has a required organization and `invoice_date`; it may be empty.
Each original issue and tax is on/before that date. A sales invoice admits only
receivable claims; a purchase invoice admits only payable claims. Every child
carries the same derived organization and invoice currency.

For each complete timestamp define cumulative invoice amount `A`, net settlement
`S`, and outstanding `B = A - S`. Amount and settlement totals cannot be negative.
At `invoice_date`, require `B >= 0`. Starting with that closing balance, add the
post-date segment and require its complete-time minimum to stay nonnegative.
This allows a payment before its issue's effective time, but only when authored
issues cover it by the invoice date. A payment-only invoice is invalid even when
its date is in the future. Author the future issue first, then the earlier-dated
advance. Later adjustments cannot hide an earlier overpayment.

No clock-triggered task is needed. The constraint is over authored effective
times. A root's full summary includes future positions; ask for a temporal prefix
to obtain an as-of balance. Equal timestamps are complete buckets, independent
of record-ID ordering.

Returns and `payment_refund` occur on/before `invoice_date`. Issue, tax and payment
adjustments occur after it. A negative `payment_adjustment` returns money after
that boundary; the user explicitly confirmed this naming split. Every reversal
must also follow its source. Each source mutation settles and validates before
the next statement, even inside a transaction: reduce cash settlement before a
price reduction that would otherwise make the invoice overpaid.

## Taxes and corrections

A rule is `round(clamp(basis * rate / 100, lower_bound, upper_bound))`.
`rate` is a percentage, the lower bound defaults to zero, and an absent upper
bound means unbounded. Bounds are nonnegative, ordered and currency-quantized.
See the [tax contract](delivery-taxes.md) for temporal and marginal examples.

A base tax reads the issue's base through its effective timestamp. A net tax
reads all strictly earlier issue-net contributions: base, taxes, returns and
corrections. Two net taxes at the same time are parallel; use distinct effective
times to compound them. A net tax has one required issue parent and no tax
predecessor reference. It never reads a final summary containing itself.

`issue_adjustment` changes exactly one dimension per record. Signed deltas are
marginal changes to the original contract:

- Quantity: `quantity_delta * original_price * original_exchange_rate`.
- Price: `original_quantity * price_delta * original_exchange_rate`.
- FX: `original_quantity * original_price * exchange_rate_delta`.

Negative deltas reverse value; positive deltas are debit corrections. Quantity
changes also adjust physical stock. Each correction's magnitude is bounded by
the original dimension/value, and the source's cumulative quantity and value
cannot fall below zero. These are explicit marginal facts, not an implicit
replacement of the remaining unit price or a compounded rewrite of prior rows.
A return uses its quantity and original price, with optional `entered_amount`
for an explicitly allocated rounding remainder. No epsilon or hidden cent entry
relaxes source capacity.

An `adjustment_tax` requires the correction and original tax. It follows the
original rate, bounds, account and conversion reactively. A base reversal uses
the correction amount. A net reversal adds earlier adjustment taxes of that
correction. It computes the difference between the bounded rule before and after
that basis change; merely taxing the reversal amount would mishandle caps and
minimum fees. A unique correction-time tree on each original tax gives nonlinear
marginal changes an explicit order. The correction must be strictly later than
the original tax, and its tax row cannot precede the correction. This prevents a
same-time base refresh and explicit reversal from counting the same reduction
twice. There is at most one link for each correction/original-tax pair.

The frontend chooses which tax reversals to author. The backend enforces the
links, dimensions, time, formula and source capacity of every row that exists;
it does not generate missing business rows or impose a tax jurisdiction.

## Manufacturing, cash and capacity

A `production` is a dated validator with `starts_at < ends_at`. Its input, output,
cash-cost and capacity rows are independent records, with arbitrary row counts.
They inherit both dates from the parent. Empty/partially authored parents are
permitted; no fixed recipe, status workflow, yield ratio or generated child is
implied. A developer can add explicit yield or material-conservation validators.

| Row | Start position | End position |
|---|---|---|
| `production_input` | Resource payable +quantity, reserving availability | Real -quantity and payable -quantity |
| `production_output` | Resource receivable +quantity | Real +quantity and receivable -quantity |
| `production_cost` | Treasury payable +amount | Treasury real -amount and payable -amount |
| `production_capacity` | Operating capacity used +quantity | Used -quantity |

Gross input demand from all productions at a start timestamp must fit the
resource availability strictly before it. Same-time receipts or outputs cannot
fund their own input, and future receivables are not available stock. Account
prefix floors additionally protect all later movements. A temporal input reader
rechecks later starts when an earlier inventory source changes.

Capacity occupies `[starts_at, ends_at)`. Complete-time extrema allow an adjacent
booking to reuse capacity at exactly the release time. The operating unit's
optional capacity is its explicit upper bound. Resource/service availability and
minimum/maximum duration settings are checked, including subsequent edits.
Production date edits move all child positions atomically and must preserve
output consumption, capacity and availability. An exchange can name a production
output to consume its own remaining dated output capacity as well as stock.

## Adding a table

1. Define a `SCHEMAFULL` record with scalar inputs and typed references.
2. State each measure's unit and each account's perspective.
3. Declare every required root/node pair and return the memberships from one
   ordinary function. Use the common helpers where their units match.
4. Materialize mutable dependency reads one reference hop at a time with
   `@rebase-derived`. For aggregate feedback use a strictly prior temporal reader,
   not the final summary of a contributing tree.
5. Put local constraints in source guards and aggregate constraints in root
   guards. Prove edits, reparenting, backdating, competing writes, deletion and
   rollback against source arithmetic before extending the accepted profile.

The existing [ordered-tree contract](../rebase-system/ordered-tree-contract.md)
defines typed keys, uniqueness, traversal, permissions and mutation boundaries.
A source repair costs the sum of logarithmic affected-tree paths, plus dependent
recalculation. A long affected suffix can still be large. This redesign does not
claim a Rust planner, unlimited graph scalability or measured production capacity.

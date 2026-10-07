# Temporal tax and adjustment contract

Both tax tables have one required `source` issue, a typed direct/indirect tax
account, an effective timestamp, percentage `rate`, lower/upper bounds, and a
positive scalar exchange rate. They inherit the issue's invoice, organization
and currency. They must be on/before its invoice date.

`issue_tax` reads the issue's base through its effective timestamp. Its reader
position is one nanosecond later in the input-only tree, so it includes every
same-time base contribution without depending on record IDs. Its financial
posting retains the entered timestamp.

`issue_net_tax` reads the issue net strictly before its timestamp. Its own
contribution is a temporal reader in that tree. Earlier base/tax/correction edits
invalidate and refresh later readers. Equal-time net taxes see the same prior
basis and do not compound each other.

For base 100, two 9% base taxes at time 2, and a 10% net tax at time 3:
`100 + 9 + 9 = 118`; the net tax is `11.80`. Inserting a 5% base tax at time 2
changes that basis to 123 and recalculates the net tax to `12.30`. There is no
explicit tax-predecessor edge and no read of a final self-containing aggregate.

Rules use `round(clamp(basis * rate / 100, lower_bound, upper_bound))`, with native
decimal ties-to-even rounding. The lower bound defaults to zero and an absent
upper bound is unbounded. Bounds must be ordered and currency-quantized.

## Reversals of bounded rules

An adjustment tax references both an `issue_adjustment`/`issue_return` and the
original tax. For a base tax its basis delta is the correction amount. For a net
tax it additionally includes that correction's strictly earlier adjustment-tax
amounts. Original rate and bound edits recalculate all these dependent rows.

Let `F` be the original rule, `B` the original basis plus prior linked correction
bases, and `delta` this correction's basis. The tax change is `F(B + delta) - F(B)`.
With rate 10%, upper bound 5 and base 100, a reduction of 20 changes no tax:
`F(80) - F(100) = 0`. A later reduction of 40 changes tax by `F(40) - F(80) = -1`.
A nonzero lower bound remains a floor; removing a fixed/minimum charge is an
explicit manual tax adjustment, not an inferred legal rule.

Correction timestamps are unique per original tax so nonlinear marginal changes
have an authored order. Use distinct instants for sequential changes. The
correction must follow the original tax strictly, and its tax row cannot precede
that correction. Otherwise a same-time base-tax refresh could already contain
the reduction being explicitly reversed. A `(correction, original tax)` pair is
also unique. Net adjustment taxes at equal times remain parallel.

Returns and their tax rows are on/before the invoice date; adjustment notes and
their tax rows are after it. The frontend controls which corresponding rows to
create. Existing rows must match their issue, preserve capacity in invoice and
tax-account currencies, and pass every affected invoice/account guard. Optional
explicit converted deltas handle authored currency-rounding remainders.

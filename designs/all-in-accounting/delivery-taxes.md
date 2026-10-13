# Temporal tax and adjustment contract

The [developer guide](developer-guide.md) contains the current equations and
strict reference diagram. `issue_tax` reads issue value through its timestamp;
`issue_net_tax` reads strictly earlier issue value, taxes and adjustments.
Equal-time net taxes do not include each other.

Unified `issue_adjustment` changes the chronological quantity/price state using
the difference between the resulting products. It can occur before or after the
invoice date, but must follow the source issue. Original rules are referenced
by the distinct `issue_adjustment_tax` and `issue_adjustment_net_tax` tables.
Explicit `tax_adjustment` and `net_tax_adjustment` change their respective original
taxes; `tax_adjustment_net_tax` recalculates a selected original net tax after a
base-tax adjustment. Linked children inherit the adjustment note.

Rule-linked changes use `f(B_before + delta_B) - f(B_before)`, including caps,
lower bounds and currency rounding. They do not apply f directly to a negative
delta. The direct original-rule reference propagates rule edits; declared prefix
memberships propagate dated basis edits. A linked change already included in an
original dated basis is rejected to prevent counting it twice.

R/P contributions remain nonnegative. Opposing directions represent reductions;
signed source capacities prevent cumulative over-reversal. The application
chooses and authors the tax graph; the engine does not create missing children.

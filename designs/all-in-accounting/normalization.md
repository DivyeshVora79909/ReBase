# Direct accounting normalization

The active contract is the [October 7 blueprint](blueprint.md). The
[execution record](redesign-2026-10-07.md) supersedes October 5's entity/claim
wrappers, optional issue parents, quote-selected pricing and predecessor taxes.

Each business fact is one explicit native row. An invoice validates; an issue
both contributes and validates. Typed account roots carry independent real,
receivable and payable measures, with resource and currency units kept separate.
Taxes have one issue parent; adjustment taxes have the two required semantic
parents. Production uses ordinary rows with two dated positions, not arrays or
source-owned output recipes. Descriptor indexes do not duplicate ledger totals.

The old recipe directory and commands have been deleted as requested. Historical
acceptance remains tied to its recorded Git/source snapshot. No compatibility
layer or populated database migration is included in this source redesign.

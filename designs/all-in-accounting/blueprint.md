# Accounting calculation contract — October 13

The complete current contract is the [developer guide](developer-guide.md).
It replaces the October 7/8 single-currency organization model and separate
return/refund APIs. The [execution contract](redesign-2026-10-13.md) preserves the
reasoning and scope recovered from the user's final redesign request.

The key distinctions are records, typed references, declared contributions and
root validators. Subsidiaries own reporting roots; organizations own sparse
native currency/resource positions. Issues and other source legs post directly
to their selected native and reporting roots. Invoices and notes validate those
participants without repeating their account contributions.

R/P are nonnegative directional contributions. Outstanding claims are their
difference; signed capacity measures enforce independent linear constraints.
Owned accounts use real movements plus explicitly named reservations. Reporting
currencies, native units and counterparty/subsidiary perspectives remain separate.

A calculation's time semantics determine its dependency rule. Predecessor rate
changes affect a bounded interval; cumulative prefixes generally affect a suffix.
See [function reactivity](../rebase-system/function-reactivity.md). Ordinary
SurrealQL functions implement the calculation and authored impact selector.

The [verification record](verification.md) identifies the tested snapshot.

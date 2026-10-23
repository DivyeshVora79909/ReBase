# G4a: terminal aggregate readers without managed outputs

**Prepared, 2026-10-23.** First checkpoint of the
[capability program](30-capability-program.md).

## Gap and contract

The shared `causal::settle` selects contracts through nonempty output declarations.
A validation-only sum reader therefore never registers or rechecks its aggregate.
Requiring a dummy private output merely to enable validation adds needless model
maintenance.

A contract handled by the shared sum scheduler participates if it declares sum
queries or managed outputs. Specialized latest-quote calculations stay on their
existing path: routing every query into the shared sum resolver would break the
calculation model's Posting.

For pure validators, resolve declared shape/parameters and maintain subscriptions,
but do not call the formula evaluator, allocate output identities or synthesize
derived fields. Evaluate validation reads after all final outputs settle. Keep
validation reads out of calculation edges, including a validator reading its own
contributed root. The current validation rule remains a nonnegative sum; custom
predicates and general windows are separate gates.

Calculation readers without emissions may compute declared derived fields.
Contracts with temporarily inactive outputs keep ordinary calculation semantics.
Disabling/deleting a query removes its old registration. Active empty/zero queries
retain their dependency identity.

## Acceptance

Extend a small native binding with a guard whose aggregate is not protected by
a root invariant. Derive expected queries/sums from sources, never writer state
or cached query results. Check complete snapshots, not only returned numbers.

- Invalid guard creation and later independent negative-prefix edits reject
  with complete state/receipt rollback.
- Valid creation registers a query without allocating private outputs.
- Out-of-prefix contributions and strict equal-time boundaries behave correctly.
- Atomic source repair validates final state regardless of command order.
- Bound/root edits, disable and deletion repair old/new registrations; deleting
  the guard permits a formerly forbidden edit.
- Managed producers settle before terminal checking in the same mutation.
- Replay, reopened integrity checks and stale-version rejection retain normal
  behavior. Invalid controls preserve complete application-table state.

Existing production formulas/query types remain unchanged. No persisted format
change is intended. Identify affected binding semantics and verify unchanged
model identity/store compatibility before acceptance.

Run focused controls, formatting, Clippy, debug/optimized Rust tests and relevant
independent native/local acceptance. Record actual counts and fingerprints.
This gate does not imply provider delivery, distributed storage, arbitrary
aggregates or two-bound reactivity.

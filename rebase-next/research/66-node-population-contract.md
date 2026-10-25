# N3 Node population contract

Status: implementation contract frozen for the N3 Node population module.

`tools/node/population.mjs` exports exactly `preparePopulation`, `propose`,
`accept` and `reject`. It consumes a prepared `prepareModel` handle and its
native developer catalog; it does not start a process, submit an operation, or
compile a schema per row. Native mutation remains the global validator.

Preparation owns public contract metadata, Ajv validators, quotas, caller-supplied
typed pools, seed, explicit clock, strategies/rules, and optional selectors.
Proposals construct ordinary JSON shape first, then select and fill compatible
typed references, then obtain fresh per-row context and apply rules, and finally
validate complete fields. Schemas or `json-schema-faker` may provide base fields;
an explicit strategy is required where generation is unsupported or unsuitable.
No keyword is silently removed to make a schema generatable. Exact rational
strings remain strings. Values outside safe JSON integer range are rejected.

State is caller-owned. One proposal may be pending. Binding is explicit through
write-once `state.pending.plan = plan`: the detached snapshot must match the
proposal's model, command list, returning IDs, and any established target. The
caller saves that plan before submitting it. Its snapshot and digest live in a
closure on a frozen pending record, and both the client and population binding
use the same full private N2 plan validator. `accept` advances quotas, typed
pools, reference usage and attempt cursor only for the exact plan and a verified
committed Node client response with the exact operation ID and ordered returned
IDs. The client response is `{status, result: {operation_id, revision,
records}, ...}`; population checks exactly that one native result wrapper and
does not expect another nested result.

An unbound exact proposal can be cancelled. A bound proposal can be rejected
only for a known native no-commit error; unknown, expired, or not-observed
outcomes retain the pending plan for same-operation reconciliation. Known
rejection advances the attempt cursor to avoid replaying deterministic IDs.
No submission, retry, context refresh, reserve creation, or automatic parent
generation is hidden in these functions.

Selection supports default seeded weighting and explicit selection/skew
callbacks. Typed existing anchors may carry validated projections. Reference
paths support properties and array positions/wildcards, including optional
references and polymorphic target unions. `propose` is awaitable; context,
strategy, selector and rule callbacks may also be asynchronous. Fresh context
callbacks run after reference selection, so a callback can read through its
caller-owned client using selected IDs. It must return an explicit mapping.
Such a read supplies authoring context only; a concurrent mutation may make it
stale and native validation can reject the resulting operation. Per-instance
clock values are supplied by the caller. All callbacks are trusted caller code.

Work is bounded by catalog-declared limits, prepared proposal size and normal
JavaScript output construction. Emitting `n` records necessarily costs at least
O(n); default pool selection indexes retained IDs, while a custom reference
selector currently receives a materialized view of compatible pool rows and
therefore costs O(pool size) time and memory for that edge before its own work.
No constant-time or universal validity claim is made.

Acceptance requires semantic controls and a real Node Equipment and Quantity
workflow covering existing anchors, custom selection/pools, exact values,
invalid/stalled inputs, stale context rejection, and duplicate-advancement
prevention. Native source and Rust build are unchanged for this checkpoint.

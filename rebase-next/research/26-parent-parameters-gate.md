# G3b: explicit authored-parent parameters for pure evaluation

**Accepted 2026-10-22.** [Evidence](evidence/2026-10-22-g3b-parameters.json)
records execution and source identities. This is a native API extension; shipped
model formulas, behavior contracts, store/codec 4 and limits remain unchanged.

## Goal and boundary

Extend the existing native calculation seam so a model can resolve declared
authored parent fields once and pass ordinary typed values into its pure
formula. An invoice/tax producer must not copy mutable tax-rule columns into
every child or make hidden database reads while evaluating. G3a's exact values
are accepted at `16514d9`; this is the next bounded implementation checkpoint.

`ReactiveBinding` owns its `Parameters` type. `resolve` returns
`Resolved<Parameters> { shape, parameters }`; the shared plan retains the bundle
until `evaluate` receives it alongside its resolved query values. Deletions have
no parameter bundle. Neither Serde, storage representation, a universal
parameter map nor a second schema registry is needed. Existing bindings use
`Parameters = ()` and keep their formulas.

All authored commands are staged before resolution, so the bundle observes final
authored values in that transaction attempt. Parameters must be owned values
from declared direct authored inputs, not database handles, parent derived
publications or undeclared multihop lookups. Model code is trusted compiled Rust;
this boundary does not sandbox arbitrary authors or prove a function pure.

Keep `ResolvedShape` responsible for dependency topology. Parameter values cannot
change topology after the final graph has been built. Resolvers can still use
declared authored values to resolve shape before graph construction, as today.
Each binding maintains its existing old/new incoming and direct routes, using
`Reference.direct_fields`. Parent input changes select registered children;
retargeting removes the old registration. This remains parent-level invalidation,
not a new field-by-field reverse index. Do not add duplicate generic registration
alongside existing calculation registrations.

## Acceptance

A test-only native tax model uses a source-derived basis and a directly
referenced rule containing `Rational`/`Rounding`. The real redb path must prove:

- Basis `10005`, parent `1/10`, half-even gives `1000`; editing only the parent
  to `1/5` gives `2001` while preserving private output identity.
- Retargeting changes the rule and removes the old dependency. Both command
  orders of a parent edit plus retarget see the same final authored context.
- A basis source edit exercises ordered-query invalidation with the same typed
  parent bundle. No copied rate fields appear in producer inputs.
- Inexactness, arithmetic overflow, missing/wrong-type references and referenced
  parent deletion reject with complete state/revision/receipt rollback.
- Receipt replay and reopening preserve sources, amounts, queries and roles.

Re-run the existing Rust and independent source/state checks for this shared
interface extension. Verify existing model identities and store/codec bytes stay
unchanged; if shared semantics change, bump every affected behavior contract as
required by `AGENTS.md`. No capacity or distributed claim follows from a new
typed argument.

## Executed result

The shared native extension adds one associated type, one small resolved bundle
and an explicit evaluator argument. There is no new runtime registry, dynamic
query, persisted parameter map or binding-specific transaction engine. The
test-only parameter type deliberately has no Clone/Debug/Default/Serde bounds.

Three native redb tests verify the source-derived arithmetic and complete
`Snapshot::finish` inventory, query, role, route and tree checks. Parent rounding
changes produce `1000 → 1001 → 1000`; a rate change gives `2001`, preserving
output identity. A different parent gives `2501`, then a source edit gives
`2502`. A parent edit that leaves the rounded result equal still retains its
dependency. Editing a detached parent leaves producer/output records untouched
and its old direct registration empty. Four independent stores prove old/new
parent edits plus retargeting in either command order.

Five rejected batches cover inexactness, overflow, missing/wrong-type references
and referenced-parent deletion. Complete observations, revisions and receipts
remain unchanged, no success receipt exists, and the independent checker still
accepts the state. Replay and reopening preserve the accepted result.

All **66 debug and optimized Rust tests**, formatting, warning-denying Clippy,
**116 independent native/local cases**, six client controls and three population
oracle controls pass. Copies of both accepted 4,096-source G2 stores also reopen
and pass their complete integrity checks; the original files are unchanged.
The shipped model identities match G3a exactly. No semantic behavior or storage
revision is needed for unit parameters. This interface change deliberately
replaces the old `shape` hook with `resolve`; no compatibility shim is supplied.

The new numeric primitive and existing scaling algorithms are unchanged, so
their full numerical/population benchmarks were not repeated. The focused
source arithmetic checker is bounded to this test corpus; G3a retains the wider
Fraction evidence. The result does not certify derived/multihop parameters or a
new business model.

## Continuation

After verification, commit and push G3b, then start G3c: a bounded accounting
workflow using these numeric and parameter primitives. Fix its tax order,
correction and settled-payment policy with an independent source oracle before
implementation. Keep arbitrary monoids, multihop/derived parameter dependencies,
general two-bound reads, distributed adapters and frontend as separate gates.

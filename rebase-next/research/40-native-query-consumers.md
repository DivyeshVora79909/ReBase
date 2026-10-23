# G4d-b/c: native statistics and authored selection consumers

**Prepared during G5c final verification, 2026-10-23; not implemented or accepted.**
The [capability program](30-capability-program.md) and the
[published-value gate](36-value-dependencies-gate.md) retain the broader scope.
Continue from the accepted G5c commit on `main`, preserving its executable and
evidence. Do not reopen G4d-a publication semantics or G5's external lifecycle.

## Selected next result

G4d-b adds an output-free `ObservationReport` to the measurement model. It
declares an Instrument, exact `TimeRange`, unit and integer threshold. It
publishes count, optional minimum/maximum, unit, and `at_least_threshold`.
The boolean is **false for an empty window**; otherwise it is
`minimum >= threshold`. No absent minimum is converted to zero. Threshold and
observations must use the declared unit, which must match the Instrument.
Unit codes and values retain the existing measurement bounds.

For unit 7 and literal observations `(time,value) = (0,5), (10,12), (20,-2)`,
window `[0,20)` with threshold 5 yields count 2, minimum 5, maximum 12 and true.
Moving the last observation to time 15 yields count 3, minimum -2, maximum 12
and false. An empty `[10,10)` window yields count 0, absent extrema and false.
Deleting all members keeps the report's query and dependency registration.

The report has no root, member, private output or role reservation. Its
instrument reference supplies reader inheritance and rejects parent deletion.
Declare its use of the Instrument's authored unit explicitly. Retargeting,
window/threshold changes and joint Instrument/report unit changes must use the
final staged state. Materialized reports retain the existing explicit Read
policy; this gate does not add transitive redaction of derived values.

Only authored Observation members enter this gate. They are final after ordinary
staging. Managed statistical emissions, dependencies on a selected record's
published fields and winner-dependent topology need separate readiness proofs.

## Actual shared seams

`NativeIndex` already owns typed keys, leaves and summaries. Its `project`
method returns JSON for public root reads; that wire projection is not an
internal formula value. `causal::ReactiveBinding` still fixes `Index = Standard`
and receives financial `&[i128]`; persisted `native_slice::Query` stores a scalar
result. Measurement currently has authored membership settlement and a complete
source checker, with no reactive report. Those are the boundaries to extend.

Use a strict compiled model/family-owned query-result type and checked operation
identity. Keep JSON at the public boundary. Do not put `Statistics` in a global
core result enum, cast a statistics sum into the financial amount channel, add
a dynamic field-path registry or create a second model-owned reactive loop.
The common causal orchestration should schedule the new output-free consumer;
financial emission/prefix operations must remain explicit capabilities.

The prepared query declaration and persisted query identity must bind the
source/slot, root/operation, exact bounds and native result contract. Decode,
validation, complete observation, independent inventory and restore must use
that same compiled type. Equal results retain query identity and registration.
Old/new rekeys, root moves, payload edits and deletion invalidate every affected
declared window using distinct changed times and original/staged routes.

Stage authored membership changes before evaluating their consumers. Preserve
the existing final graph and publication scheduling for financial models; do
not pretend that an authored-only statistics read establishes managed-emission
readiness. Charge resolution, native reads, candidate visits and scheduling to
the existing work budget. Avoid new limits or a generic query language.

## G4d-b acceptance

Use a small literal source oracle that filters authored observations by exact
bounds and computes count/extrema/threshold with ordinary integers. It must not
read tree summaries, persisted Query results or report derived values to compute
its expected answer.

- Exercise unbounded, one-sided, open/closed and empty windows, negative values,
  equal threshold and all-members-deleted cases. Query identity survives emptiness.
- Revalue, rekey, delete and move members between instruments. Retarget the report
  with parent/member changes in both valid command orders. Include equal-result
  edits, detached roots and an Instrument-only unit edit.
- Reject dimension mismatch, invalid references, parent deletion and bounded
  work exhaustion atomically, including receipt absence and every private table.
- Reconstruct report results and query/routes independently. Corrupt the native
  result tag/binding, bounds, route and derived result; check/startup/restore reject.
- Use ordinary authenticated HTTP for source-derived values, authority, replay,
  reopen and verified restore. Measure zero/one/many report selection within the
  unchanged 64-public-source measurement envelope. No 4,096-source campaign is
  needed for this binding or unchanged financial capacity.

Choose store/codec/API versions from the actual format changes; G5c owns source
0.12 /store 9 /native codec 6 /effect codec 3 /API 3. Bump affected behavior/model
identities, preserve a matching prior binary/store and prove incompatible open
without changed physical bytes. Do not bump unrelated model identities solely
because a shared source file changed. Use one Cargo owner, retained caches,
affected controls and one optimized product workflow.

## G4d-c follows the accepted report

Add a concrete output-free latest-observation consumer only after G4d-b is
accepted. It declares Instrument and exact `at`, returning an optional native
selection `{identity, member_slot, time, unit, value}` at or before that time.
The winner is the greatest complete `(time, UUID, member slot)` key. Duplicate
times are legal; equal payload with a different identity changes the selection.

The dependency domain is the complete declared `(-infinity, at]` window,
including when no candidate exists. Observe insertion of the first candidate,
replacement/deletion of the winner, nonwinner edits, equal-time ties and root
moves through a literal sorted-source oracle. Depending only on the previous
winner is insufficient. Use the same typed query persistence, common scheduler
and original/final invalidation paths established by G4d-b. Authored members are
the entire candidate universe in this gate; do not extend it implicitly.

After these consumers, prepare G6's dated rational FX, sparse contributions and
quantity returns against their concrete model contracts. G7 still requires a
real distributed backend and actual conflict/unknown-commit schedules. G8 remains
an explicit workload/release gate. None is accepted by this preparation paper.

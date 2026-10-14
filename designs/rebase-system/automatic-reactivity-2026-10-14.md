# Automatic dependencies from ordered reads

The October 14 request supersedes developer-authored impact functions. The
developer writes the calculation once; supported reads establish and maintain
their dependencies during its execution. Breaking schema/compiler changes are
authorized. The accepted starting snapshot is `ae10ba8`.

## Meaning recovered from the conversations

- Track a logical query on a root and field, rather than the physical AVL node
  visited during a lookup. Rotations cannot change a dependency's identity.
- A predecessor read watches both the selected value and the gap in which an
  insertion could change that selection. Empty results also need a subscription.
- A cumulative prefix consumes all earlier contributions. A link to the last
  record alone cannot detect an earlier contribution changing that aggregate.
- Subscriptions follow executed branches and helper-function calls. Changing a
  reader's date, parent or branch removes obsolete reads and installs the new ones.
- Native balances, reporting conversions, adjustment products and validators
  retain their existing units and mathematics. Replace their dependency plumbing.
- The coordinator remains synchronous and atomic; this work concerns database
  calculations, rather than the gateway's background effect reconciler.

## Implementation decisions and proof gates

Ordinary SurrealQL functions expose `fn::tree::read_value` and
`fn::record::read_value`. The compiler finds their transitive callers and emits
private instrumented versions for derived calculations, membership providers,
required outputs and validators. Native CREATE helpers use the ordinary pure
versions; the source event evaluates and captures the complete calculation.
Field evaluation still follows its actual dependency graph.

Protected records store one logical read per distinct executed query, its
subscriber/phase, last consumed value, and evaluation generation. Stale reads
are removed at the end of evaluation. Applications do not declare reader slots,
reader trees or inverse impact functions.

The reverse access path uses private AVL memberships for logical query positions.
Native array-based IDs still identify reads/groups and support exact prefix
lookup. The first integer-only ID-range probe passed, but a later dated-accounting
case found a backend ordering gap: a native range omitted `date + 1ns` even
though record-ID value comparison placed it after the lower bound. The final
implementation uses the same typed comparison as the source AVL. This also
avoids inventing separate sortable encodings for decimal or composite keys.

Predecessor/successor invalidation derives neighboring bounds from the repaired
source tree. Prefix reads use the affected suffix; exact reads use their business
key. Entire summaries watch the selected component. Range reads use an internal
AVL interval index, ordered by lower bound and augmented with the maximum upper
bound, so a change can prune past and future intervals. Its tuple key is internal
metadata, not a new untyped application root. Candidate values are compared
before recalculating a subscriber, and rechecked before processing a queued read.

Registration and source mutation share a protected source fence. This is needed
to reject a concurrent insertion of a subscription that an in-flight source
change has not seen. Evaluation metadata belongs to the same transaction and
must also roll back when a formula, permission check or validator rejects.

Validation reads are recorded separately: a validator may inspect its own
contribution, but runs after the affected calculation closure settles. Formula
feedback cycles fail atomically; the engine does not solve fixed-point equations.

The user-facing primitives have known semantics. Ordinary helper functions can
compose them without writing an inverse. Arbitrary SELECTs, dynamic evaluation
and external calls do not become automatically incremental. The compiler must
reject a reachable untracked ordered-tree operation rather than silently lose
its dependency.

## Work and acceptance

- [x] Recover the complete exported chat, prior accounting intent and Git state.
- [x] Probe private event writes, compound record-ID ranges and actual query plans.
- [x] Prove branch-aware capture through functions, empty/predecessor/prefix/range
      reads, exact affected values, date/parent moves, deletion and rotations.
- [x] Prove source/subscriber concurrency, cycle/tenant/permission rejection,
      metadata rollback, populated reapplication and cleanup.
- [x] Integrate the compiler/coordinator and migrate accounting rates,
      projections, adjustments, taxes and production validation.
- [x] Run relevant core regressions and consolidated accounting acceptance.
- [x] Publish the developer contract, record evidence and commit validated work.

Record candidate enumeration, consumed-value changes and actual formula calls
separately. Indexed discovery and affected writes have different costs. Report
interval-index node visits honestly; do not infer an output-linear bound merely
because two endpoint filters exist.

## Accepted result

Fresh consolidated accounting acceptance passed: 103 checkpoints, 51 rollback
snapshots, exact populated reapplication and released subscriptions at cleanup.
The generic proof passed 50 checkpoints and 7 rollbacks; its interval case visited
24 nodes across 68 registered ranges. All 30 developer-tool tests passed, along
with the recorded compiler/runtime/tree checks. See the [verification record](../all-in-accounting/verification.md)
for source fingerprints, timing and exact scope.

The native datetime reproduction returned `{logical:true, scanned:['zero']}`
after creating both source-key and nanosecond records. Reverse positions now
use typed AVL order. Group counts were removed in favor of indexed emptiness
checks. Public summaries retain published aggregate permissions; captured
summaries read current repaired nodes. Derived arrays replace existing values,
and flexible object helpers retain their selected record/key information.

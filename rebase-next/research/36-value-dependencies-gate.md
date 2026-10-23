# G4d: declared published values, then typed query consumers

**G4d-a accepted 2026-10-23, source 0.9.0 / store+codec 6.** The
[dated evidence](evidence/2026-10-23-g4d-published-values.json) records typed
declarations, shared graph/readiness and IssueShare. Invoicing behavior is 5;
calculation, equipment and measurement keep their G4c identities. Their retained
stores pass complete checks, including both 4,096-source stores. The G4c invoicing
store rejects under the new identity with physical bytes unchanged.

The 58 library tests, nine existing invoicing tests and four new IssueShare tests
pass. Six publication controls cover source-derived diamonds/chains, final edge
reversal, mixed cycles, strict slots/native values, and charged budget rejection
with complete rollback. Thirteen small graph cases compare plain adjacency
orders. Five corrupt derived/Direct images reject in check/startup/restore.
The optimized HTTP workflow passes 11 mutations /19 commands (eight commits,
three complete rollbacks), Fraction expectations, materialized-record authority,
replay and crash/reopen/restore. Parent-only and detached-parent changes select
two and one calculations; a parent with eight consumers selects nine, using
173, 233 and 386 work units respectively. These are bounded examples, not a
new capacity limit.

Validation was scoped to changed behavior: no full optimized Rust suite or
population mutation campaign was repeated. Two initial share assertions expected
an internal type tag in public records; the corrected four-test suite passes.
The six publication controls were rerun after adding one budget-exhaustion
injection. Earlier successful library/invoicing results remain retained.
Next is G5a atomic intent. Typed statistics and selection below remain unaccepted.
This paper
narrows [G4d](30-capability-program.md) against the current
[native index port](34-native-index-extension.md),
[`causal.rs`](../src/causal.rs), [`dependency.rs`](../src/dependency.rs) and
the invoicing/measurement bindings. It is a proposed next contract, not evidence
that arbitrary published-parent or native-summary reactivity already works.

**Recommendation:** implement G4d-a below: an invoicing `IssueShare` calculates
an exact fraction of its directly referenced Issue's settled published amount.
It needs no new tree, query algebra or private output. Close that readiness and
invalidation seam, then proceed with [G5a atomic intent](33-external-effects-gate.md).
Richer summary consumers and selection remain separately selected checkpoints.
G5 does not depend on any of them; its
[integration review](35-external-integration-review.md) can proceed independently
if another application for G4d is preferred before implementation.

## Current boundary and choice

[G3b parameters](26-parent-parameters-gate.md) capture final **authored** parent
fields during shape resolution. At that point a changed parent's derived value
may still be old. Putting that value in `Parameters` would freeze the wrong
result before the final graph is scheduled.

The shared scheduler currently receives financial `&[i128]` results, uses the
`Standard` index family and contracts each producer's formula and outputs into
one scheduled step. Calculation's quote/latest path is separate. The current
measurement model maintains authored observations and exposes native statistics
through root reads; it does not run those statistics through this scheduler.
These are distinct established boundaries.

| Candidate | Useful observable result | New obligation and decision |
| --- | --- | --- |
| Direct publication: `IssueShare` | A source edit to an Issue updates its percentage calculation without copying the Issue amount or creating another history root. | Direct producer-to-consumer readiness and invalidation. Select first. |
| Native summary: `ObservationReport` | A declared window publishes count/extrema/unit and a unit-aware threshold result. | Typed query identity/result storage and generic scheduler participation. Prepare separately; a `sum` field does not qualify a statistics result as money. |
| Selection: latest observation | A declared date resolves an optional observation identity and exact value. | Winner replacement, absence dependencies and explicit tie/readiness rules. Defer until its consumer and selection semantics are selected. |

Do not combine these into one universal value engine. A compiled associated type,
ordinary declarations and pure projection functions are sufficient. A global
`serde_json::Value` formula channel, registry of arbitrary field paths, dynamic
expression evaluator or second model-owned settlement loop would obscure the
new dependency contract. Existing native index ownership stays with the selected
family; no publication needs a synthetic one-member index.

## G4d-a: exact percentage of a published Issue

Add one bounded public invoicing source, provisionally named `IssueShare`:

- Authored fields: `issue` reference, exact `ratio`, explicit `rounding`.
  The ratio satisfies `0 <= numerator <= denominator`; use the existing
  canonical `Rational` and `Rounding` operations.
- The declared input is Issue contract 211, publication 101, `amount_minor`.
  Prepare this code/name/type relationship against the parent's publication
  declaration. The input is a published value, not an authored field with the
  same spelling and not the Issue's private capacity output.
- Published fields: `basis_minor` and `amount_minor`, where
  `amount_minor = ratio.apply(basis_minor, rounding)`.
- No root, membership or managed output belongs to the share. It calculates a
  proposed share; it does not post a credit, enforce allocation conservation or
  change the existing Issue, credit, tax, payment or refund formulas.
- Keep invoicing's existing 64-public-source envelope and ordinary mutation
  work budget. Zero ratio still consumes the declared publication and retains
  its registration. There is no missing-parent or missing-publication fallback.

For a concrete fixture, quantity `3/2`, unit price `10001` and half-even rounding
publish Issue amount `15002`. A one-third share with half-even rounding publishes
`basis_minor = 15002`, `amount_minor = 5001`. Updating only the Issue quantity to
`2` publishes `20002` and updates the share to `6667` in the same commit. Reading
the previous `15002` during resolution would incorrectly leave `5001`.

Declare the new share's `issue` reference mutable and `ON DELETE REJECT`.
Retargeting observes the final selected Issue, repairs the reverse registration
and applies reader inheritance through that reference. This is an explicit rule
for the new contract; existing invoicing reference mutability stays as declared.
Retarget plus edits to existing parents must have the same result in either
command order. Existing prerequisite-first creation requirements still apply
when creating referenced sources in one batch.

The first production target is an Issue handled by the shared causal scheduler.
Do not infer that every `PublishedField` in every binding is already a ready
producer: the specialized quote/Posting path needs an explicit publication
boundary before it can be an additional target. Nor may the resolver walk
Issue → Invoice → another record to discover extra values. Any extra read must
be a separately declared direct input.

## Declaration, native value and persistence contract

The implemented publication-input declaration names a source-local input
slot, authored reference slot, published field code and native binding. Target
contracts come from the reference's existing allowed targets; no duplicate
target list is stored. Preparation checks every allowed target. Resolve
only that reference's target identity before graph construction. Validate the
slot/code/type and target contract, tenant, existence and reference policy through
the ordinary prepared model and mutation path.

Keep value delivery small: one model-owned native publication value type and
an owned value associated with its declared input slot. Invoicing can represent
the first value as a typed `IssueAmount` case containing exact minor units.
A trusted projection function receives the already selected, ready parent and
the prepared publication code; it returns the corresponding native value.
`evaluate` receives the resolved publication values alongside its existing
authored parameters and financial query values. It receives no workspace.
Use explicit slot access or a model-owned typed bundle; do not silently bind
values by lexical field order or reinterpret another publication's `i128`.

These publication values are attempt-local, like authored parameter bundles.
They need no Serde bound or new cached query-result row for G4d-a. The source's
existing persisted derived value remains the publication. Its static declaration
and source reference determine dependency identity; do not persist a second copy
of the same amount merely to have a dependency row.

Reuse the existing parent-level `Direct` reverse route. The declaration must
distinguish authored direct fields from published fields, while a single
`(consumer UUID, reference slot)` registration covers either or both uses of
that parent. A reference that also reads authored fields does not create a
duplicate node. Route/header preparation and the complete checker must account
for both declarations. This retains one maintained reverse index rather than
adding a publication-specific shadow subscriber list.

Runtime and developer catalogs derive publication inputs, target codes, native
binding and formula inputs from that declaration. Use the existing
**materialized-record authority** for this gate. `security::write_authority`
loads and checks the current principal scope/credential epoch; the authorization
closure in `local::mutate_inner` checks `scope.can_read` for each newly introduced
reference target before settlement. Creating or retargeting the share follows
that same check. An unchanged reference is explicitly skipped by that check;
internal recalculation does not introduce a second actor-level parent-read gate.

Share `basis_minor` and `amount_minor` are explicitly published fields governed
by Share Read permission and the share's current reader route. The existing
reader selection uses immediate referenced **owners**, not transitive parent
readers. Issue.owner can differ from Issue.reader. Consequently revoking Issue
Read alone does not redact an already published share, and this gate promises
no transitive confidentiality or recursive redaction. Withdrawing Share Read or
access to its reader makes the share unavailable through ordinary reads/pages
and receipt disclosure. No private output enumeration or implicit parent
hydration is added. A stricter visibility intersection would require its own
cross-record projection, pagination and receipt contract.

For this first gate, declared publication inputs are mandatory calculation
inputs. Shape validation must compare the complete resolved input-slot set with
the declaration, reject duplicate/missing slots, and verify that each selected
UUID is the actual target of its declared authored reference. A resolver may not
substitute another same-contract parent or omit a zero-coefficient input. Keep
publication input slots distinct in type from query slots and output roles;
their numeric codes do not imply a shared persisted namespace.

## Discovery before evaluation

The existing initial pass collects `Direct` dependents when an authored parent
input changes. That is insufficient when the parent is recalculated solely
because one of its own query inputs changed.

During closure discovery, every newly planned producer must also discover its
registered publication dependents from the original and staged route views.
Continue until the affected closure is complete, including output-free
calculators selected only through a publication declaration. Reconcile final
registrations before scheduling and retain old registrations long enough to
discover consumers affected by deletion or retargeting.

Do not wait until a parent's new derived value has been evaluated or compared
with its old value to discover these consumers. That would add predecessors
after the graph was fixed and could read a half-settled diamond. Conservative
parent-level discovery is acceptable and must be charged. Equality may avoid an
unchanged final record write; it cannot remove the input registration, original
read protection or final calculation edge.

No whole-store rescan is part of ordinary mutation. Share edits and parent edits
use normal changed records and reverse routes. Bound candidate propagation with
the existing work/population budgets and report any increased affected closure.

## Final readiness and cycles

Extend the existing final graph with an edge **parent calculation step → consumer
calculation step** for every active direct publication input whose parent is in
the affected closure. Keep existing financial prefix/segment gates unchanged.
All edges refer to final authored references and final active shapes. Original
and staged routes are discovery aids; their union is not the scheduling graph.

A parent outside the affected closure supplies its checked settled publication
from the same transaction snapshot. A parent inside it is pending until its
formula and declared outputs have completed. Capture its publication only then,
immediately before the consumer evaluates. An old derived row still present in
the workspace is not a readiness signal; neither is a pending output's temporary
absence a settled zero.

This checkpoint keeps the current atomic calculation step as its scheduling
unit. It does not promise field-by-field scheduling within one record. Reject
self-dependencies and all final cycles, including mixed paths through published
values and financial roots, and cycles whose formulas happen to multiply by
zero. An explicit chain of separately declared direct inputs can be checked by
the shared graph; this is different from following undeclared multihop reads.
The first IssueShare schema only targets Issue, so a small native test binding
must exercise chains, diamonds and feedback that this production schema cannot
express.

Published values cannot choose the consumer's root, query bound, reference,
output activation or emission time during evaluation. Those remain resolved
from final authored data before scheduling. Ordered-result-dependent topology
would need a separate stratification or dynamic-shape contract; no retry-until-
stable solver is introduced here. Terminal validations still run after all
calculations and have no outgoing calculation edges.

## Concrete integration seams and bounded work

`causal::uses_sum_scheduler` currently admits only contracts with managed outputs
or sum queries. Extend that admission through the explicit publication-input
declaration so IssueShare participates without inventing a query or output.
Do not admit every contract with `PublishedField`: Posting/quote evaluation
still belongs to a separate established path. Retain terminal-only sum readers
and calculation declarations whose currently active query/output lists are empty.

`binding::headers`, the invoicing `registrations` function and source-derived
integrity inventories must agree when a referenced target needs `Key::Direct`.
The exact registration remains `(consumer UUID, reference slot)` even when that
reference contributes several publication inputs or authored fields. Extend
the existing set construction rather than independently inserting one node per
field. `routes::collect` already visits original and staged views. Invoke it
once for each newly planned live/deleted producer during closure discovery;
duplicate candidate UUIDs remain deduplicated by `pending` and `plans`.
Collecting authored-only dependents conservatively through this shared route is
permitted, but only published inputs add readiness edges.

`dependency::Graph::build` already allocates one vertex per planned live source,
including output-free readers. Build one UUID-to-vertex map and add the final
publication edges through its existing charged `edge` function. Several inputs
from the same parent require one readiness edge but still deliver their distinct
declared values. Preserve the current topological ordering and prefix/segment
gates; do not scan all producer pairs for publication edges.

The evaluation loop's `Plan.record` is a pre-evaluation clone and can contain
stale derived fields. Resolve the pinned parent through the current workspace
immediately before evaluating its consumer, after confirming any planned parent
has completed its scheduled step. Never project publication data from a parent's
cached Plan record, captured authored parameters or original snapshot if that
parent is pending. A same-attempt newly created parent initially lacks a derived
value; that is pending work, not a default publication.

Charge each resolved input check, projection and candidate visit using existing
work accounting. A map lookup/edge per declared publication input is sufficient;
one large parent's fanout still costs every selected consumer. Exercise both a
bounded successful cascade and an exhausted-budget attempt with whole-state
rollback. Unchanged derived results retain all declarations/routes/graph edges,
while ordinary version repair may omit an unchanged final record write.

## G4d-a acceptance and compatibility

Use a literal source oracle with Python integers/Fraction or equivalent exact
arithmetic, plus a plain adjacency list for publication and pairwise financial
dependencies. It must not read writer query caches, parent derived values,
compressed dependency gates or tree summaries to compute its expected results.

1. Run the fixture's `15002 → 20002` parent and `5001 → 6667` share change through
   authenticated mutation and ordinary record reads. Reopen, replay and verified
   restore retain the values, source/public indexes and complete inventories.
2. Exercise parent quantity/price/rounding edits, share ratio/rounding edits,
   retarget, deletion, zero ratio and an equal-result parent edit. Verify the
   detached parent cannot select the share; the new parent can. Check both
   command orders of valid existing-parent edit/retarget repairs.
3. In a small native binding, change only an aggregate source to dirty a parent
   whose authored input did not change. Propagate through two publication
   consumers and a join. Enumerate all valid topological orders and compare
   final values. Keep a wrong-old-value control that demonstrably disagrees.
4. Compare a valid edge reversal against the cyclic old/new union; accept the
   final DAG. Reject self, direct, mixed root/publication and zero-coefficient
   feedback. Include an output-free publication consumer and an authored-only
   direct dependency so the two kinds are not conflated.
5. Reject missing/wrong-contract parents, nonexistent publication codes,
   incompatible native projection, inexact rounding, genuine arithmetic overflow,
   denied authority and deletion with surviving references. Compare all
   application tables, revisions and receipt absence after each rejection.
6. Independently derive expected publication routes, declarations and derived
   values. Corrupt missing/orphan/misbound direct registrations and stale derived
   results; startup/check/restore must reject. Measure zero/one/many dependent
   selection and a mixed aggregate/publication cascade within unchanged budgets.
7. Give a non-admin reader access to both Issue and IssueShare, then remove only
   Issue Read while retaining Share Read and the same reader reachability.
   Issue read becomes unavailable, the previously published share remains
   readable, and a fresh share create/retarget to that Issue rejects under the
   ordinary new-reference check. Remove Share Read next; record/page access and
   replay disclosure stop exposing the share. Keep admin authority available to
   perform these graph edits. This confirms the selected materialized-output
   policy instead of asserting transitive redaction.

IssueShare's constrained ratio should not overflow a valid positive Issue by
itself; overflow and mixed-cycle controls belong in the deliberately broader
test binding. Do not manufacture an unreachable production overflow example.
No role reservation, output identity or dummy query row should appear for a
share. Record the exact inventory rather than accepting equal returned numbers.

Bump invoicing's behavior/model identity for the new source and dependency
semantics. Audit every other affected shared behavior as required by
[`AGENTS.md`](../AGENTS.md). Reusing unchanged Direct node bytes can avoid a
physical codec change, but this must be demonstrated by the final implementation;
static model metadata may still change prepared identities. If any persisted
envelope or meaning changes, assign the next format version at that checkpoint.
Preserve a matching pre-change binary/store and verify explicit incompatible
open with bytes unchanged. Do not silently migrate a populated store or borrow
G5's provisional version number. G5's identity decision follows the actually
accepted predecessor.

## Subsequent candidates: decisions not supplied by G4d-a

**Typed statistics consumer.** A useful G4d-b candidate is an output-free
`ObservationReport` in measurement: an authored instrument, exact `TimeRange`,
unit and threshold publish count/min/max/unit and whether a nonempty window
stays above that threshold. An empty result has zero count and absent extrema;
it must have an explicitly chosen false/unknown threshold policy, never an
invented minimum of zero. Choose the policy before implementation.

Its query identity includes source/root/slot/operation, exact bounds and the
native result contract. Same-root revalue/rekey/deletion and root moves stab
every distinct old/new changed time against original/staged registrations.
Equal results and empty windows retain active query identity. The source oracle
scans literal authored observations and checks dimensions and threshold units.

This requires replacing or extending the current persisted scalar `Query.result`
and checker inventories with a strict model/family-owned native result type.
It also requires deliberate scheduler participation beyond
`ReactiveBinding<Index = Standard>`. Keep optimized financial scalar reads
explicit. First scope this to authored observation members: their values and
positions are final after staging. Reactive consumption of managed statistics
contributions needs declared generic emissions and exact final producer coverage
before it can claim the same readiness. Do not cast a statistics sum to the
financial amount channel or add `Statistics` to a global core result enum.

**Selection consumer.** A later concrete candidate is latest authored observation
at or before an exact date, returning `Option<{identity, time, unit, value}>`.
Absence is a result and dependency, so insertion of a first candidate must select
the consumer. A conservative initial invalidation domain is the entire declared
`(-infinity, at]` window: old/new rekeys, root moves, payload edits and deletion
inside it can change the result. Depending only on the old winning identity
misses a new winner. Equal payload with a different selected identity is still
a changed selection result.

Measurement allows duplicate times. Before adding this operation, choose and
publish its tie policy, such as greatest complete `(time, UUID, member slot)`,
with a literal sorted-source oracle. Financial complete-time aggregation and
existing unique-time quote selection keep their established meanings.
The first proposed selector reads authored observations, not unresolved managed
candidates or the selected record's derived fields. Extending selection to
managed candidates requires readiness over every possible final candidate in
the declared search domain, or another proved policy; waiting for the old winner
alone is unsound. Winner-dependent topology, arbitrary predicates and selected-
parent publication chains remain separate choices.

G4d-a can close one real value-dependency gap without deciding either candidate's
result wire or policy. Preserve that boundary in its evidence and continuation.

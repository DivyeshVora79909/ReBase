# Declarative calculation engine: design and execution

Prepared October 16, 2026 against clean commit `cc7b98d`. This is the execution
record for the requested redesign. Checkboxes below describe completion, not
intent. Earlier acceptance remains evidence for its original revision.

## Objective and recovered intent

ReBase should make a large space of business calculations expressible with a
small, stable set of concepts. Optimize the cost of understanding, changing and
proving a design over its lifetime. A short implementation is useful only if it
also has clear ownership, explicit dependencies and predictable work.

The October 16 discussion supersedes the earlier request for dependencies
discovered while arbitrary helper functions execute. The accepted trade is a
fixed number of dependency declarations per strict record type. Sources and
bounds may change with a record's inputs; the schema owns the possible slots.
Breaking changes are acceptable for this undeployed prototype. No compatibility
engine or data migration is required.

Preserve the accounting model as a demanding example of composition. It is a
calculation engine, with explicit facts, dimensions and constraints, rather than
a prescribed compliance workflow. Other applications should use the same
primitives without inheriting accounting concepts.

The attachment graph was followed through eleven accessible files, ten unique
contents, including the original system proposal, tenant/tree continuation,
accounting redesign, reactivity discussion and integrity campaign. The downloaded
architecture discussion is byte-identical to its attached copy. Three older
references name `Pasted text(10).txt`, `(7)` and `(5)` without a resolvable path;
those names were not found in the attachment or Downloads directories. Their
surrounding discussions and the reachable continuation chain supply the relevant
intent. Prior agents' diagnosis and recommendations are hypotheses; current
source and executable results determine implementation choices.

## The model

| Primitive | Author supplies | Engine supplies |
| --- | --- | --- |
| Record | Strict fields and typed references | Tenant boundaries, authorization and audit |
| Ordered membership | Owner, slot, key and contribution | Balanced ordering, rank, range and maintained summaries |
| Calculation | Pure `VALUE` expressions and ordinary helpers | Actual local dependency order and protected results |
| Dependency | A typed reference or a named logical ordered query | Reverse discovery and synchronous propagation |
| Invariant | A condition over the resulting state | Transaction rollback when the condition fails |

A record can own roots, contribute through several slots, validate aggregates,
and calculate values. These roles are independent. A reference does not enroll a
record in a tree. An index does not grant permission to its members. An invoice
can validate its participating issues and payments without posting them twice.

The source of truth is authored records and their formulas. Tree links, summaries,
dependency indexes and transaction revisions are maintained state. Formulas are
pure; a useful indexed database is not literally stateless.

## Mathematics and boundaries

For an ordered contribution sequence, a summary is a monoid: an identity and an
associative combination. Associativity permits rotations to regroup subtrees
without changing the result; commutativity is unnecessary and generally false.

For scalar deltas, retain `(sum, minimum_prefix, maximum_prefix)` and combine:

```
sum(A ++ B) = sum(A) + sum(B)
min_prefix(A ++ B) = min(min_prefix(A), sum(A) + min_prefix(B))
max_prefix(A ++ B) = max(max_prefix(A), sum(A) + max_prefix(B))
```

The existing complete-timestamp extrema additionally preserve the distinction
between record order and the state after all contributions at one timestamp.
Keep their exact decimal algebra and independent oracle.

For a fixed-coefficient linear constraint `a*x(t) + b*y(t) >= c`, contribute
`a*dx + b*dy` to one maintained measure and check its complete-time minimum
against `c`, accounting for the initial balance. An equality requires both
minimum and maximum. Separate minima cannot be subtracted. Changing a coefficient
changes the contributions and requires their recalculation; this is not an
automatic constant-time solver for arbitrary nonlinear expressions.

Range aggregation is the main query. Prefix is `[NONE, upper)` and the whole
tree is `[NONE, NONE)`. An unbounded range returns the maintained root summary;
finite ranges combine covered subtrees. Keep useful public shorthand without
separate maintenance protocols. Predecessor, successor and exact-key selection
remain distinct operations because selection is not aggregation.

All bounds use the tree's typed comparator. `NONE` is an unbounded endpoint,
not a large numeric sentinel. Preserve nanoseconds, decimals and complete
record-ID/slot tie breaking. A partial timestamp key precedes all full keys at
that timestamp. The last quote at or before a datetime is selected before
`[datetime + 1ns]`.

## Dependency contract

A schema declares named query descriptors as fields. Each declaration specifies
an operation and allowed source roots; its pure `VALUE` supplies the source,
bounds, consumed path and optional fallback. A calculation reads that descriptor
through one pure value function. Helpers can compose descriptors and arithmetic.
The query is declared once and shared with inverse indexing.

Direct typed reference expressions remain simple: `$this.rule.rate`. The compiler
infers ordinary one-hop dependencies, with explicit declarations for dependencies
hidden by helper calls. Materialize multiple reference hops as ordinary derived
fields when necessary. Reject opaque local row flows instead of guessing an
evaluation order.

There is one generated node slot per declared ordered dependency on the business
record. Corresponding roots live on its source owner. They share the existing AVL
implementation and may contain readers from several tables. There are no separate
subscription records, evaluation generations, capture buffers or private copies
of application helpers. Identical bounds on two named slots must remain distinct;
financial coalescing must not merge dependency roles.

Range dependencies use an interval augmentation: order by lower bound and
maintain the maximum upper bound, including positive infinity. Expose interval
stabbing as a reusable tree operation. Predecessor/successor/exact dependencies
use ordered point indexes. A reader retains the source series and query bounds,
not a pointer to whichever historical source leaf happened to answer its query.

Record metadata on a query's owner may affect its fallback or interpretation.
Owner input changes therefore conservatively reconsider its declared readers.
Index maintenance alone must not trigger this notification. A calculation can
declare a finite superset of possible reads; automatic branch-sensitive discovery
is deliberately removed. Arbitrary undeclared database reads in a stored formula
are not promised reactive semantics.

Validation dependencies use the same descriptor/index contract but are evaluated
at the validation boundary. Validators over their own changed roots need no
reverse subscription: every changed owner is already validated. A validator over
another root declares that query. Validation does not recursively feed a record's
own contribution back into its calculation.

## Transaction protocol

1. The synchronous database event enters the coordinator with the old row image.
2. For a moving prefix consumer, remove its old contribution first. Settle affected
   predecessors before calculating at the new position. Cached old slots remain
   authoritative; dereferencing an old business reference reads its new state.
3. Evaluate pure descriptors and derived fields in actual dependency order.
4. Fence the declared source records, then reconcile fixed dependency slots at an
   explicit boundary. Do not mutate reverse trees inside arithmetic expressions.
5. Repair business memberships and reconcile required outputs in dependency order.
6. Discover affected readers from old and new positions. Recalculate synchronously;
   unchanged derived values and contributions stop ordinary downstream work.
7. Publish resulting roots, propagate direct publications, then run all affected
   validators. Any failure rolls back the whole initiating transaction.

This is an event-driven cascade, not a global scheduler or fixed-point solver.
Diamonds may revisit a record. Count actual evaluations in cost claims. Every
individual statement retains its final validation boundary, including statements
inside a client transaction; do not claim that intermediate `VALUE` checks vanish.

A fixed reverse index still needs concurrency control. Consider quantity zero:
changing its rate may leave the amount zero while another transaction changes
quantity. If neither transaction writes a shared source fence, both can commit a
stale amount. Every evaluation fences its declared sources, including unchanged
queries and inferred direct references. Keep the revision on the source record,
without a separate lock table. A confirmed transaction conflict is retried as a
whole by the caller. A timeout is not proof that a transaction failed.

Keep direct dependency-cycle rejection and an active calculation path for actual
ordered feedback. Typed table structure alone does not prove the runtime graph
acyclic. Keep same-tenant checks, source existence checks, root deletion guards,
protected generated fields and complete rollback evidence.

## Cost model

Let `n_s` be members in a particular source tree, `r_s` its indexed dependency
slots, `k_s` candidate slots and `F(v)` the work in a record's formulas.

| Work | Bound or interpretation |
| --- | --- |
| Repair one balanced membership | `O(log n_s)` |
| Read a finite segment or predecessor | `O(log n_s)` |
| Read the complete aggregate | `O(1)` from the maintained summary |
| Report point-index matches | `O(log r_s + k_s)` plus source boundary lookup |
| Report intervals with maximum-end pruning | Conservative `O((k_s + 1) log r_s)`; also bounded by index size |
| Recalculate a candidate | `F(v)` plus its changed business/dependency memberships |
| Complete cascade | Sum of discovery, calculation and repair work over actual evaluations |

`O((r + 1) m log n)` is a useful uniform approximation for membership work,
not the cost of every operation and not a unique-record guarantee. Avoid claiming
`O(log n)` for reporting or updating an unbounded number of matches. Slot count
is schema-bounded; application constraints can bound fan-out and depth when a
particular domain needs it. Do not build a speculative global quota framework.

## Index and platform policy

Use explicit rooted, cross-table trees for business uniqueness, analytics and
ordered/interval lookup. Preserve native references and reverse references for
graph traversal. Inventory ordinary table-field indexes before replacing them;
auth, queue, delivery and lifecycle constraints retain their established contracts.
No claim is made that every native database index can be replaced by an AVL or
that generic `SELECT ORDER BY` will use a custom root automatically.

SurrealDB remains the transactional engine. The Node runtime continues to handle
external effects. Keep tenant identity, credentials, authorization DAGs, scalar
`read_by`, provider adapters, queues, audit and explicit required outputs. Do not
introduce a new database, application framework, scheduler or frontend rewrite.

## Execution and gates

- [x] Recover the intent and recursive context; inspect clean Git state, current
  source and retained failures. Baseline: SurrealDB 3.3.0; all 56 developer tests
  passed at `cc7b98d`.
- [x] Prove the shared range/interval algebra, including unbounded endpoints,
  coincident keys, missing measures and invalid bounds.
- [x] Implement the fixed dependency contract, compiler diagnostics and generated
  source/root/slot inventory. Preserve pure helpers and local topological order.
- [x] Replace dynamic capture with explicit reconciliation and source fences.
  Prove rekey, reparent, deletion, fallback, diamonds, cycles and rollback in a
  disposable native database before migrating the full accounting profile.
- [x] Convert all-in-accounting and all-in-one ordered formulas. Preserve all
  source arithmetic, units, effective-time rules, tax/adjustment dependencies,
  same-time production constraints and managed-output behavior.
- [x] Retire obsolete runtime capture tables, instrumentation and maintained
  probes. Replace their useful behavioral coverage with static-slot oracles;
  retain historical evidence as history, with no compatibility implementation.
- [x] Provide a generated dependency explanation and one current developer guide
  teaching the primitives, linear invariants, queries and cost boundaries.
- [x] Run compiler/unit checks, focused native and seeded dependency histories,
  structural cost checks, typed/boundary trees, full accounting and output gates.
  Check rebuild/freshness, SurrealQL validation, source-only inventory, permission
  boundaries, populated schema reapplication and child-first cleanup.
- [x] Review the final diff and documentation against actual results. Record the
  implemented contract, exact verification and any unresolved gate explicitly.

The acceptance oracle must derive desired dependencies from authored source
facts, not merely trust the maintained index. Removing a slot with otherwise
self-consistent tree links must fail verification. Inspect after every mutation,
not only at the end of a history. Preserve full before/after snapshots for
rejected writes and minimized reproductions for any newly found defect.

Execution is authorized by the current request. A failed proof changes the design
or implementation; it does not justify presenting an unverified replacement as
finished. No publication, remote push or live-database deployment is part of this
work.

The [current verification record](declarative-engine-verification.md) and
[retained manifest](evidence/2026-10-16-declarative-engine.json) collect completed
results, command output and source revision boundaries. Full accounting acceptance
passed 103 checkpoints and 54 rollback snapshots, including populated reapplication
and cleanup. The 65-table schema has 138 declared queries. Its generated SQL is
11,183,330 bytes; no schema-size or throughput improvement is claimed. All
broad-regression components passed across the documented initial run and its
successful continuation; 54 developer tests passed. The numeric-demo comparator
adapter preserves exact accounting equality and has focused native/unit evidence.
No implementation or acceptance gate remains open for this replacement.

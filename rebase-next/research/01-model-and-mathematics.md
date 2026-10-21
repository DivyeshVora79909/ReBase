# Records, ordered projections and calculation integrity

**Status:** semantic research proposal, 2026-10-21. Existing contracts supply the
model; the Rust proof checks a small part of its mathematics. Source routes are
in [sources.md](sources.md). This paper defines meaning before choosing storage.

## 1. A compact model

Let a record have stable identity `r`, a contract `c`, authored values `x`, and
protected calculated values `y`. A contract fixes the allowed fields and roles.
The active roles of a particular record are a sparse subset of allowed roles.

| Primitive | Identity / declaration | Obligation |
| --- | --- | --- |
| Record | Stable UUID; compact contract code | Satisfy strict inputs, immutable dimensions and access rules |
| Reference | `(record, field)` → typed target | Existence, target contract, tenant and link/delete policy |
| Root | `(record, root slot)` | Typed order, permitted member contracts, summary and publication policy |
| Membership | `(source record, member slot)` → root | Key, contribution, tags, activation and uniqueness |
| Calculation | `(record, calculated field)` | Pure function of declared inputs |
| Query dependency | `(record, query slot)` | Source root, operation, typed bounds, channel and fallback |
| Invariant | Named predicate over settled state | Reject the containing mutation if false |
| Effect intent | Stable execution identity | Request external work from committed state |

The structural address `(source UUID, slot code)` can identify a separately stored
index node. It is part of the same fact's projection, not another user-created fact.
Several projections can change without rewriting a large payload or changing its
identity. Root headers may also be separate physical keys under their owner/slot.

Schema selection must remain unambiguous after creation, even if every optional
membership is disabled. Inferring a contract from a populated invoice history
would confuse an invoice, payment and correction. An explicit contract code is a
small reliable starting point. Higher-level compositions can be flattened at model
load; conflicting field/rule definitions fail there.

This explains the star-schema intuition: one fact references several dimensions,
while only chosen dimensions contribute to particular projections. A reference is
information; a membership is participation. An invoice may own and validate roots
without contributing those totals upward. Subsidiary reporting and native account
positions use selected contributions with explicitly different units/perspectives.
Real, receivable and payable remain independent; net is receivable minus payable.
Reporting currency conversion uses directed event-time rates and explicit rounding.
The engine does not infer ledger entries, inverse exchange rates or compliance.

## 2. Which graph is a tree?

There are several independent relations:

- The **principal graph** is the dynamic tenant-scoped DAG for control/sharing.
- The **contract graph** describes possible typed relations and can contain cycles.
- Each **index instance** is a balanced tree over membership occurrences.
- The **active calculation graph** must admit causal evaluation order.

A source contributing to two roots creates a diamond in the participation diagram;
it does not make either tree's balance topology a DAG. Tree parent pointers supply
search structure, not ownership or inherited permissions. Static type cycles do
not imply legal calculation feedback. The runtime should reject active feedback;
general fixed-point solving is outside the intended model.

## 3. Ordering and occurrence semantics

An index compares a declared typed business tuple, followed by source ID and slot:

`key = (business components..., source UUID, member slot)`.

The suffix supplies total deterministic order. Root uniqueness, when required,
applies to the business tuple before that suffix. Key width and number of slots
are independent quantities. Root partition metadata can identify tenant, reader,
contract and index without repeating them in every comparison key.

Bounds use the same comparator as the tree. A range is `[lower, upper)` with
explicit negative/positive infinity. A partial tuple precedes its extensions.
Nanosecond time boundaries and decimal comparisons cannot pass through JavaScript
floating-point values. A pure time root supplies chronological constraints; a
composite partitioned root supplies lexicographic constraints inside its partition.

The new [wireframe](07-contract-wireframes.md#5-queries-order-scope-and-budget)
proposes typed boundaries before/after a prefix for inclusive-time and composite
queries. Do not implement an upper boundary by incrementing the maximum timestamp
or inventing a greatest UUID/string. Exact boundary encoding is a research gate.

Coincident business contributions from one source/root/key may be coalesced when
the declaration means one net fact. Choose a stable declared representative slot.
Independent occurrences remain distinct. Query dependencies and interval slots
must never be merged just because bounds match. Counts then mean maintained
occurrences, not automatically distinct business records.

## 4. Why augmentation works

For a sequence `S`, let its bounded summary be `h(S)`. Require an identity `e` and
an ordered associative operation `⊕` such that:

`h(A ++ B) = h(A) ⊕ h(B)` and `h([]) = e`.

Associativity makes tree rotations preserve the answer. Commutativity is usually
false because history order matters. Invertibility is unnecessary: range summaries
fold complete subtrees and boundary pieces in order. Subtracting prefix minima or
maxima cannot reconstruct a range's extrema.

For scalar deltas, with the empty prefix included:

```
sum(A ++ B) = sum(A) + sum(B)
min_prefix(A ++ B) = min(min_prefix(A), sum(A) + min_prefix(B))
max_prefix(A ++ B) = max(max_prefix(A), sum(A) + max_prefix(B))
```

Counts provide rank/select. Rank of a value depends on that tree's order: median
amount requires an amount-ordered membership; median date is a different answer.
Average needs a meaningful sum and the matching contribution count. Ordinal labels
provide order, not automatically a valid numerical average. Exact uniform tags
can preserve dimensions; missing tags require an explicit presence obligation.

## 5. Complete-time boundaries are a separate algebra

When several deltas share a time, some rules concern the state after the entire
instant, rather than after each arbitrary ID tie. Preserve both policies.

For a nonempty segment retain its first/last time, sum, record-prefix extrema and
optional extrema of **internal completed-time boundaries**. An internal boundary
is a prefix ending before another strictly later time in that segment.
When joining ordered segments `A` and `B`, internal candidates are:

```
A.internal_boundaries
A.sum + B.internal_boundaries
A.sum, only if A.last_time < B.first_time
```

Do not include `A.sum` when the split lies inside the same time. Missing internal
boundaries stay absent. Whole complete-time extrema are the extrema of `0`, total
sum and those candidates. Missing numeric channels are zero contributions but
still preserve chronology and its internal boundaries.

This is associative on ordered segments because its summary describes precisely
the same completed boundaries of the concatenated sequence, independent of split.
The proof checks regroupings against a scan that aggregates all equal-time deltas.

For example, a same-time release `-100` followed by acquisition `+100` has
record-prefix minimum `-100` but complete-time minimum `0`. Moving acquisition to
a later instant creates a real deficit. Choose the correct policy in the invariant;
do not use complete-time guards to relax a strictly causal calculation.

## 6. Linear constraints and exact arithmetic

For fixed coefficients and dimensionally compatible histories, project each event
into `d = a*dx + b*dy`. Maintain `d` as its own summary. To require
`initial + a*x(t) + b*y(t) >= limit` at all complete times, check its corresponding
minimum. Equality over time requires both minimum and maximum to equal the target.

`min(x - y)` is not `min(x) - min(y)`. For events `dx=[10,0,10]` and
`dy=[0,15,0]`, the final difference is `5`, but the intermediate difference is
`-5`; both individual histories have minimum `0`. A shared difference measure
preserves the information the rule needs.

Coefficients/rates that change require recalculating affected contributions.
Arbitrary nonlinear functions, large distinct sets and all possible linear systems
do not acquire a constant-width summary automatically. A domain rule is eligible
only when its summary preserves all necessary information.

The proof uses checked `i128` scaled units. Production must choose a declared scale,
rounding and range, or a suitably bounded exact decimal/rational implementation.
Rounding each source leg and rounding a combined total differ; declare the point.
An overflow is an input/operation failure, not a wrapped or approximate amount.
The algebra is over mathematical integers; checked machine arithmetic is a partial
implementation. Associativity applies where all needed subsegment sums fit. A
conservative absolute-contribution bound ensures this across tree regroupings;
otherwise a different grouping can overflow even when the final total fits.

## 7. Two kinds of dependent reads

Direct dependencies consume a particular referenced field. Reverse routes locate
consumers, and field-sensitive invalidation avoids unrelated work. A root-dependent
query consumes a logical series and bounds, not the leaf that answered last time.

The fixed descriptor vocabulary is `range`, `latest`, `next`, `exact`, plus source,
bound arguments, projection/channel and fallback. Calculation and validation
phases use the same descriptor mechanism with different settlement timing.

Rate selection at time `t` can change after a historical insert, rekey or delete.
Affected predecessor readers lie from the changed key to the next selection boundary.
Moves union old/new intervals; deletion reopens fallback gaps. Prefix consumers
often require refreshing a suffix. Arbitrary windows require interval overlap or
stabbing discovery; augmenting maximum upper endpoints permits pruning.
Endpoint/bound changes are semantic changes even when a numeric channel stays equal.

Local field ordering uses declared dependencies, never naming order. The bounded
[M3/M5 contract](09-causal-settlement.md) resolves active slots, roots, keys and
bounds from authored facts and an acyclic direct-scalar graph before ordered
arithmetic. Arbitrary ordered-result-dependent shape remains a separate gate.
Use old/new routes to discover affected work, but evaluate and reject cycles
against the **final** active calculation graph. A valid move can reverse an edge;
the old/new union can be cyclic even when both states are individually valid.

Remove obsolete contributions of the affected closure, including managed outputs
of tree-less readers. Remaining final contributors may be unresolved; temporary
absence is not a settled zero. Readiness belongs to the consumed interval/channel,
not one undifferentiated root: a prefix can be ready before its later members.
Coalesce repeated notifications only when inputs are ready. Incremental diamonds
may require another evaluation if a consumed input changes later. The frozen
five-step experiment agrees in every valid order; that does not establish that
every record in a general runtime is evaluated exactly once.

## 8. Honest work bounds

Let `E` count actual evaluations, `m_e` changed memberships per evaluation, `n_s`
members in a touched root, `q_s` summary width, `D` discovery work, and `G` graph/
reader repairs. A useful accounting of work is:

`D + G + Σ_e [formula_cost(e) + Σ_s q_s*log(n_s)] + validation + I/O`.

The familiar `O(r*m*log n)` is a shorthand under fixed-width/bounded formula
assumptions with `r` actual reactive evaluations. A large suffix needs proportional
work. Point dependency discovery can be `O(log R + candidates)`; maximum-end
interval trees have a conservative output-sensitive bound, capped by index size.

Materialized DAG reachability can occupy `Θ(V²)` pairs. Joining two long chains
through one edge can create `Θ(V²)` new reachable pairs; an explicit representation
must write those pairs. Sparse average storage cannot give universal logarithmic
edge edits. AVL insertion/deletion also has bounded-height paths; insertion may
need one local rebalance, while deletion can propagate rebalancing up the path.
Neither means every complete business mutation requires only three writes.

The purpose of Rust/workspace redesign is lower constants, less repeated work and
smaller dirty bytes with precise semantics. It cannot remove required consequences.

Verification has a different cost boundary. The
[M6 contract](10-independent-checker.md) derives expected populations from source
facts and scans each subtree's leaves independently of maintained caches. Those
bounded audit costs must not be advertised as mutation costs; a complete logical
inventory and a valid balanced shape are separate obligations.

# Automatic dependencies from ordered reads

Write the calculation once. `fn::tree::read_value` and
`fn::record::read_value` establish dependencies when a stored formula,
membership provider, required-output recipe or validator executes them. Ordinary
helper functions can compose these reads. There is no source impact function,
application reader slot or inverse formula to maintain.

The October 14 implementation replaces the October 13 authored-impact API.
`@rebase-impact` is rejected at compile time. Earlier impact evidence describes
that historical implementation; it does not verify this one.

## A dated-rate example

```surql
DEFINE FUNCTION fn::example::rate_at($pair: record, $at: datetime) {
    LET $rate = fn::tree::read_value($pair, 'z_rates', 'latest',
        [[$at + 1ns]], 'measures.rate.sum', NONE);
    RETURN IF $rate = NONE
        THEN fn::record::read_value($pair, 'initial_rate', NONE)
        ELSE $rate END;
} PERMISSIONS FULL;

DEFINE FIELD rate ON line TYPE decimal
VALUE fn::example::rate_at($this.pair, $this.effective_at)
COMMENT '@rebase-derived';
```

The compiler discovers that `rate_at` uses a tracked read and emits a private
instrumented helper. The public helper remains pure. During refresh, the private
helper records the logical tree query and its consumed value. Only the empty
branch records an initial-rate dependency.

Changing a quote repairs its source tree, finds the next surviving quote and
looks up subscriptions between those ordered positions. The engine compares
actual consumed values before refreshing a subscriber. Insertion, deletion,
moving a quote and changing the reader's pair/date follow the same protocol.
Rotations do not change a subscription: it watches a logical query, rather than
an AVL ancestor or the previously selected physical node.

## Read operations

The signature is:

```surql
fn::tree::read_value(owner, slot, operation, arguments, path, fallback)
fn::record::read_value(record, path, fallback)
```

`path` names the consumed component, for example `measures.quantity.sum`,
`measures.balance.instant_min` or `tags.currency.uniform`. An empty tree path
consumes the entire result. Record paths select a business field; physical node
storage and an entire record are not tracked record-field reads. A root path
such as `z_history.summary.measures.amount.sum` becomes a tree-summary read.
Public computed fields are observed again when their roots publish.

| Operation | Arguments | Automatic discovery |
| --- | --- | --- |
| `latest` | `[boundary, inclusive?]` | Changed position through its next surviving source position |
| `next` | `[boundary, inclusive?]` | Previous surviving source position through the changed position |
| `before` | `boundary` | Subscription positions at or after the changed position |
| `range` | `[lower, upper]` | Intervals containing the changed position |
| `exact` | Complete business key | Reads of that business key |
| `summary` | `[]` | Reads of the changed summary component |
| Record field | Field path | Subscribers of that source field |

Boundary values are arrays using the root's declared key types. Source order is
business components, canonical record ID, then slot. `before` is strict;
`range` is lower inclusive and upper exclusive. `latest`/`next` default to strict
comparison of the complete ordered key; their optional Boolean enables equality
with a complete key. A partial `[date]` sorts before full keys at that date.
For the last rate **at or before** a nanosecond-resolution date, use
`latest([date + 1ns])`. This also gives deterministic handling of ties.

`latest`, `next` and `exact` expose `record` and `key` as well as the selected
leaf's measures/tags/spans. Read `record` to store its identity, `key` to store
its effective position, or the empty path to receive both. A stored selection
can use a flexible derived object; no links to every historical contributor are
needed. A returned record ID alone does not replace the ordering subscription.

## What the transaction does

1. Evaluate fields in their actual dependency order and capture executed reads,
   including nested helper calls. Duplicate identical reads share a subscription.
2. Repair source memberships using cached old contributions. For a moving
   contribution that reads its own tree, remove its former position and settle
   affected predecessors before evaluating it at the new position.
3. Use the changed measure/tag/span and old/new positions to discover candidate
   subscriptions. Compare consumed values and recheck queued candidates before
   refreshing their subscribers. Unchanged outputs stop ordinary downstream work.
4. Publish settled roots, refresh their dependent publications, then run final
   validators. Validation subscriptions are separate from calculation subscriptions.
5. Remove reads from branches and dates that are no longer used.

Calculations and validators execute in the source transaction. Rejected writes
restore subscriptions, evaluation generations and source fences along with the
business records, roots and audit rows. Active calculation feedback throws
`REBASE_READ_CYCLE`; cyclic equations are not solved as fixed points.

Native CREATE helpers evaluate the ordinary pure formulas. The private source
event captures the complete calculation. Derived arrays are replaced rather
than appended; flexible objects preserve their selected record/key data.
Ordinary application queries do not register subscriptions. Public summary reads
retain published-root permissions, including aggregates with private members;
private captured summary reads see the current transaction's repaired nodes.

## Indexes and cost

Four protected tables hold logical reads, shared groups, evaluation generations
and source fences. A distinct executed query has one read record and one private index node.
Point reads use the ordered subscription index; ranges use the interval index. Both registration and source mutation touch the
same source fence, preventing a concurrently registered reader from committing
an unseen stale value. A transaction conflict requires the caller to retry the
whole confirmed failed transaction.

Point subscriptions use a private AVL ordered by the complete typed query
position. General ranges use a second AVL ordered by lower bounds and augmented
with maximum upper bounds. Both reuse the source tree's comparison semantics;
expired and future interval subtrees can be pruned without scanning all readers.
Array-based record IDs identify subscriptions and groups. Native prefix scans
are used only for exact group enumeration and bounded emptiness checks.

A native SurrealDB 3.3.0 experiment found that the logical record-ID comparison
orders a `date + 1ns` after the corresponding full source key, while a native
record-ID range beginning at that source key omits the nanosecond record. A full
accounting oracle caught the missing same-date rate reader. The reverse index
therefore uses typed AVL comparisons instead of assuming the storage encoding
preserves all datetime, decimal and composite-key ordering.

Point discovery targets `O(log N + log R + k)` index/tree work for a source root,
where `k` is candidate logical reads. Each candidate still pays for its actual
query, commonly `O(log N)`, and changed subscribers pay for their full formulas
and postings. Union, ordering, metadata writes and result materialization have
additional costs. Interval traversal is output-sensitive; a conservative bound
is `O((k + 1) log R)`, rather than an unproved output-linear claim.

The developer must use supported reads for mutable dependencies hidden in a
helper. Arbitrary SELECTs, external calls and dynamic function names are not
automatically recorded. A reachable raw ordered lookup in a calculation is
rejected; use `read_value`. Ordinary one-hop typed field dependencies and
`@rebase-depends` remain available for explicit record-field calculations.

## Executable proof

Run `npm run probe:observed-reads`. The [fixture](../../dev-tools/temporal-tree/observed-fixture.surql)
and [probe](../../dev-tools/temporal-tree/observed-probe.js) cover nested and duplicate
reads, inactive branches, empty results, ties, moves, prefix adjustments,
interval pruning, publications, tenant/record permissions, rollback, forced
concurrent registration, reapplication and cleanup. Accounting has a separate
source arithmetic and [subscription oracle](../../dev-tools/temporal-tree/read-oracle.js).
See its [verification record](../all-in-accounting/verification.md) for acceptance
of the exact accounting schema.

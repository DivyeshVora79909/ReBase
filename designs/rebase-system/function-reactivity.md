# Declared queries and pure calculations

ReBase has a fixed dependency graph vocabulary: typed references and named
ordered queries. The schema fixes the number of possible query slots on a
record. Its inputs choose each slot's source, bounds, projection and fallback.
A disabled descriptor returns `NONE`. Ordinary helpers remain ordinary pure
functions; running a helper does not discover or register new dependencies.

This contract replaces the October 14–15 dynamic capture implementation. The
[design and execution plan](declarative-engine-plan.md) records the rationale,
transaction protocol, cost model and acceptance gates. SurrealDB 3.3.0 is pinned
in the repository.

## Author a query once

```surql
DEFINE FIELD OVERWRITE q_price ON line TYPE option<object> FLEXIBLE
VALUE {
    source: $this.curve,
    arguments: [[$this.at]],
    path: 'measures.amount.sum',
    fallback: 0dec
}
COMMENT '@rebase-dependency latest @rebase-dependency-source curve.z_points';

DEFINE FIELD OVERWRITE price ON line TYPE decimal
VALUE fn::dependency::value($this.q_price)
COMMENT '@rebase-derived';
```

`curve.z_points` must be a declared root, and `line.curve` is a normal typed
`REFERENCE`. The compiler resolves `q_price` before `price`, regardless of the
lexical ordering of those names. The query field becomes private and protected.
The value accessor returns its stored result; it performs no lookup or write.

A pure helper may construct the descriptor. Its allowed sources and operation
remain on the field declaration. Multiple `@rebase-dependency-source` annotations
allow a finite union of roots with matching key types. If two allowed roots
belong to the same table, supply `slot` in the descriptor to disambiguate them.
An active source must exist. Public initial evaluation rejects unreadable roots;
a missing source is not an empty tree. Validators can read their own newly
created root without an external descriptor.

A typed expression such as `$this.rule.rate` establishes a one-hop direct
reference dependency. For a read hidden in a helper, declare its path with
`@rebase-depends rule.rate` on the calculated field. Materialize multiple mutable
reference hops as separate derived fields. Immutable dimensions may be read
inside pure helpers. Arbitrary `SELECT` expressions are not analyzed into reverse
routes: the author must expose mutable dependencies through this contract.

## Four operations

| Operation | `arguments` | Result before projecting `path` |
| --- | --- | --- |
| `range` | `[lower, upper]` | Aggregate of keys in `[lower, upper)` |
| `latest` | `[key, inclusive?]` | Last member below the key, or at it when inclusive |
| `next` | `[key, inclusive?]` | First member above the key, or at it when inclusive |
| `exact` | Complete business key | First member with that logical business key |

For `range`, `NONE` is an unbounded endpoint. Prefix is `[NONE, upper]`; the
whole series is `[NONE, NONE]`. Reversed or equal finite bounds describe an
empty range. The public `fn::tree::read_value` still offers `before` and `summary`
conveniences for interactive queries; stored formulas declare canonical ranges.

A key is an array using the root's typed comparator. Partial keys sort before
full keys that share their prefix. Physical keys append the source record ID
and slot, so a full key can divide ties. A datetime-only boundary excludes every
member at that datetime. Select a quote at or before `at` with
`arguments: [[at + 1ns]]`. No conversion to JavaScript milliseconds is involved.

Selection returns the member summary plus `record` and `key`. `path: ''`
consumes the complete result; `path: 'measures.rate.sum'` consumes that measure.
A missing projected value uses the fallback. Query identity is the named field:
two identical queries in different fields retain separate slots. Neither their
phase nor their role is lost through financial contribution coalescing.

## Calculation and validation are separate boundaries

A query normally runs during calculation. Add `@rebase-dependency-validate` for
an external query used only by an invariant. For example, production checks the
available stock before its start and the gross reservations at the same instant.
Those descriptors refresh after all contribution repairs and root publication.
Calculated fields cannot consume validation-phase descriptors.

An invariant over its own root can read `$row.z_history.summary` or call a public
ordered read with `$row.id`. Local reads may be forwarded through declared
helpers. External ordered reads in validators must be named dependencies;
external mutable scalar facts should be materialized through typed derived fields.

`@rebase-validate fn::...` rolls back the initiating transaction on failure.
Within a client transaction, each statement still settles and validates before
the next statement. Keep statement order valid. Delete children before sources,
one record at a time, so intrusive neighbours remain available during repair.

Derived fields, query constructors, membership providers, required-output
recipes and invariants must be read-only. The compiler rejects writes, HTTP/API
calls, scripting, dynamic custom calls and unavailable helpers in these paths.
A whole local row may be forwarded to a declared helper with static field
access; opaque aliases and dynamic local field dependencies are rejected.
Application write functions remain separate entry points.

## Maintained state and transaction order

The business record stores the descriptor and one generated
`__rebase_dependency_<field>` node. Source owners hold the corresponding
`__rebase_dependents_<root>_<operation>` roots. These are ordinary typed AVL slots
using the shared tree implementation. Range slots use interval maximum-end
augmentation; selection slots use ordered query positions. There are no dynamic
subscription tables, capture buffers, generation rows or cloned application helpers.

1. Remove the former contribution of a moving prefix consumer and settle affected
   predecessors before evaluating its new position.
2. Calculate descriptors and fields in dependency order.
3. Fence declared source records, including unchanged results, then reconcile
   query slots at an explicit boundary.
4. Repair business memberships and required outputs. Locate affected readers
   from old and new positions, filtered by the consumed channel.
5. Recalculate candidates whose consumed values changed. Owner metadata changes
   conservatively reconsider readers, including fallback and effective-date rules.
6. Publish roots, propagate direct publications, then refresh validation queries
   and run invariants. Any failure rolls back records, indexes, fences and audit.

`rebase_dependency_revision` on source records provides a shared write for
concurrent evaluations. A source edit that leaves an amount zero must still
conflict with a concurrent quantity edit. Retry a confirmed transaction conflict
as a whole transaction. A timeout is not evidence that a transaction rolled back.

The coordinator follows synchronous database events; it is not a fixed-point
solver. Active ordered feedback raises `REBASE_CALCULATION_CYCLE`. Direct
reference cycles also remain invalid. Diamonds can revisit a calculation, so
costs count actual evaluations rather than distinct records.

## Work and inspection

For one source tree with `n` members and `r` reverse slots, membership repair and
ordered reads use balanced paths. Point-index discovery costs `O(log r + k)` for
`k` candidates. Interval discovery with maximum-end pruning has a conservative
`O((k + 1) log r)` bound, capped by index size. Each candidate still pays for its
query, formula and changed memberships. Metadata edits can reconsider all of a
source's readers. A large affected suffix entails proportionate work.

A full public range reads the published root summary in constant time. Finite
ranges and predecessor selection read covered subtrees and boundary paths.
Publication permissions belong to the root; a summary does not become the sum
of just the caller's visible leaves. Dependency slots do not grant business access.

```bash
node dev-tools/compiler/cli.js --project designs/all-in-accounting --explain issue_adjustment.amount_delta
npm run build:all-in-accounting
```

`--explain` reads current source and writes no files. It shows local inputs,
evaluation order, relevant queries, source roots, private slots and direct
reference routes. Each build writes `dependency-plan.json`; check mode verifies
its freshness alongside the SQL. In the workbench use
`explain('issue_adjustment.amount_delta')`. The API exports `explain(subject, options)`.

## Executable evidence

- `npm run probe:dependencies`: exact source arithmetic and complete business/
  reverse AVL structure after mutations, seeded histories, duplicate roles,
  empty intervals, moves, fallback, diamonds, feedback rejection, concurrency,
  private fields, populated reapplication and cleanup.
- `npm run probe:intervals`: unbounded range and interval endpoint semantics.
- `npm run probe:dependency-cost`: bounded structural work and consumed-channel
  filtering; these measurements are not production throughput claims.
- `npm run verify:accounting`: full accounting and extension scenarios with an
  independent exact-decimal oracle, rollback snapshots, reapplication and cleanup.

The independent [dependency oracle](../../dev-tools/temporal-tree/dependency-oracle.js)
receives expected queries derived from source facts and schema roles. It does
not infer the expected inventory from maintained descriptor fields. Missing
slots therefore fail even when the remaining links form a consistent tree.

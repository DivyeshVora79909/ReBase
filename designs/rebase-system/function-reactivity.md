# Function calculations and authored impact ranges

A stored formula explains how to calculate a value. Its impact rule explains
which records might need that calculation again. Use ordinary SurrealQL functions
for both. There is no expression interpreter or automatic recording of every
tree node a function visits.

Use `@rebase-derived` for the formula and `@rebase-impact fn::name` on the source
table. The source function receives `(before: option<object>, after:
option<object>)`; `NONE` represents creation/deletion. Return an array of ranges:

```surql
RETURN [{
    owner: { rid: $pair, slot: 'z_readers' },
    lower: [$changed_at],
    upper: IF $next_at = NONE THEN NONE ELSE [$next_at] END
}];
```

Each range is **lower inclusive, upper exclusive**. `NONE` is unbounded. Bounds
use the root's typed business key, including leading composite-key prefixes.
Equal bounds select nothing; reversed or incorrectly typed bounds are errors.
The root must exist and belong to the source's authorization tenant.

The target records declare normal node slots in that reader root. One slot
represents one logical read position, not one link to every contribution or to
the physical AVL node that currently contains a summary. No additional registry
table is needed. Membership repair automatically handles a reader's date or
reference changes. An impact rule may return ranges on several roots.

The coordinator selects these members after synchronizing the changed source's
memberships. It combines overlapping candidates, preserves key order, refreshes
their stored formulas and repairs only changed membership values. Direct field
dependents still refresh only when their consumed fields change. The work settles
and validates within the source transaction. A rejected downstream validator
rolls back the source, formulas, memberships and aggregates together.

Root publication also invokes its root record's impact rule with the before/after
published images. Such a rule can inspect the particular changed measures. A
source's cached old slots describe its old contributions; dereferencing an old
record reference after an edit does not recover the old target's contents.

## Choose a correct inverse for the calculation

| Calculation | Safe impact |
|---|---|
| Current parent field | Existing typed-reference dependency and `@rebase-depends` when the read is hidden in a function |
| Last dated value at or before `t` | From the changed date through the next dated value, excluding that next date |
| Initial fallback before the first dated value | Unbounded start through the first dated value, excluding it |
| Cumulative sum before `t` | All readers after the changed contribution; the next contribution does not cancel its effect |
| Bounded range or conditional formula | An authored conservative selector covering every possibly changed result |
| Published entire-root aggregate | Existing summary dependency, or an explicit root impact rule |

For a moved/reparented dated value, return the union of the old and new ranges.
Use the repaired tree to find each next surviving value. This also handles a
deleted value: the predecessor now supplies the gap left behind. For same-time
rate reads, `seek([date + 1ns], reverse=true, inclusive=false)` selects the last
value at or before that date; the rate root uses unique timestamps.

A rule may select extra candidates. It must never omit a record whose result
could change. Returning `[]` for a label-only change is valid; bounding an
arbitrary cumulative formula at the next input is not. Arbitrary impact-function
correctness cannot be proven by the compiler. Keep the function beside its
calculation and test them against the same independent source oracle.

## Ordering and cycles

Local fields are evaluated by their actual dependency graph. The impact ranges
order candidate records by their reader keys. Direct reference cascades retain
their existing dependency semantics. A record selected through several ranges
is evaluated once in that impact batch; a later distinct causal change can
legitimately schedule it again.

Keep same-tree cumulative feedback on the existing prefix-member protocol
(`fn::tree::member(..., true)`). It enforces forward causal contributions and
rejects topology changes during a sweep. The new contract is useful for separate
input and reader trees, such as dated exchange rates and valued transactions.
It does not turn arbitrary cyclic equations into a fixed-point solver. A direct
or impact cascade revisiting its active record path throws `REBASE_IMPACT_CYCLE`.
Do not design a publication cycle between aggregate roots; published dependencies
must remain acyclic as before.

## Cost and evidence

`fn::tree::affected` uses prefix counts and one rank seek, followed by the selected
range's `next` links. For `R` registrations and `k` candidate slots, the number of
tree-node reads is `O(log R + k)`. Materializing, sorting and deduplicating several
ranges also consumes CPU/memory proportional to their returned candidates (and
sorting work). It is not a claim that all interpreter work is linear.

Each formula then pays for its own queries, typically `O(log N)`. Only changed
contributions require AVL repairs. If `r` outputs change and they each participate
in a fixed number of trees, that repair work is proportional to `r` logarithmic
paths. No method can update `r` independently persisted changed values without
work proportional to `r`. Unchanged output does not propagate to ordinary direct
dependents, but evaluating a candidate can still be necessary to discover that.

The [small fixture](../../dev-tools/temporal-tree/impact-fixture.surql) and
[executable probe](../../dev-tools/temporal-tree/impact-probe.js) verify predecessor
selection, exact candidate sets, output-change suppression, date/pair moves,
deletion/fallback, invalid ranges, tenant boundaries, cycles, rollback,
reapplication and cleanup. Its visit counters exist only in the disposable probe.

```bash
node dev-tools/temporal-tree/impact-probe.js
```

This is source-statement coordination, not a transaction-wide change queue.
Several statements in an explicit transaction still settle their intermediate
guards. Automatic cancellation of arbitrary batched changes and general interval
subscription synthesis are not introduced by this contract.

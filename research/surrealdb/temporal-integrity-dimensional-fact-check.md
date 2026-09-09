# Temporal Integrity And Dimensional Fact Check

Status: measured engine behavior plus explicit design consequences
Last reviewed: 2026-09-04

This note is the evidence boundary for the expanded calculation suite. It
answers the engine questions that affect mutable reactive records, historical
corrections, state lanes, and multi-dimensional aggregates. It does not claim
that a measured behavior is a portable guarantee across every SurrealDB
release.

The existing baseline notes remain useful for narrower topics:

- [`schema-temporal-fact-check.md`](./schema-temporal-fact-check.md) records
  catalog, view, time-group, and statistics probes.
- [`reference-permission-performance.md`](./reference-permission-performance.md)
  records the on-disk authorization/reference benchmark.
- [`surreal_db_internals_architecture.md`](./surreal_db_internals_architecture.md)
  records storage and execution internals.

For the Accounts-specific follow-up on writable position anchors, view
read-only behavior, movement concurrency, and bounded replay, see
[`accounts-transaction-concurrency-fact-check.md`](./accounts-transaction-concurrency-fact-check.md).

## Executive findings

| Question | Finding | Classification |
| --- | --- | --- |
| Can a record user ask whether an arbitrary table exists? | No safe generic API. `type::table()` is a cast; catalog inspection is privileged. | Measured / adopted |
| Does a nested `SELECT` break a transaction? | No. It runs in the current transaction and a later `THROW` rolls the write back. | Measured |
| Can a guard use `SELECT` and then always return `true`? | That only proves the query did not error. It does not prove existence, visibility, or cardinality. | Measured / rejected |
| Do grouped materialized views follow dereferenced parent-field edits? | Not by themselves. Direct-source changes trigger maintenance; parent changes need an explicit reverse invalidation path. | Measured / adopted |
| Can a current total prove every historical balance was valid? | No. An ordered prefix can be invalid even when the final total is positive. | Measured / mathematical consequence |
| Are SQL window functions a native escape hatch? | The tested running-sum syntax did not parse, and grouped views do not provide arbitrary ordered prefix state. | Measured / rejected |
| Can changefeeds enforce a synchronous invariant? | No. They expose committed changes after the fact and cannot be nested in an event/ASSERT. | Measured / adopted for repair only |
| Do polymorphic record references work? | Yes, `record<item | service>` and `record::tb()` worked in the pinned probe. | Measured / adopted with explicit branches |
| Do draft/archive rows need to participate in the calculation graph? | No. Separate lanes can be inert, but an unreferenced typed ID is only provenance and may dangle. | Measured / adopted with a boundary |
| Does adding dimensions create a full Cartesian cube? | No. Grouped materialized views are sparse over observed tuples, but each additional view still adds write/storage cost. | Measured / adopted |

## Probe environment and reproducibility

The disposable probes used an on-disk RocksDB store; no `mem://` datastore was
used for the performance or temporal measurements. The local binary currently
available in this workspace is:

```text
/tmp/surreal version
3.2.4+20260803.93ab219 for linux on x86_64
node --version
v18.19.1
```

The package declares Node 20 or newer. The Node 18 value above is a local probe
limitation, not a supported CI target. An earlier baseline run was recorded on
SurrealDB 3.2.0 with Node 22; upgrade-sensitive assertions must be rerun with
the exact binary used by CI and deployment.

Every probe follows the same shape:

1. start a disposable SurrealDB process against a temporary on-disk directory;
2. define only the tables and views needed by the assertion;
3. issue one or more parameterized queries through the SDK;
4. inspect the final statement result explicitly (`response.at(-1)` when the
   SDK returns a statement array);
5. stop the process and remove the temporary store.

The checked-in `architecture-probe.js`,
`reference-permission-performance.js`, and the queries documented in
`schema-temporal-fact-check.md` are the reproducible starting points. A probe
report must include the binary version, storage mode, schema text, data shape,
and whether the result was measured, documented, or only proposed.

## 1. Catalog, table existence, and guards

### 1.1 `type::table()` does not inspect the catalog

The expression below returns a table value for both known and unknown names:

```surql
type::table($name)
```

It is a cast. It is not a `table::exists` function. A dynamic query behaves
differently depending on the input and caller:

| Operation | Existing table | Existing but hidden rows | Missing table |
| --- | --- | --- | --- |
| `SELECT ... FROM type::table($name)` | rows allowed by policy | `[]` | query error |
| `record::exists($id)` | `true` when visible | `false` to the record caller | `false` |
| privileged `INFO FOR DB` | catalog entry | catalog entry | no entry |

`INFO FOR DB` is an IAM-protected catalog operation. It is appropriate for a
startup/migration connection checking a static profile, not for a record user's
business guard. A caller must never be able to choose a table or record target
and turn it into executable SurrealQL.

### 1.2 A nested `SELECT` remains transactional

The disposable transaction probe created a row, ran a nested query, then
threw. The created row was absent afterward. This establishes:

```text
write -> nested SELECT -> THROW
```

does not commit the write or break the transaction. A query in an ASSERT can be
used for a business cardinality check, but it must compare the result:

```surql
LET $candidate = $value;
array::len((SELECT VALUE id FROM parent WHERE id = $candidate)) > 0
```

An empty result and an invisible result are intentionally indistinguishable to
a record caller. That is useful for authorization, but it is not a catalog
existence test.

### 1.3 Nested scopes rebind `$this`

Inside a subquery, `$this` refers to the inner row. Capture the outer identity
before entering the query:

```surql
LET $outer_id = $this.id;
LET $children = (SELECT VALUE id FROM child WHERE parent = $outer_id);
```

This is a correctness requirement for generated `e_*` guards and reverse
invalidation events. A guard that accidentally compares an inner `$this` can
accept a wrong parent or reject an unrelated row.

### Adopted catalog boundary

- Compiler/profile validation owns the set of legal table, field, view, and
  action identifiers.
- A privileged startup or migration probe uses `INFO FOR DB` to verify that
  the compiled set exists.
- Record sessions receive generated capability metadata; they do not receive
  generic table introspection.
- A cron or frontend selector stores a descriptor key, never a raw table name.

## 2. Reactive views and synchronous guard invalidation

### 2.1 What the materialized view mechanism does well

The tested grouped views updated immediately when a direct source row was
created, changed, moved to another group, or deleted. `sum`, `mean`, `min`,
`max`, `variance`, and `stddev` were accepted in the pinned aggregate-view
probe. A final group disappeared when its final source row was deleted.

This matches the ReBase model:

```text
a_* source write
  -> d_* VALUE fields
  -> direct-source v_* maintenance
  -> synchronous system_ping
  -> dependent d_*/e_* recalculation
```

The read of an existing aggregate is cheap relative to scanning all source
rows. The write is not free: every affected group, index, reverse reference,
and synchronous dependent adds maintenance work and possible contention.

### 2.2 Parent dereferences are not dependency declarations

A view such as:

```surql
SELECT time::group(order.a_order_date, 'month') AS month,
       math::sum(amount) AS total
FROM order_line
GROUP BY month;
```

is directly sourced from `order_line`. Updating `order.a_order_date` did not
move the line between buckets in the probe. A record reference provides
topology and delete behavior; it does not automatically make every field
reachable through that reference a view dependency.

There are two equivalent repairs within the reactive model:

1. Store the needed parent values as direct `d_*` shadows on the source row and
   generate a reverse-reference event when the parent field changes.
2. Generate a precise reverse fan-out event that pings each dependent source
   row, causing its value fields and source views to recalculate.

Both `$before` and `$after` keys must be invalidated on a move, update, or
delete. The event must compare the declared dependency fields so an unrelated
parent edit does not fan out to every child.

### 2.3 Derived record fields need a separate compiler category

The combined test/CRM/accounts compile probe failed on:

```text
Reader field sl.d4_item must declare REFERENCE
```

`sl.d4_item` is a machine-derived `VALUE TYPE record<item>` shadow. The current
analyzer treats every record-typed field as an authorization reader/reference
edge. That is too broad:

- authoritative relationship fields need existence, delete action, and reader
  propagation according to their declaration;
- a derived record shadow may be a calculation key only and must not silently
  create a new reader edge or require native `REFERENCE`;
- a derived link that intentionally participates in reverse maintenance must
  opt in with an explicit dependency/reference marker.

This distinction is a compiler fix and a required regression contract before
the all-in-one profile can compile.

### Adopted reactivity rule

Every cross-record expression that affects a guard or an aggregate must be
either:

- represented by a direct, persisted `d_*` shadow with a generated reverse
  invalidation edge; or
- declared with a validated dependency marker that the compiler can turn into
  the same reverse path.

Silently relying on a multi-hop dereference is rejected because it produces
stale but plausible numbers.

## 3. Historical integrity under mutable edits

### 3.1 The measured counterexample

A temporary `txn` table contained one account's effective-time facts:

| Effective time | Amount | Running balance |
| --- | ---: | ---: |
| day 1 | +100 | 100 |
| day 2 | -90 | 10 |
| day 3 | +100 | 110 |

The current total was `110`. Updating the first row from `+100` to `+80` made
the day-2 prefix invalid under the probe's policy and the synchronous event
threw `TEMPORAL_NEGATIVE`. The update rolled back and the original row
remained unchanged.

This proves exact historical-prefix validation is possible synchronously, but
only by reading/folding the affected ordered partition (or an equivalent
summary index). A positive current total is not evidence that every earlier
prefix was valid.

### 3.2 What the engine does not provide natively

The tested syntax:

```surql
math::sum(amount) OVER PARTITION BY account ORDER BY effective_at
```

did not parse. A materialized `GROUP BY` view with an `ORDER BY` clause did not
provide a running prefix either. Therefore the universal first implementation
cannot promise O(1) historical validation from a normal aggregate view.

### 3.3 A current row cannot reconstruct overwritten history

If an old mutable row is overwritten and no prior value was retained, the
database has no information with which to determine the old balance path. No
query-language trick, current aggregate, or changefeed retention setting can
recover data that was never stored.

This is an information boundary, not a performance preference. A table that
needs historical validity must select one of these policies:

| Policy | Stored material | Write behavior | Suitable for |
| --- | --- | --- | --- |
| `current` | current source rows and derived views only | cheap local guards; late edits may change past interpretation | CRM, dashboards, exploratory calculations |
| `validated_history` | generated before/after revisions or correction facts plus ordered key | synchronous replay of an affected partition, with a bounded budget | balances, stock, attendance where past prefixes matter |
| `snapshot_report` | periodic snapshots/checkpoints and source rows | report as-of snapshots; repair can replay from a checkpoint | large reporting partitions |
| `segment_summary` (future) | block summaries `{total, minimum_prefix}` and a tree of blocks | logarithmic/block-level validation after a benchmarked specialization | very hot, very large ledgers |

`segment_summary` is mathematically attractive because summaries compose:

```text
total = left.total + right.total
minimum_prefix = min(left.minimum_prefix,
                     left.total + right.minimum_prefix)
```

SurrealDB does not expose this as a generic incremental window primitive. It is
a later generated specialization, not a hidden promise of every table.

### 3.4 Recommended temporal contract

For a table marked `validated_history`, the compiler generates:

- `effective_at` (business ordering) and `recorded_at` (write ordering);
- a deterministic tie-break (`id` or a revision sequence);
- a partition key (account, employee, warehouse/item, and so on);
- a revision/history row containing the `$before` snapshot before an edit;
- a synchronous validator that replays the affected suffix or checkpoint;
- a maximum synchronous work budget and an explicit `needs_rebuild` outcome;
- a bounded repair job for imports, late writes, and interrupted rebuilds.

If the budget is exceeded, the write must either be rejected or enter an
explicit pending-repair lane. It must not silently claim that historical
integrity was checked. Changefeeds can feed the repair path, but they do not
replace the revision source.

## 4. Changefeeds, audit, and repair

The changefeed probe used:

```surql
DEFINE TABLE t SCHEMAFULL CHANGEFEED 1h INCLUDE ORIGINAL;
SHOW CHANGES FOR TABLE t SINCE 0;
```

Observed behavior:

- committed creates, updates, and deletes appeared in `SHOW CHANGES`;
- a transaction later cancelled by `THROW` produced no changefeed entry;
- creates included the resulting record;
- updates included current state and a JSON patch;
- deletes included the original record;
- versionstamps were returned as big integers;
- `SHOW CHANGES` could not be nested inside an event or assertion.

Consequences:

1. Changefeeds are excellent for post-commit projection repair, cache
   catch-up, audit export, and detecting a missed asynchronous effect.
2. They cannot veto the write that generated the change.
3. Retention is finite; a feed cannot be the sole permanent history for a
   strict temporal invariant.
4. Audit rows generated synchronously from `$before`/`$after` are the durable
   history boundary when a table requires it.

The suite therefore separates three concerns:

```text
e_* guard       = synchronous acceptance/rejection
revision/audit  = durable prior state when policy requires it
changefeed      = post-commit repair and observation
```

## 5. Time grouping and statistics

### 5.1 Buckets

`time::group(datetime, unit)` accepted `year`, `month`, `day`, `hour`,
`minute`, and `second` in the pinned probe. `week` and `quarter` were rejected.
The input must already be a datetime. Offset timestamps are normalized to UTC;
there is no timezone argument.

For tenant-local calendars, the schema must explicitly choose one of:

- normalize to the business timezone before writing a persisted bucket;
- persist both the instant and a business-zone/bucket shadow;
- report in UTC and state that policy clearly.

Do not label a UTC day as a local day by convention. Missing datetimes are
errors, not empty buckets.

Temporal windows use half-open bounds:

```text
[from, to)
```

When a cron asks for the first row, the contract is:

```surql
ORDER BY event_time, id LIMIT 1
```

The ID tie-break makes equal timestamps deterministic.

### 5.2 Incremental and non-incremental statistics

The pinned aggregate probe accepted:

```text
math::sum, math::mean, math::min, math::max,
math::variance, math::stddev
```

`math::avg` is not the function name in this engine. Direct expressions also
exposed `median`, `mode`, and `percentile`, but using those over a source field
in an incremental materialized view was rejected as an unsupported selector.

Observed empty-input behavior:

| Expression | Result |
| --- | --- |
| `math::sum([])` | `0` |
| `math::mean([])` | `NULL` |
| `math::variance([])` | `NULL` |

`NONE` and `NULL` values need an explicit policy before aggregation. A view
may represent an empty bucket by no row, zero, or null statistics, but each
choice must be declared because it changes downstream guards.

The documented engine examples use sample variance (the `n - 1` denominator;
for example, two values `80` and `88` produce variance `32`). Treat the
denominator as upgrade-sensitive and keep a direct numeric regression rather
than assuming population variance in a tax, stock, or attendance formula.

Existing materialized groups make reads inexpensive, but maintenance work is
proportional to affected groups and dependents. The suite must say "cheap
grouped read" or "incrementally maintained" rather than claiming that every
aggregate is universally O(1).

## 6. Polymorphic references and inert state lanes

### 6.1 Polymorphic references are viable

The probe accepted:

```surql
DEFINE FIELD target ON line TYPE record<item | service>;
```

`record::tb(target)` identified the concrete table. Use explicit branches for
semantics such as cost, stockability, or service duration:

```surql
IF record::tb($this.target) = 'item' THEN ...
ELSE IF record::tb($this.target) = 'service' THEN ...
END
```

Do not use an ambiguous null-coalescing chain to infer the semantic type.

### 6.2 Native references and archive/draft links

An authoritative relation with `REFERENCE ON DELETE REJECT` blocked deletion
while the target existed. A draft/archive row with a record-typed link but no
`REFERENCE` survived deletion of the canonical row; its ID became dangling and
it did not contribute to the canonical aggregate view.

That is a useful state-lane boundary, but it has a precise meaning:

- no `REFERENCE` means no existence enforcement and no delete propagation;
- a record value still looks typed, but it is not proof that a target exists;
- dereferencing a dangling state-lane link in a view or guard is unsafe.

For snapshots whose source may disappear, use an opaque provenance value (for
example a record ID plus source-table enum) and never dereference it. Use a
native `REFERENCE` only when the state row is meant to participate in the
canonical graph and its delete action is part of the contract.

### 6.3 Compiler implication

The compiler must distinguish:

1. **authoritative relation**: typed, existence-checked, reader/deletion edge;
2. **calculation shadow**: machine-owned value used as a key or snapshot;
3. **provenance link**: opaque origin retained for display/audit, deliberately
   outside reactivity.

Treating all three as the same reference creates accidental fan-out and was
the cause of the observed `sl.d4_item` reader/reference diagnostic.

## 7. Sparse dimensions and the cube question

### 7.1 Measured sparse grouping

A fact table with dimensions `entity`, `currency`, and `item` was populated with
four observed tuples. Separate views grouped by each dimension and by the
three-dimensional combination. The combined view returned four rows, one per
observed tuple; it did not pre-create every possible entity x currency x item
combination.

This means materialized grouping is sparse. It does not mean dimensions are
free:

```text
storage/write work ~= source rows * number of maintained views
                       + group/index/reverse-reference overhead
```

A high-cardinality combination can still approach one group per fact, and each
additional view adds maintenance on every source write. The physical key count
is not the logical row count.

### 7.2 Adopted dimension strategy

Use one normalized fact with explicit dimensions, then maintain only the views
that answer a real guard or high-volume screen:

```text
fact(entity, currency, catalog_ref, amount, event_time, ...)
  -> v_entity_*       (required operational totals)
  -> v_currency_*     (required treasury/tax totals)
  -> v_entity_currency_* (only when queried often)
  -> ad hoc query     (rare three-way exploration)
```

Do not materialize a full cube or every permutation by default. Add a view when
its read savings and integrity role justify its write amplification. Optional
dimensions need a declared `NONE`/unknown policy; silently mixing missing and
real values creates a false group.

### 7.3 Currency and catalog dimensions

The current account fragment infers currency through a company scalar and a
single FX rate. That cannot represent both sides of a cross-currency payment
or preserve the rate used at the time of a correction. The suite direction is:

- one `currency` catalog with code, precision, active state, and display data;
- an organization finance profile with a functional currency;
- each monetary source row stores transaction currency and amount;
- an explicit FX pair/rate with effective time, source, and rounding policy;
- a derived functional amount and, when needed, an explicit gain/loss fact;
- views group by currency before conversion; unlike-currency values are never
  summed directly.

Keep `item` and `service` as separate tables when their validation and cost
semantics differ. Use a typed union reference from a line and a direct `d_kind`,
`d_currency`, and `d_unit` shadow. This preserves normalization without
duplicating a second product identity table.

## 8. Existing schema defects that must be regression cases

The current fragments expose concrete, testable failure modes:

### Accounts

- editing an `invoice_line` amount below an existing allocation was accepted
  because the invoice guard was not reached by the child write;
- invoice/payment FX paths use a scalar/ambiguous `??` route rather than two
  explicit monetary legs and a rate snapshot;
- product cost, tax, adjustment, and organization changes do not all have
  reverse invalidation paths;
- `accounts/seed.surql` contains view/event material and should not be treated
  as ordinary seed data.

### CRM

- the monthly opportunity view references `created_at` in the raw fragment
  even though the framework field is added only during composition;
- changing only an order's date did not move line-based daily/monthly buckets;
- cascade/delete and aggregate convergence need explicit old/new-group tests.

### Compiler

- derived record shadows are incorrectly treated as reader/reference fields;
- dependency analysis currently focuses on authorization references and needs a
  separate business dependency graph.

## 9. Classification and adopted policy

### Measured

- catalog and permission behavior described in Sections 1 and 2;
- synchronous ordered replay can reject a historical negative prefix;
- window syntax and nested `SHOW CHANGES` are unavailable in the tested form;
- changefeed entries are post-commit and include original/patch information;
- accepted time units and incremental statistics;
- polymorphic record types and inert dangling state-lane links;
- sparse materialized grouping.

### Adopted for ReBase

- SurrealDB remains authoritative for current-state guards and reactive views;
- every cross-record business dependency gets a direct shadow or generated
  reverse ping;
- strict historical tables retain revisions and use bounded replay;
- changefeeds are repair/audit inputs, not synchronous guards;
- dimensions are sparse and selectively materialized;
- currency, tax, catalog, and entity are explicit typed dimensions;
- state lanes are inert provenance stores unless explicitly promoted;
- table/function selection is compiler-descriptor based, never dynamic input.

### Rejected claims

- a generic record-user `table::exists()` function;
- `SELECT` followed by unconditional `RETURN true` as an existence check;
- a normal materialized `GROUP BY` view as a running-balance index;
- changefeeds as a substitute for retained history;
- an automatic full Cartesian cube;
- a universal O(1) write or historical validation guarantee;
- silently dereferencing draft/archive IDs after the canonical target is gone.

## 10. Required regression matrix

Before changing the compiler or schemas, keep these probes small and
deterministic:

| Area | Positive case | Negative/edge case |
| --- | --- | --- |
| Catalog | privileged expected-table check | record caller cannot introspect catalog |
| Guard query | explicit count finds visible target | empty, hidden, and missing target are handled distinctly where required |
| Scope | outer ID survives a nested query | inner `$this` cannot satisfy the outer condition |
| View | source amount and group move update immediately | parent-only field edit would stay stale without reverse ping |
| Historical | valid ordered replay commits | old edit causing a negative prefix rolls back source, revision, view, and ping |
| History | `$before` revision is retained | cancelled transaction produces no committed revision |
| Changefeed | committed update is replayable | `SHOW CHANGES` cannot be used inside a guard |
| Time | UTC bucket and deterministic first row | unsupported unit, missing datetime, and boundary `to` are rejected |
| Statistics | sum/mean/variance match source | empty/`NONE` policy is explicit; median is not claimed incremental |
| Polymorphism | item and service branches resolve | wrong table or dangling inert origin is not dereferenced |
| Dimensions | only observed tuples are grouped | high-cardinality view count and write amplification are measured |
| State lanes | draft promotes into canonical once | draft/archive mutation never changes canonical totals |

## Upgrade rule

Rerun the fact probes after every SurrealDB upgrade and after changing any
`VALUE`, `ASSERT`, `REFERENCE`, view, event, permission, or storage setting.
Record the exact binary and SDK versions. A product decision may be promoted
from measured to adopted only after the same result is observed in the target
runtime and the corresponding regression test is checked in.

## Sources

- [`schema-temporal-fact-check.md`](./schema-temporal-fact-check.md) - baseline
  catalog, view, time, statistics, and domain probes.
- [DEFINE TABLE and pre-computed views](https://surrealdb.com/docs/reference/query-language/statements/define/table.md)
- [SELECT table-view aggregate support](https://surrealdb.com/docs/reference/query-language/statements/select.md)
- [SHOW changes](https://surrealdb.com/docs/reference/query-language/statements/show.md)
- [Math functions](https://surrealdb.com/docs/reference/query-language/functions/database-functions/math.md)
- [Time functions](https://surrealdb.com/docs/reference/query-language/functions/database-functions/time.md)
- [Record references](https://surrealdb.com/docs/reference/query-language/language-primitives/record-references)

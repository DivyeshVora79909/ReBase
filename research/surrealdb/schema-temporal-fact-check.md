# Schema, Catalog, And Temporal Aggregation Fact Check

Status: measured engine findings and proposed design constraints
Last verified: 2026-09-04
Tested: SurrealDB 3.2.0, Node 22.23.2, Linux x86_64
Storage: temporary on-disk RocksDB databases; no `mem://` datastore was used

This note records the disposable probes used while planning the accounts, CRM,
warehouse, HRM, and temporal-cron schemas. It separates behavior observed on
the pinned local binary from product choices that still need schema work.

## Catalog And Table Existence

### `type::table()` is a cast, not an existence check

`type::table($name)` returned a table value for both an existing name and an
unknown name. It does not consult the catalog.

```surql
RETURN 'orders' IN object::keys((INFO FOR DB).tables);
```

The expression above is a usable catalog check only for a root, namespace, or
database system user that is allowed to execute `INFO FOR DB`. It is not a
record-user permission primitive.

`SELECT ... FROM type::table($name)` behaved as follows:

| Input | Result |
| --- | --- |
| Existing table | Normal rows, subject to that table's permissions |
| Existing table with hidden rows | Empty result for the record caller |
| Missing table | Query error: `The table '...' does not exist` |

`CREATE type::record($id)` with an unknown table prefix created a new
schemaless table in the root probe. A client-controlled table or record string
must therefore never be used as a write target without a compiler/runtime
allowlist.

There is no documented or parsed `table::exists`, `schema::exists`,
`meta::exists`, `type::is_table`, or `type::is::table` function in 3.2.0.
`INFO FOR TABLE missing_name` returns an empty structure to a privileged
system user; it is not a record-user-safe boolean API.

### `SELECT` inside a field value or assertion

The pinned on-disk probe also tested a `SELECT` nested in a `VALUE` block and
in a field `ASSERT` on SurrealDB 3.2.0:

- Nested `SELECT` is legal and runs in the current mutation transaction.
- `SELECT` does not commit, cancel, or otherwise break that transaction. A
  `BEGIN TRANSACTION; CREATE ...; SELECT ...; THROW ...; COMMIT` sequence rolled
  the create back completely.
- A block which reads rows and then unconditionally `RETURN true` only proves
  that the query did not error. It does not prove that a row exists, that the
  caller can see one, or that a table is selectable.
- For a row/cardinality check, compare an explicit count/length, for example
  `array::len((SELECT VALUE id FROM parent WHERE id = $candidate)) > 0`.
  An empty result and an invisible result are still indistinguishable to a
  record caller.
- A nested subquery rebinds `$this` to its inner row. Guard code must capture
  the outer identity before entering the subquery:

  ```surql
  LET $self = $this.id;
  LET $rows = (SELECT VALUE id FROM child WHERE parent = $self);
  ```

- In a record session, the nested `SELECT` observes the target table's select
  policy. A hidden existing row yielded `[]`; a privileged event has different
  visibility. Assertions therefore must not use caller-visible `SELECT` as a
  universal catalog or authorization test.

This is useful for reactive business guards, but it is not a table-existence
API. Keep catalog checks privileged and keep dynamic identifiers behind a
compiler/runtime allowlist.

### Record permissions and catalog permissions are different

An authenticated record session produced these results:

```text
INFO FOR DB                         -> IAM error: Not enough permissions
record::exists(visible_record)      -> true
record::exists(hidden_record)       -> false
record::exists(missing_record)      -> false
SELECT FROM type::table('private')  -> only rows allowed by private's policy
```

A database-level `VIEWER` user could execute `INFO FOR DB` and see all table
definitions, including tables whose record permissions were `NONE`. Catalog
visibility is therefore not equivalent to a table's `select` capability.

A subquery inside a table permission is syntactically possible, but it observes
the caller-visible rows of the subquery table. It does not expose whether that
table exists or whether its `select` predicate would grant a particular actor.
Embedding `INFO FOR DB` in a permission parsed, but a record request failed at
runtime with the same IAM error.

### Adopted boundary

1. Startup and migration checks use a privileged catalog connection and
   `INFO FOR DB` against a static expected-table set.
2. Record users query only compiler-declared tables. The database remains the
   authority; an empty result is never interpreted as "table absent".
3. Generic cron/resource selectors store a descriptor key, not an arbitrary
   table or field identifier. The runtime resolves that key against generated
   metadata before constructing a query.
4. No record-user API is added solely to introspect another table's permission.
   If a UI needs capability discovery, expose a separately authorized,
   generated capability document.

## Pre-computed Table Views

Official SurrealDB documentation describes `DEFINE TABLE ... AS SELECT` views
as event-based, materialized, and incrementally maintained. The same reference
documents three limits that matter here:

- the update event is triggered by tables named directly in `FROM`, not by
  tables reached through a record link or graph path;
- views are read-only in 3.2.0;
- omitted `PERMISSIONS` defaults to `NONE` for record users.

The disposable probe confirmed:

| Mutation | Observed result |
| --- | --- |
| Insert source row | Group view appeared immediately |
| Update source amount | Sum/mean/min/max/variance changed immediately |
| Move source row to another group | Old and new groups were updated immediately |
| Delete final source row | The group row disappeared |
| Read view as record user with default permissions | Empty result |
| Update a parent field used through `child.parent.field` | Child view bucket stayed stale |
| Cascade-delete parent while a view grouped on `parent.field` | The delete could fail when the dereference became `NONE` |

The parent/cascade behavior is not a safe integrity boundary by itself. A view
whose grouping or measure depends on another mutable table needs one of:

- a stored `VALUE` shadow of the required parent value on the direct source row,
  plus an explicit synchronous reverse-reference ping when the parent changes;
- an explicit synchronous fan-out event that updates affected source rows and
  re-runs their guards;
- a deliberately asynchronous reporting view with a documented freshness
  bound and repair job when immediate integrity is not required.

The first two options preserve the ReBase calculation model: source records
remain mutable, while derived fields and aggregate rows are maintained by the
database. They are not an event-sourced or append-only replacement.

### Reactive guard invalidation

A focused on-disk probe established the intended write path:

```text
mutable child write
  -> incremental view refresh
  -> synchronous view event updates parent.system_ping
  -> parent VALUE/e_guard re-evaluates
  -> a failed guard rolls back the child, view, and ping together
```

The same works for a parent field change when a reverse-reference event pings
the dependent child. The child `VALUE` shadow changes, the view moves groups,
and the old and new aggregate targets can be revalidated in the same
transaction. Without that reverse ping, a dereferenced expression such as
`child.parent.business_date` remains stale in the view.

Generated invalidation must therefore cover business dependencies, not only
ownership/readers. It should use the native reverse reference scan, deduplicate
targets, and fire only when a declared dependency field changes. A machine ping
is an invalidation trigger, not a business value and not an immutable lock.

Do not claim that every aggregate read or write is O(1). Existing groups make
reads cheap, but writes pay maintenance for every dependent view and group-key
change. Initial materialization is a full query, and high-cardinality groups
increase storage and write amplification.

### Transaction boundary finding

In a multi-statement request, an earlier `CREATE` remained committed after a
later statement returned a missing-table error. Schema installation, fixture
loading, and coupled business mutations must use an explicit transaction when
all-or-nothing behavior is required.

Concurrent independent batch inserts occasionally returned a retryable
`Transaction conflict: Resource busy` error. Retrying the batch produced the
correct materialized total. Conflict handling belongs in the caller/loader; it
must not be mistaken for eventual view inconsistency.

## Temporal Grouping

`time::group(datetime, unit)` accepted only:

```text
year, month, day, hour, minute, second
```

It rejects `week` and `quarter`, and the first argument must already be a
datetime, not an ISO string. Offset timestamps were normalized to UTC before
grouping. For example, an instant late on January 2 at `-05:00` grouped into
January 3's UTC day.

There is no timezone argument on `time::group`. A tenant-local day/month
requires an explicit timezone policy: normalize the event into the chosen zone
before bucketing, or persist a precomputed business bucket and its zone.
Never silently interpret a UTC bucket as a local calendar bucket.

Missing datetimes are errors, not empty buckets. Use a required event timestamp,
or filter/normalize missing values before calling `time::group`.

## Statistics

The installed engine accepted these numeric functions in direct expressions and
in aggregate views:

```text
math::sum, math::mean, math::min, math::max,
math::variance, math::stddev
```

`math::avg` is not a function name. Direct expressions also support functions
such as `math::median`, `math::mode`, and `math::percentile`, but attempts to
put those functions over a source field in a materialized aggregate view were
rejected because the selector was not an optimized incremental aggregate.
Use a scheduled/full recomputation or an ordinary query for those statistics;
do not model them as incrementally maintained O(1) fields without a separate
algorithm and benchmark.

Observed edge behavior:

| Expression | Result |
| --- | --- |
| `math::sum([1,2,3])` | `6` |
| `math::mean([1,2,3])` | `2` |
| `math::variance([1,2,3])` | `1` (population-style result in this version) |
| `math::sum([])` | `0` |
| `math::mean([])` | `NULL` |
| `math::variance([])` | `NULL` |

`NONE` and `NULL` members need filtering or explicit defaults before `sum` and
the other numeric functions. The schema contract should state whether an empty
bucket is represented by no row, zero, or null statistics.

## Current Domain Design Findings

### Accounts

The current schema and views validate on their own, and direct source writes
refresh their immediate views. The following are design defects rather than
syntax defects:

- `org.a_currency`, `tax_account.a_currency`, and one scalar `a_fx_rate` do
  not identify both sides of a cross-currency transaction or preserve a rate
  snapshot and rounding policy;
- changing an `invoice_line` amount below an existing payment allocation was
  accepted because the invoice guard runs on `invoice`, not on the line write;
- changing an invoice FX rate after allocation was rejected, showing that the
  guard works when its own table is touched but not when a dependent table is
  changed;
- currency and organization consistency is inferred through paths in several
  guards instead of being an explicit posting invariant;
- `accounts/seed.surql` contains view and event definitions, not seed rows, and
  should be separated from data seeds;
- all raw tables/views default to `PERMISSIONS NONE` until the framework
  compiler adds the ReBase policy.

### CRM

The raw CRM schema and views also validate syntactically, but the runtime probe
found:

- `v_bi_opp_created_monthly` references `created_at`, which is absent from the
  raw `opportunity` table; creating/reading opportunities can therefore fail
  when that view evaluates;
- a temporal view based on `order_line` did not move buckets when only the
  referenced `order.a_order_date` changed;
- cascaded deletion of an opportunity left the line aggregate visible in the
  immediate read in the probe, so cascade/view convergence needs an explicit
  test and repair policy;
- lookup and business tables have no common ownership/timestamp contract,
  unique business-number indexes, or explicit lifecycle transition policy;
- stage/pipeline and parent/organization guards are useful, but they do not
  replace source-row snapshots for reporting keys.

## Benchmark Boundary

The authorization/reference benchmark remains the large-scale performance
fixture. Future domain benchmarks should keep these rules:

- use temporary on-disk RocksDB only;
- generate deterministic, realistic data in bounded batches, with hot tenants,
  long tails, dense and sparse authorization, and skewed time buckets;
- send one batch request per bounded chunk, never one request per row;
- record query plans, p50/p95 latency, write latency, conflict/retry counts,
  process RSS, datastore bytes, compaction, and view-correction time;
- verify result equivalence after every scale and after restart/reconciliation;
- stage 1k, 10k, 100k, and guarded 1M rows locally; reserve 10M-100M (and any
  100-billion-KV capacity exercise) for a dedicated host with explicit disk,
  RSS, runtime, and stop budgets.

The number of physical keys is not the number of logical rows: each reference,
index, view group, and payload field multiplies storage. A capacity claim must
report that multiplier rather than a raw row count.

## Sources

- [DEFINE TABLE and pre-computed views](https://surrealdb.com/docs/reference/query-language/statements/define/table.md)
- [INFO](https://surrealdb.com/docs/reference/query-language/statements/info.md)
- [Type functions](https://surrealdb.com/docs/reference/query-language/functions/database-functions/type.md)
- [Record functions](https://surrealdb.com/docs/reference/query-language/functions/database-functions/record.md)
- [Time functions](https://surrealdb.com/docs/reference/query-language/functions/database-functions/time.md)
- [Math functions](https://surrealdb.com/docs/reference/query-language/functions/database-functions/math.md)
- [`reference-permission-performance.md`](./reference-permission-performance.md)

Upgrade rule: rerun these probes after every SurrealDB upgrade or any change to
view definitions, reference actions, permissions, or storage configuration.

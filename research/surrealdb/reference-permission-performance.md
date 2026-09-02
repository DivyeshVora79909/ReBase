# Reference-Backed Permission Performance

Status: measured engine behavior and ReBase recommendation

This document records an on-disk benchmark of the current ReBase authorization
predicate versus native SurrealDB `REFERENCE` reverse links. It answers a
narrow question: can a record-reference array replace the table scan used by
the generated visibility/readers/owner permission expression?

The answer for stock SurrealDB is **no, not implicitly**. A reference field
creates an efficient reverse key and an explicit reverse traversal uses
`ReferenceScan`, but an unqualified `SELECT` whose table permission contains a
dynamic OR expression is still planned as `TableScan`. A reference-backed
authorization path can be useful as a server-controlled, adaptive candidate
query for sparse grants; it is not a replacement for the database permission
predicate.

## Scope And Reproduction

Measured on:

- SurrealDB `3.2.0` for Linux x86_64.
- Node `v22.23.2`.
- A temporary on-disk RocksDB directory for every run. No `mem://` datastore
  was used.
- One low-priority disposable server, removed on exit.
- Five comparison tables populated with the same logical rows.
- Bounded inserts (`RETURN NONE`) in batches. There is no per-record network
  request and no unbounded transaction or in-memory fixture. Only one batch is
  materialized by the client at a time; this is deliberate memory protection,
  not a reduction in row count. The harness loops only over bounded batches and
  measurement samples; it never loops over rows with one database request per
  record.

The reproducible harness is
[`dev-tools/reference-permission-performance.js`](../../dev-tools/reference-permission-performance.js)
and is exposed as `npm run probe:reference-permissions`.
The project requires Node `>=20`; when the `surreal` executable is not on
`PATH`, set `REBASE_REFERENCE_PERF_SURREAL_BIN=/absolute/path/to/surreal`.

Normal staged run:

```sh
PATH=/path/to/surreal:$PATH \
REBASE_REFERENCE_PERF_ROWS=1000,10000,100000 \
REBASE_REFERENCE_PERF_BATCH_ROWS=5000 \
REBASE_REFERENCE_PERF_REPETITIONS=3 \
REBASE_REFERENCE_PERF_OUTPUT=/tmp/rebase-reference-perf.json \
npm run probe:reference-permissions
```

Sparse authorization run (1/4/5/10 authorized rows per 1,000):

```sh
PATH=/path/to/surreal:$PATH \
REBASE_REFERENCE_PERF_ROWS=10000 \
REBASE_REFERENCE_PERF_VISIBLE_PER_1000=1 \
REBASE_REFERENCE_PERF_READER_PER_1000=4 \
REBASE_REFERENCE_PERF_NARROW_OWNER_PER_1000=5 \
REBASE_REFERENCE_PERF_WIDE_OWNER_PER_1000=10 \
npm run probe:reference-permissions
```

Dense authorization run (200/250/250/250 per 1,000):

```sh
PATH=/path/to/surreal:$PATH \
REBASE_REFERENCE_PERF_ROWS=10000 \
REBASE_REFERENCE_PERF_VISIBLE_PER_1000=200 \
REBASE_REFERENCE_PERF_READER_PER_1000=250 \
REBASE_REFERENCE_PERF_NARROW_OWNER_PER_1000=250 \
REBASE_REFERENCE_PERF_WIDE_OWNER_PER_1000=250 \
npm run probe:reference-permissions
```

Large runs must set explicit ceilings. The harness checks child RSS, RocksDB
directory size, and elapsed time at batch boundaries and checkpoints JSON after
each completed scale. For example, the guarded one-million attempt was:

```sh
PATH=/path/to/surreal:$PATH \
REBASE_REFERENCE_PERF_ROWS=1000000 \
REBASE_REFERENCE_PERF_BATCH_ROWS=10000 \
REBASE_REFERENCE_PERF_MAX_RSS_MB=3500 \
REBASE_REFERENCE_PERF_MAX_DISK_MB=10000 \
REBASE_REFERENCE_PERF_MAX_RUNTIME_MS=600000 \
REBASE_REFERENCE_PERF_ALLOW_BUDGET_STOP=1 \
npm run probe:reference-permissions
```

The harness accepts larger values such as ten or one hundred million rows, but
those values are capacity experiments, not defaults. With five physical
comparison tables, a 100M-row run would require hundreds of gigabytes (and
potentially much more after compaction); it is not responsible to launch that
scale on a development workstation without an explicit disk/RSS budget and a
dedicated host.

## Fixture And Skew

Each logical row contains scalar, nested, and relational-shaped data:

- tenant key, status, amount, timestamp, tags, and nested customer/risk
  metadata;
- visibility and reader grants;
- a typed owner and a controller array;
- narrow and wide authorization outcomes.

Values use a deterministic 32-bit mixing function so a run can be reproduced,
while still looking like real data. Status is approximately 70% active, 22%
pending, and 8% archived. Tenant selection is strongly skewed with a cubic
distribution, producing hot tenants and a long tail. The default authorization
mix is 8 visible, 40 reader, 50 narrow-owner, and 100 wide-owner rows per 1,000;
the remaining rows are denied. The sparse and dense runs above deliberately
stress opposite ends of the selectivity range.

The comparison tables are:

| Table | Authorization representation |
| --- | --- |
| `resource_plain` | Current visibility/readers/owner predicate; plain controller array |
| `resource_ref` | Same predicate; controller array additionally has `REFERENCE ON DELETE UNSET` |
| `resource_closure` | Materialized controller/authorization closure with a reference array |
| `resource_owner_ref` | Only owner reverse references (a deliberately incomplete control) |
| `resource_indexed` | Same logical grants with a secondary index on controller elements |

The actor has a two-entry access set in the narrow case and a 129-entry access
set in the wide case. All IDs are explicit test IDs; production IDs remain
SurrealDB-generated.

## Query Plans

`EXPLAIN FULL` on the populated database reported these access paths:

| Query shape | Plan observed |
| --- | --- |
| Current permission table, no business filter | `TableScan` |
| Same permission with a `REFERENCE` field | `TableScan` |
| Materialized closure used by a permission expression | `TableScan` |
| `actor<~(table FIELD controllers)` | `ReferenceScan` |
| Concrete `owned_by = actor` | `IndexScan` |
| Concrete `readers_index CONTAINS 'actor'` | `IndexScan` |
| `WHERE id IN $ids` after a candidate scan | `TableScan` |

The critical distinction is query shape. `REFERENCE` writes a reverse key and
enables an explicit reverse source; it does not cause the planner to infer a
reverse source from `id IN`, a permission expression, or a materialized array.
The current predicate remains the security boundary and must be evaluated by
SurrealDB even when an application has produced candidate IDs.

The measured two-step candidate variant (`ReferenceScan` followed by
`WHERE id IN $ids`) still planned the second step as `TableScan`. Therefore a
candidate path is not automatically faster end to end; it needs a measured
fetch strategy, a hard candidate bound, and a final database authorization
check before it can be enabled for a workload.

## Measured Latency And Resource Cost

All latency values are local WebSocket wall-clock medians (`p50`) over the
stated repetitions. Page queries return at most 100 values; count queries scan
the full authorized relation. Rows are per comparison table.

### Default skew, narrow actor

| Rows/table | Population | Server RSS | RocksDB | Current page | Current count | Closure page | Closure count | Explicit reverse page | Explicit reverse count |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 0.384 s | 181 MB | 5.4 MB | 6.746 ms | 5.225 ms | 4.795 ms | 3.960 ms | 1.458 ms | 1.467 ms |
| 10,000 | 3.457 s | 356 MB | 53.1 MB | 6.568 ms | 50.131 ms | 5.214 ms | 33.956 ms | 12.452 ms | 13.176 ms |
| 100,000 | 36.419 s | 1,231 MB | 589.6 MB | 7.783 ms | 519.057 ms | 6.414 ms | 364.212 ms | 418.152 ms | 402.447 ms |

### Default skew, wide actor

| Rows/table | Current page | Current count | Closure page | Closure count | Explicit reverse page | Explicit reverse count |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 10.356 ms | 9.729 ms | 6.861 ms | 5.811 ms | 2.810 ms | 4.858 ms |
| 10,000 | 10.863 ms | 93.615 ms | 7.234 ms | 56.291 ms | 39.134 ms | 39.274 ms |
| 100,000 | 11.690 ms | 969.412 ms | 8.282 ms | 632.676 ms | 1,906.646 ms | 1,906.902 ms |

The bounded page stays nearly flat because `LIMIT 100` can stop early. Counts
are the dangerous operation: they grow with candidate rows and are roughly
linear at this scale. Closure values reduce expression work in this fixture but
do not change the physical access path.

### Selectivity crossover at 10,000 rows/table

| Distribution | Actor | Current page | Current count | Explicit reverse page | Explicit reverse count |
| --- | --- | ---: | ---: | ---: | ---: |
| Sparse | narrow | 65.411 ms | 53.067 ms | **1.812 ms** | **1.745 ms** |
| Sparse | wide | 78.147 ms | 104.850 ms | **4.589 ms** | **4.029 ms** |
| Dense | narrow | 7.697 ms | 53.328 ms | 210.637 ms | 207.053 ms |
| Dense | wide | 10.083 ms | 89.823 ms | 421.009 ms | 429.107 ms |

Sparse reverse traversal wins because the reference candidate set is small.
Dense traversal loses because it must enumerate and hydrate thousands of
referencing rows. This is why a single global “always use references” rule is
incorrect.

### Million-row boundary

A guarded on-disk attempt targeting 1,000,000 rows/table stopped cleanly at
560,000 rows/table when it reached the configured 3,500 MB RSS budget. At the
stop point the child reported approximately 3,548 MB RSS and the RocksDB
directory was 3,442.9 MB. No swap-driven or unbounded run was allowed to
continue. This is a resource observation, not an estimate that one million
rows always requires exactly that amount; payload width, indexes, compaction,
hardware, and SurrealDB versions change the result.

## Write And Reference-Key Cost

An append benchmark updated arrays containing 1, 8, 32, 128, and 256 existing
references. At 256 references, representative p50 times were:

| Representation | p50 append | Expected maintenance shape |
| --- | ---: | --- |
| Plain array | 3.883 ms | Record payload only |
| Secondary indexed array | 10.970 ms | Existing index entries plus the new element (513 expected key operations in the harness accounting) |
| Native `REFERENCE` array | 3.098 ms | Record payload plus one reverse-reference delta |

The exact values are workload-specific, but the direction is stable: native
references avoid the large per-element secondary-array index maintenance seen
in this fixture. They still require record rewriting and reverse-key updates;
they are not free and they do not make a permission expression index-driven.

## Correctness And Lifecycle Findings

The correctness probe compared the current permission result, a reference-field
variant, a materialized closure, and an explicit reverse traversal. For both
sparse and dense 10k runs, the first three and the complete controller reverse
traversal returned the same authorized set. The owner-only reverse control
omitted non-owner grants, proving it cannot replace the visibility/readers/owner
union.

### Delete behavior

Measured with `REFERENCE ON DELETE` on arrays and scalars:

| Definition | Observed result |
| --- | --- |
| Array `UNSET` plus `$value.len() > 0` | Deleting one parent removes that member; deleting the final parent fails and the transaction retains the child and parent |
| Array `UNSET` without the assertion | All parents can be deleted and the child becomes an empty array |
| Array `REJECT` | Any matching parent delete is rejected immediately |
| Polymorphic array `UNSET` plus non-empty assertion | Same member removal and final-delete rejection across target tables |
| Optional scalar `UNSET` | Field becomes `NONE` |
| Required scalar `UNSET` | Delete fails because `NONE` violates the field type |

These semantics support keeping authorization-graph `parents` on `REJECT`; a
silent `UNSET` would create a parentless principal unless a separate invariant
repairs it.

### Closure freshness

Moving a child from `closure_graph:root` to `closure_graph:other` immediately
changed the native reverse scan, but a stored `descendants` array still
contained the old child. A `VALUE` expression combined with `REFERENCE` was
accepted by the engine, yet it did not propagate a transitive closure to
ancestors. Closure maintenance therefore requires explicit events or writes,
with cycle handling and failure recovery. It is not a transparent substitute
for the live graph.

## Permission Optimization Matrix

The generated test build has a common select predicate for most client tables:

```surql
'<table>_select' IN $auth.permissions AND
(!!visibility OR readers_index CONTAINS <string>$auth.id
 OR <string>owned_by IN $auth.z_access_index)
```

The following matrix separates safe query/index work from changes that would
weaken or duplicate authorization. “Keep RLS” means the table permission stays
authoritative even when a faster candidate query is used.

| Table or surface | Current permission shape | Useful optimization | Do not do |
| --- | --- | --- | --- |
| `user` | Principal ID or graph dominance; no visibility union | Direct record-ID reads; bounded graph traversal; index username if searching | Replace dominance with an owner-only reverse set or a client-supplied ID list |
| `groups` | Permission plus dominated/parent group checks | Direct IDs and bounded parent/group lookups; keep root as an explicit anchor | Materialize a closure without transactional maintenance or cycle checks |
| `test_primitive` | Visibility/readers/owner; readers currently empty | If the descriptor has no readers marker, omit reader field/index in a future generated schema; add indexes for real business filters | Assume a reference field changes the permission plan |
| `test_relation` | Same union; readers derived from `a_primitive` and `a_primitive_array` | Index concrete relation fields for joins/lookups; bound relation hydration; measure reverse fanout | Treat computed reader propagation as a free index or use it as the only authorization branch |
| `test_multiref` | Same union; readers currently empty; several `REJECT` references | Omit unused reader maintenance when schema metadata proves it is unused; index creator/reviewer/approver/group fields for explicit filters | Change `REJECT` edges to `UNSET` merely for scan speed |
| `test_tree` | Same union; parent and related-node readers; recursive edges | Keyset order and parent indexes; bound depth/fanout; direct node reads | Use a stale transitive closure as live permission state |
| `email_brevo_config` | Same union; readers currently empty; secrets field-hidden | Keep secret fields out of projections; direct config IDs; omit unused reader index in a future policy-aware build | Index or expose API keys, or use config ownership as a global provider selector |
| `file_storage_config` | Same union; readers currently empty; secrets field-hidden | Direct config IDs and selective metadata filters; keep the shared bucket independent of row ownership | Let the ordinary `provider` field select executable code |
| `razorpay_config` | Same union; readers currently empty; secrets field-hidden | Direct config IDs and metadata filters; hide credential projections | Let provider output or secret fields participate in client authorization |
| `test_attachment` | Same union; readers derived from storage and target records; effect outputs | Use attached-target/config indexes and bounded pages; direct attachment reads; keep output fields read-only | Build an owner-only reverse path that loses target/config grants |
| `send_brevo_email` | Same union; readers derived from config; async lifecycle | Filter by indexed lifecycle fields (`rebase_outcome`, wake/schedule/lease fields) and use bounded keyset pages | Global counts/exports or client mutation of provider state |
| `razorpay_order` | Same union; readers derived from config; sync effect | Direct config/provider-ID lookups and bounded lifecycle queries | Recompute or make provider output writable |
| `razorpay_payment` | Same union; readers derived from order; webhook/provider outputs | Index order and provider payment ID; use detail reads and bounded history | Client-write webhook-owned fields or infer authorization from payment status |
| `change_logs` | Target ownership/dominance predicate; `(target, at)` index | Always scope by a visible target and time/keyset range | Offer a global history scan to record users |
| `authentication_email` | Principal-scoped (`principal = $auth` or dominated principal); address and principal indexes | Exact address/principal lookups and bounded identity lists | Turn identity rows into a general-purpose permission index or expose private verification fields |
| `authentication_phone` | Principal-scoped (`principal = $auth` or dominated principal); number and principal indexes | Exact number/principal lookups and bounded identity lists | Use phone reverse links as a substitute for the authorization DAG |
| `authentication_challenge` | `PERMISSIONS NONE` | Keep challenge operations in privileged auth handlers | Add a client query path or leak code hashes/attempt state |
| `audit_mutation` | `PERMISSIONS NONE` | Keep inaccessible; inspect through privileged probes | Add a client fallback that bypasses the database permission |
| Aggregate views (`v_*`) | Derived queries over client tables; excluded from navigation | Query the underlying table with a bounded, authorized scope when a view is needed | Use an unbounded aggregate view as an authorization shortcut |

For tables with no reader sources, a future compiler optimization can omit the
reader field, reader index, and reader-cascade maintenance. That saves writes
and storage, but it is a schema-generation optimization, not a fix for the
general dynamic permission scan. It must be driven by an exact descriptor and
covered by a regenerated-schema contract.

## Adopted Recommendation

1. Keep the current SurrealDB permission predicate as the authoritative
   fallback for every table.
2. Keep typed `REFERENCE` fields where their delete and reverse-navigation
   semantics are domain-correct. Do not add them solely expecting the planner
   to optimize RLS.
3. For sparse, known-grant workloads, allow a server-controlled candidate path:
   perform explicit reverse scans for the relevant grant branches, union with
   visibility and other branches, apply a hard candidate cap, then fetch and
   re-check through the database permission. Treat it as an adaptive strategy,
   not a client-controlled authorization decision.
4. Prefer a selective business predicate plus a matching index, bounded limits,
   and keyset pagination. Reject or separately authorize unrestricted counts,
   exports, and deep offsets.
5. Keep `parents` on `REFERENCE ON DELETE REJECT` with the non-empty invariant.
   Do not use a stored transitive closure unless explicit maintenance, cycle
   protection, and recovery are added and measured.
6. Keep `$auth.z_access_index` compact where possible and measure hierarchy
   width as a capacity metric. A wide access set is a direct CPU cost.
7. Re-run this probe after any SurrealDB, storage engine, compiler, index,
   permission, or event change. Pin the supported engine version; these are
   observations of `3.2.0`, not universal guarantees.

## Limitations

These are single-process local measurements, not cluster capacity tests. Disk
class, OS cache, compaction state, network latency, concurrent writes, row
width, relation fanout, and actual projections change absolute timings. The
benchmark intentionally isolates permission shapes with synthetic records; it
does not claim that every production table has the same slope. A larger run
should be performed on a dedicated host with an explicit disk budget rather
than by removing the harness guards.

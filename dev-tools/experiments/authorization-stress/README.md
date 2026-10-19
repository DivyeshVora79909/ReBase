# Authorization stress suite

An opt-in experiment comparing ordinary permission-filtered queries with explicit
custom-tree candidate selection and native record hydration. It compiles the
current framework and synthetic workload, starts a private loopback SurrealKV
server, and removes its database and temporary schema on exit. It does not load
an application environment profile or connect to an application database.

Run from the repository root with dependencies installed, the repository-pinned
Node/npm versions, and `surreal` on PATH. `REBASE_TREE_SURREAL_BIN` can select an
installed binary. Resource sampling uses Linux `/proc`.

```bash
node dev-tools/experiments/authorization-stress --quick
```

For a reproducible run with explicit limits and separate raw JSON/log artifacts:

```bash
node dev-tools/experiments/authorization-stress \
  --scales 100,1000,10000,100000,1000000 \
  --owner-count 32 --batch-rows 500 --samples 3 \
  --seed-mode image --budget-seconds 1800 --max-stage-seconds 900 \
  --max-rss-mb 6000 --max-disk-mb 10000 \
  --scan-timeout-ms 3000 --variant-rows 1000 \
  --output /tmp/authorization-stress.json \
  > /tmp/authorization-stress.log 2>&1
```

The million-row scale is a request, not a completion guarantee. Inspect
`stages`, `skipped_scales`, and the final report status before citing any scale.
Measured results and their limits are recorded in the
[results report](../../../research/rebase/authorization-stress-results.md).

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `--quick` | off | Replace requested scales with `100,1000`; other limits and checks stay enabled. |
| `--scales` | `100,1000,10000,100000,1000000` | Positive row counts, deduplicated and sorted. |
| `--samples` | `3` | Timed samples per sequential read/mutation case; 3–30. |
| `--owner-count` | `32` | Bulk owner partitions; 3–256, providing two reachable owners for transfer tests. |
| `--batch-rows` | `500` | Maximum fact rows per construction/verification batch. |
| `--seed-mode` | `image` | Private validated image loader, or `native` to retain all field definitions throughout loading. Both preserve native ownership backlinks. |
| `--soak-seconds` | `30` | Mixed read/write duration on at most 1,000 rows before scaling; `0` disables it. |
| `--budget-seconds` | `1200` | Whole-suite deadline, with progress checks and a watchdog for the disposable server. |
| `--max-stage-seconds` | `600` | Admission threshold for projected load plus verification of subsequent scales. |
| `--max-rss-mb` | `6000` | Sampled combined client/server RSS limit, using bytes divided by 1024². |
| `--max-disk-mb` | `10000` | Sampled private storage-directory size limit, using bytes divided by 1024². |
| `--scan-timeout-ms` | `3000` | Server timeout on each native comparison SELECT; reference materialization precedes it. |
| `--variant-rows` | `1000` | Rows per slot/measure variant, capped at the largest requested scale. |
| `--output` | `/tmp/rebase-authorization-stress.json` | JSON checkpoint/final-report path; overwritten during the run. |
| `--help`, `-h` | off | Print command help. |

Numeric limits require positive integers; `--soak-seconds` also accepts zero. Memory/disk limits use sampled
checkpoints; the suite deadline terminates only its own disposable server if an
in-flight operation stalls. There is no hard per-stage watchdog. A scale can be
skipped when its projected construction plus verification exceeds either the
stage threshold or 65% of remaining suite time. The projection uses the preceding
measured load/verification rate. A running query or verification batch may extend
past a sampled checkpoint limit.

## Workload and correctness

The performance workload distributes actual records across owners. With 32
owners, `wide` dominates the first 16 and `sparse` owns one partition. Separate
same-tenant outsiders, a foreign-tenant actor, and an actor missing table
permission test denials. Performance rows deliberately have `read_by = owned_by`,
so the custom owner partitions and native RLS queries select matching sets.
Expected rows come from an independent JavaScript source-DAG oracle, not the
database's permission functions or materialized closure.
Performance actors can read their candidate root principals. The hidden-parent
functional cases check business-record authority separately. With 32 owners,
one million source rows form 32 trees of 31,250 nodes, not one million-node tree.

Functional authorization cases separately exercise inherited readers and their
ordered choice, source-owner changes, grants and revocations with existing and
fresh sessions, role revocation, hidden direct-parent groups without
`node_select`, and SELECT versus UPDATE/DELETE authority. Tiny graphs include an
8-node chain, 15-node balanced tree, 32-leaf star, and a diamond whose alternate
path survives removal of one edge. Cycle/cross-tenant failures, closure forgery,
rollback, and concurrent opposing parent changes are checked. These graph edits
are isolated from bulk facts; they do not benchmark million-row reparent repair.

Large fixtures contain full intrusive AVL node/head images, including links,
ordering keys, summaries and revisions. Both construction modes temporarily
remove workload events and restore their exact definitions in `finally`.
`native` retains all field definitions and VALUE expressions throughout loading.
The faster default, `image`, first creates a normal prototype for every owner to
obtain native derived values. It then temporarily makes the private fact table
SCHEMALESS and suspends its other field definitions, keeping `owned_by REFERENCE`
active. Ordinary batched INSERTs copy the prototypes, explicit source facts and
complete tree images while SurrealDB creates ownership backlinks normally. Other
native reference fields must be empty in these fixed synthetic prototypes.
Table, fields and events are restored and their complete metadata compared with
the original before any authorization measurement.

`OPTION IMPORT` patches precomputed root headers only, which contain no native
reference fields. Using it for source rows would bypass native reference
bookkeeping; restoring events later would also not reconstruct missing trees.
This is a private, fixed-workload experiment loader, not a general rebuild API or
a change to production authorization.

Every scale verifies all initial records, node images and root headers in
batches, plus native ownership backlinks. At 1,000 rows or fewer, the independent
tree oracle also reconstructs AVL/link/summary invariants from source facts.
The larger initial image comparisons reuse the construction routine; they are
not an independent full reconstruction of the large topology.
After events are restored, authenticated native CREATE, payload/aggregate UPDATE,
rekey, owner move and DELETE must change the intended records and restore exact
root aggregates. Every mutation phase checks the count and every measure in
every configured slot on both affected owner roots. Fixture-construction timings are separate from those native
mutation timings. After native writes, the independent full structural oracle
runs at up to 1,000 rows. Larger stages check row effects and exact aggregate
restoration; their full initial image verification does not establish every
post-write structural invariant.

## Query comparisons

- Custom public `fn::tree::read(..., 'page', ...)` calls select candidates from
  authorized owner roots. Native SELECT then hydrates every returned record under
  its actual record session and row permissions.
- The default bounded heap merge initially requests
  `ceil(page size / owner roots) + 1` items per root, capped at 200. It refills an
  exhausted stream as needed. A full-prefetch comparison requests the full page
  size from every root for the wide actor's first 50-row page.
  Another comparison fetches four root groups concurrently, exposing its latency
  and request-count tradeoff without changing the production query functions.
- Continuation uses the last globally emitted full key, preserving source-ID and
  slot tie breakers. Re-seeking each root avoids losing unconsumed prefetched
  records. Revisions are reported; multiple requests do not create a snapshot.
- Native comparisons cover permission-filtered keyset scans, keyed RecordId
  reads, reference-backlink candidate materialization plus sorting when the
  selected set is at most 20,000, and deep offsets at scales up to 10,000.
  The reference comparison materializes IDs in a preceding LET; its SELECT
  timeout does not bound that LET or the entire multi-statement request. The
  whole-suite watchdog still applies and reported durations include both steps.
- Pages cover sizes 1/50/200, first/middle/last positions, and reverse order.
  Scales up to 1,000 additionally walk the entire visible set forward and backward
  with cursor-progress, duplicate and completeness checks. Repeated rank values
  exercise ties.
- Unindexed `hot` and `absent` post-filters visit at most 1,000 hydrated rows.
  A truncated search is a valid prefix, not a complete empty result.
- Warm concurrent reads use 1/2/4 independent record connections, each performing
  three operations. Four concurrent writers share an owner root; surfaced
  conflicts, bounded retries, committed rows, and exact aggregate restoration are
  checked. Separate native mutation variants use `(slots, measures)` of
  `(0,0)`, `(1,0)`, `(4,1)`, and `(4,8)`, alongside the main `(1,1)` workload.
- Before scaling, two writers repeatedly run atomic six-operation CRUD lifecycles
  against shared owner roots while two readers verify stable authorized pages,
  permitted point reads and outsider point denials. Scratch keys sort after the
  baseline prefix and each transaction deletes its scratch row before committing.
  The phase uses `min(1000, variant-rows, largest requested scale)` rows so it can
  reconstruct every final AVL/link/summary invariant with the independent oracle.
  It records successful transactions, retries, exhausted attempts, read samples,
  actual elapsed time and before/after resource observations. It does not measure
  concurrent changes to the returned prefix or a million-row sustained workload.
  Retries are immediate and capped at four attempts; exhausted requests are
  recorded, not silently counted as commits. The check requires both writers to
  make progress and verifies no partial records plus complete final tree state.
- Summary and bounded-range aggregate reads check exact source-derived counts
  and every configured measure. The variant matrix runs before the large scales.

Native EXPLAIN output is captured using an actual record session for plain,
reference and keyed reads. Inspect recorded `TableScan`, `ReferenceScan` and
`RecordIdScan` output and authored secondary indexes; custom trees are explicit
query APIs, not automatic query-planner indexes. Generic hidden-member traversal
fails closed: this suite does not redefine public tree paging as permission
filtering across arbitrary mixed-visibility roots.

## Reading the JSON report

The report records options, timestamps, Node/SurrealDB versions, commit, CPU,
logical CPU count, cgroup CPU quota, compiled-schema hash and suite-source hash. Preserve the JSON,
log, relevant source revision and hashes when comparing runs. Stage resource
snapshots are observations, not peak-memory measurements.

- `authorization` contains functional cases, assertion counts and case timings.
- `soak` contains the bounded mixed-load phase and its full post-write structural
  oracle. Its row count and timings are separate from the large-scale matrix.
- `stages` contains each attempted row scale, construction/verification times,
  integrity counts, actual plans, read cases, denials, native mutations,
  concurrent reads and resource observations. `variants` contains slot/measure
  mutation comparisons. `skipped_scales` gives admission decisions and reasons.
- Read cases preserve `samples_ms`, sample count, p50/p95/min/max, throughput,
  returned/candidate/visited counts, requests and `result_object_bytes` where
  applicable. This last field measures the final JavaScript result object, not
  network traffic; it excludes discarded prefetched rows. Candidate counts also
  exclude internal seek paths and the tree page's extra lookahead reads.
  Sequential read warm-up is excluded, except that expensive bounded post-filters
  make one measured pass after preceding page warm-ups. Mutation samples are
  native operations without a separate excluded warm-up. Concurrent throughput
  uses elapsed group wall time.
- `server-query-timeout` is a performance limit, not successful execution or a
  correctness pass for that query. A denial with this native status does not
  establish that the native scan completed without leakage; its custom-root
  rejection is checked separately. Inspect these entries even when the overall
  report or enclosing stage says `passed`.
- `truncated: true` means the post-filter visit budget stopped a search before
  it produced a full requested result. It does not prove no later match exists.
- Final `passed` means the configured checks completed; it can still contain
  explicitly timed-out comparison paths. `passed-with-resource-skips` excludes
  listed scales. `budget-limited` retains partial checkpoints and the stop reason;
  unfinished stages are not completed evidence. `failed` records an unexpected
  failure and exits nonzero. The exit status alone is insufficient: budget stops
  can return normally.

These are single-host, warm-cache synthetic measurements. Three samples make p95
a descriptive order statistic, usually the largest sample, not a reliable tail
latency estimate. Actual records and tree nodes are used; compressed weighted
surrogates from older experiments are not comparable. Application business-rule
cost, production contention, cold-cache behavior and deployment capacity require
separate evidence.

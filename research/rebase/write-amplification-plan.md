# Reactive write amplification test plan

## Scope

Measure source writes and dependent refreshes in the compiled all-in-one profile. A
tree membership is counted only when the source fact actually contributes to that
owner; authorization and authentication are outside this test. Use a disposable,
on-disk RocksDB instance and the ordinary compiled schema and event path.

## Workloads

1. Exercise every data table using valid domain writes: first create dimension owners,
   then fund monetary and stock sources, then create claims, invoices, settlements,
   corrections, returns, CRM activity, and HRM grants/usage. Reconstruct maintained
   state from source inputs and check rollback for rejected business writes.
2. Scale shared-tree writes at 10, 100, 1,000, 10,000, 100,000, and 1,000,000 source
   rows, stopping at the first impractical level. Use treasury-to-organization payments
   and record active memberships instead of assuming every owner slot is present.
3. Attach live `money_charge` consumers at 10%, 1%, 0.1%, and 100% density. Change the
   shared calculation rule once to measure dependent refresh work (`r`). Also create valid
   `money_refund` rows against funded originals at a separately recorded density.
   Charges and refunds remain within original source capacity.
4. Record insertion throughput, median and p95 batch latency, rule-update time, active
   memberships, charge/refund counts, largest owner tree population and height, and the
   flushed persistent database size. Billion-row results are extrapolations only.

## Fast synthetic path stimulation

Use a separate minimal compiled fixture when physical population costs dominate. Seed
tree roots and weighted aggregate shards directly with refresh events disabled, then
install only the fixture's generated tree events and exercise real updates, creates,
and deletes. A 20-level, `m = 10` path can represent `n = 1,000,000` in summaries with
dozens of physical rows. Label this as a logical stimulation: it measures compiled
event/path behavior, not a materialized million-record AVL tree or its KV locality.
Validate source-derived aggregates after each real mutation, and algebraically model
larger balanced batches when their measured projection exceeds the time budget.

## Estimates and stop rules

For each table, `m` is the maximum number of declared tree-node slots on one row;
actual active slots can be lower when optional business relationships are absent or
owners coincide. The scale run records active slots for its concrete payment, charge,
and refund fixtures. Business `r` depends on domain mix, so report explicit densities
instead of presenting an unsupported universal average. Preserve raw timing rows,
storage engine, and hardware/runtime version in the results summary. Increase scale only while the preceding
level completes without errors and projected runtime/storage remains practical; do not
attempt a billion-row load unless measured throughput makes its estimated duration
reasonable.

## Exclusions

Do not run authorization or authentication flows, access-control assertions, or load
credentials. Root-only DDL and writes are used only to initialize and exercise business
calculations. No production database or credentials are used.

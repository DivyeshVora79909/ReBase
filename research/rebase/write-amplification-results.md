# Reactive write amplification results

## Coverage and method

The all-in-one profile defines 49 tables. Twenty-four have tree-node slots; the
remaining tables are dimensions, owners, or principals with `m = 0`. The counts below
are the maximum declared membership slots per table, not guaranteed active memberships:
optional links and coalesced owners reduce active `m` on individual writes.

| Table | Slots | Table | Slots | Table | Slots |
|---|---:|---|---:|---|---:|
| `asset_allocation` | 6 | `asset_parent_allocation` | 6 | `audit_mutation` | 2 |
| `crm_case` | 2 | `crm_interaction` | 2 | `crm_transition` | 2 |
| `delivery` | 8 | `delivery_adjustment` | 9 | `delivery_charge` | 7 |
| `delivery_charge_adjustment` | 8 | `delivery_parent_charge` | 7 | `delivery_return` | 9 |
| `leave_grant` | 3 | `leave_use` | 3 | `money_adjustment` | 13 |
| `money_charge` | 6 | `money_parent_charge` | 6 | `money_refund` | 13 |
| `payment` | 6 | `settlement` | 9 | `tax_adjustment` | 4 |
| `tax_assessment` | 4 | `tax_recovery` | 8 | `tax_remittance` | 8 |

`npm run probe:accounts-write-only` exercised monetary transfers, invoices, tax claims,
FX, stock/delivery, notes, corrections, refunds, remittance, recovery and rejected-write
rollback. `npm run probe:suite` exercised CRM transitions/interactions and HRM
employment/leave grants/usage. Both passed populated schema reapplication. Both commands
were run with `REBASE_TREE_STORAGE_ENGINE=rocksdb`; the accounts auth/sign-in branch was
skipped. No authorization or authentication flow was tested.

The scale runner uses the compiled event path and a disposable **on-disk RocksDB**
directory on SurrealDB 3.2.0, Node v22.23.2, Linux x86_64, on an Intel Core i5-12450H
(8 cores/12 threads). It commits up to 250 source statements per transaction. The
nonnegative bank starts with 2,000,000,000 units; scale payments are 1,000 units. A
shared rule starts at 1 per payment and is changed to 2. Refunds reverse 10 units per
source payment and have a valid dated adjustment note. Startup, schema compilation, and
fixture setup are excluded from phase timings.

## Measurements

| Payments `N` | Charge density | `r` | Refund rows | Payments | Charges | Rule refresh | Refunds | Largest tree `n` / height |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 0.1% | 0 | 1 | 3.87 s | 0 | 0.08 s | 0.55 s | 12 / 4 |
| 10 | 10% | 1 | 0 | 3.48 s | 0.58 s | 0.51 s | 0 | 12 / 4 |
| 10 | 100% | 10 | 0 | 3.50 s | 5.82 s | 3.65 s | 0 | 21 / 5 |
| 100 | 10% | 10 | 1 | 47.29 s | 6.60 s | 4.52 s | 0.79 s | 112 / 7 |
| 100 | 100% | 100 | 1 | 49.20 s | 76.68 s | 51.13 s | 0.92 s | 202 / 8 |
| 1,000 | 0.1% | 1 | 10 | 667.09 s | 0.89 s | 0.74 s | 8.66 s | 1,012 / 10 |

The sampled payment had four active memberships (`m = 4`), and the sampled
`money_charge` and `money_refund` each had five (`m = 5`). Their schema slot maxima are
six and thirteen respectively. Every charge update changed the stored charge amount to
2; all refund writes passed source-capacity and note validation. The 1,000-payment,
0.1%-charge run completed with `r = 1`; its payment phase took 11.1 minutes. The 10-row,
one-refund directory occupied 12.7 MB after clean shutdown, including schema/fixture
storage. RocksDB file sizes can change during compaction, so scale throughput and tree
counts are the main comparison measures.

At this rate, the next 10,000-row sparse case projects to roughly 2.5 hours; it was not
run. The 100-row, 100%-charge case projects the 1,000-row dense case at about 43 minutes.
From the 1,000-row sparse result, one million rows at 0.1% charge density and 1% refund
density projects to about 16 days; one billion projects to about 64 years. From the
100-row dense result, one million at 100% charge density projects to about 56 days, and
one billion to about 228 years. These are `n log n` throughput extrapolations, not
observed results; they omit hardware/storage changes, concurrency and contention. No
10,000, 1M, or 1B load was attempted.

## SurrealKV transaction-size comparison

To isolate transaction batching, the same `N = 100`, 10% charge, and 1% refund
scenario was run on on-disk SurrealKV (SurrealDB 3.2.0, Node v22.23.2). Batch
size controls source-row statements per explicit `BEGIN`/`COMMIT` transaction;
batch size 1 therefore gives every payment and charge its own transaction and
client request. Fixture setup and schema work are excluded. Every run passed the
dependent rule-update assertion (`money_charge` amount became 2), refund creation,
and tree/record checks; no auth or authorization was exercised.

| Rows per transaction | Payment txns | Charge txns | Refund txns | Payment writes | Charge writes | Rule refresh | Refund writes | Database bytes |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 250 | 1 | 1 | 1 | 49.49 s | 6.46 s | 4.50 s | 0.74 s | 9.5 MB |
| 10 | 10 | 1 | 1 | 50.77 s | 6.59 s | 4.63 s | 0.76 s | 10.6 MB |
| 1 | 100 | 10 | 1 | 58.41 s | 7.75 s | 4.43 s | 0.82 s | 21.0 MB |

At one row per transaction, payment writes took 18% longer and charge writes
20% longer than the 250-row control; the combined measured phases increased from
61.2 s to 71.4 s (about 17%). The 10-row case was within 3% of the control for
those phases. This small sample indicates transaction/request overhead is
measurable but does not dominate reactive-tree work at this workload. Refund
counts were one in every scenario, so this does not measure the cost of splitting
a large refund batch. Database directory size also rose with more commits; it is
an observation, not a stable storage-efficiency metric. Timings are single-run
measurements and should be repeated for robust latency distributions.

## Synthetic million-node stimulation

Added `npm run probe:synthetic-write-amplification` using a dedicated compiled
fixture, rather than changing the business profile. It uses on-disk SurrealKV,
the generated temporal-tree functions and generated refresh/touch events for only
the synthetic tables. It first seeds without events, then installs those events;
no authentication or authorization event is exercised. Ten separate owner roots
give each test fact exactly `m = 10` active memberships. A shared rule update
refreshes `r = 10`, `5`, or `1` dependent facts (100%, 50%, and 10% of ten).
The source kinds rotate through invoice, payment, input-tax, refund, stock, and
recovery examples. A deterministic amount sequence and alternating owner signs
make each completed create/update/delete lifecycle net to zero.

To keep setup short, `n = 1,000,000` is a **logical weighted tree population**:
39 physical seed rows hold the exact count/amount summaries and expose a 20-level
mutation path. The large aggregate shards are compressed placeholders, not one
million stored records or a fully materialized AVL topology. The test measures
compiled event-driven path updates at the requested height; it does not validate
rank/select/range queries, arbitrary rotations through compressed shards, or
million-record KV locality. This is a fast write-path stimulation, not a
replacement for the physical scale measurements above.

| Reactive density | `r` | Refreshed memberships | Rule update | Reset |
|---:|---:|---:|---:|---:|
| 100% | 10 | 100 | 15.18 s | 14.87 s |
| 50% | 5 | 50 | 4.84 s | 4.62 s |
| 10% | 1 | 10 | 0.71 s | 0.70 s |

All roots remained at one million logical rows and height 20. One create/update/
delete lifecycle took 17.54 s. Ten cycles in one transaction took 177.94 s and
processed 30 source events; both workloads restored exact counts and balances.
The 100-cycle case was not sent to the database. Linear projections put it near
1,779 s (29.7 min) based on the measured ten-cycle batch. Its deterministic
business schedule was algebraically simulated and nets to zero; that is not a
measured database result. Batch size does not remove per-record tree work, and
the projection does not credit possible commit amortization. The runner skips
projected workloads above 60 seconds by default; use `--max-projected-seconds 300`
to permit the measured ten-cycle run, or `--allow-slow` to opt into all requested
cases.

## Reproduction

```sh
REBASE_TREE_STORAGE_ENGINE=rocksdb npm run probe:accounts-write-only
REBASE_TREE_STORAGE_ENGINE=rocksdb npm run probe:suite
npm run probe:write-amplification -- --sizes 10,100 --densities 0.1,1 --refund-density 0.01
npm run probe:write-amplification -- --sizes 1000 --densities 0.001 --refund-density 0.01
npm run probe:write-amplification -- --sizes 100 --densities 0.1 --refund-density 0.01 --batch-size 250 --storage surrealkv
npm run probe:write-amplification -- --sizes 100 --densities 0.1 --refund-density 0.01 --batch-size 10 --storage surrealkv
npm run probe:write-amplification -- --sizes 100 --densities 0.1 --refund-density 0.01 --batch-size 1 --storage surrealkv
npm run probe:synthetic-write-amplification
npm run probe:synthetic-write-amplification -- --densities 1 --counts 10 --batch-sizes 10 --max-projected-seconds 300
```

The runner reports schema slot counts, active slots, phase and batch timings, dependent
and refund counts, tree size/height, and the flushed database directory size. It defaults
to charge densities 10%, 1%, 0.1%, and 100%, with 1% refunds, and skips later scales when
the next estimate exceeds five minutes. Use an explicit `--sizes` value to run a larger
case after reviewing its projected runtime.

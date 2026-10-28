# Population and scaling investigation

**Status: bounded investigation and removal of fixed model population ceilings, 2026-10-28.** Earlier trials use source checkpoint `06d9b263c81f800e1c33f2fb9fd941d7abfa7549` (`06d9b26`); the larger trials below use the changed source. These results do not establish unrestricted capacity, complete the ordered-index redesign, or certify a production topology.

## Changed limit and larger connected runs

Compiled models no longer declare the former public/output/reservation population ceilings by default. Population counters now use checked `u64`; optional configured limits remain enforceable. Node accepts a `null` public limit in the catalog. The codec is `native-slice-kv-8`, and model identities now include limit policies. Existing stores require an explicitly designed migration or the matching old binary. Integer, transaction work, query, receipt, scan and backup limits still apply: notably 262,144 inventory rows, 64 MiB backups, 1,024 receipts, 200,000 work units, and 64 commands per mutation. The full inventory checker reports `work_limit` when its observation budget is exhausted. Counts above JavaScript's safe integer range are not a supported Node catalog limit value.

An isolated local redb run through the authenticated HTTP API used the same Pool/Delivery/Reservation scenario below, with validation enabled and batches of 32. Every public input and every reservation result was checked independently; the native `store.check` reported valid. Each case is a single local run using Node 26.12.0 and a debug-profile Rust binary, with no claim about distributed latency or statistical tails.

| Public records | Derived outputs | AVL nodes | Batches | Population | Independent reads | Integrity check |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5,001 | 5,000 | 7,500 | 158 | 25.04 s | 5.49 s | 3.61 s |
| 10,001 | 10,000 | 15,000 | 314 | 55.39 s | 10.92 s | 10.26 s |

The 10,001-public-record case recorded 20,001 total records and 115,006 native rows; its store and processes were cleaned up. Source and results are retained in [the large trial](evidence/2026-10-28-population-large-trial.mjs.source), [results](evidence/2026-10-28-population-large-results.json), and [source and artifact fingerprint index](evidence/2026-10-28-population-scaling-evidence.json). The test binary SHA-256 was `497eba3b0f88b26b44d9538e736360250f0d8be6b3fcaab39ccea599c7b55d89`. This exercises one shared pool with disjoint reservations, not all contracts, the whole accounting suite, concurrency, multi-host FoundationDB or a million records.

The full Rust library suite passed 116 tests with no failures or ignored tests. The complete Node 24.22.1 suite passed 167 tests with no failures or skips against the changed binary, including six-model snapshots and population integration. The Measurement integration target passed 14 tests; a codec-open fence and checked-count/optional-limit controls also passed.

## Executed Equipment construction

The caller-owned [Node harness](evidence/2026-10-28-population-connected-trial.mjs.source) used the existing debug executable `target/verification-build/debug/rebase-next`, redb, a fresh owned store, a local authenticated HTTP service, and the public population/client functions. [Raw summaries](evidence/2026-10-28-population-connected-results.json) are retained. No credentials or store contents are reproduced here. The binary SHA-256 was `688616f7572faad5ed19e97613c11a18425ac13c6ba9638fbc349b7575f72663`.

Each run authored one Pool, n Deliveries of 10 units at time 0, and n active Reservations requesting 7 units in disjoint one-unit intervals beginning at time 10. Explicit strategies and contract ordering supplied this valid construction. Typed references selected the sole committed Pool. Proposals used batch size 32 and progressed only after the matching committed receipt. This is a constructed feasible scenario, not inference of business rules from schemas.

After population, the harness read every authored row through `records.get`, checked input equality, and independently checked each Reservation's allocation of 7 and available-before value of 10n. Native `store.check` reported valid current state, indexes, links, calculations and receipt structure; that check explicitly excludes historical receipt truth. Every run reported no errors and successful owned-store/service cleanup.

| n Deliveries and n Reservations | Public rows | Committed batches | Population ms | Proposal ms | Prepare ms | Execute ms | Independent reads ms | Store check ms | Total ms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 21 | 2 | 68.6 | 3.2 | 13.9 | 49.6 | 30.4 | 18.5 | 250.9 |
| 100 | 201 | 8 | 623.1 | 6.4 | 23.1 | 584.0 | 254.3 | 107.3 | 1,062.2 |
| 1,000 | 2,001 | 64 | 10,332.3 | 49.0 | 230.6 | 9,962.2 | 3,852.3 | 1,616.3 | 15,885.5 |

Each row is one run, without repetitions or controlled cold/warm cache states. Population time includes caller-loop work beyond the three named subtotals; total includes setup, verification and cleanup. A Cargo build overlapped investigation execution, with no precise contention intervals recorded. Treat all timings as potentially contended descriptive observations, not comparative benchmarks, throughput guarantees or tail-latency evidence. No additional Cargo build was started for this report.

The executable advertised 4,096 public records, 8,192 active outputs, 16,384 retained output reservations, 1,024 receipts, 64 commands, 32 returning records, 65,536 request bytes, page limit 32 and visit budget 128. All three runs remained within these advertised bounds. The largest run checked 2,001 public rows and 1,000 Reservations; its native integrity report counted 4,001 records including generated records. This does not test larger populations or accept any new capacity settings.

## Direct optional Z3 witness

The original ReBase root package declares `z3-solver` 5.3.1 in [package.json](../../package.json), and its optional helper is [dev-tools/fixtures/solver.js](../../dev-tools/fixtures/solver.js). This dependency belongs to original ReBase, not ReBase Next. Neither Next's [Cargo manifest](../Cargo.toml) nor its [Node package](../tools/node/package.json) declares Z3 or a simplex solver. The Next population module has no built-in solver integration.

The [trial](evidence/2026-10-28-population-z3-trial.mjs.source) imported the already installed root Z3 package directly. It solved integer constraints `1 <= delivered <= 1000000`, `1 <= requested <= delivered`, `delivered - requested = 3`, `delivered + requested = 17`, `start = 10`, and `end = start + 1`. The solver returned `sat` with delivery 10, request 7, start 10 and end 11. Adding `requested > delivered` returned `unsat`. The [log](evidence/2026-10-28-population-z3-trial.log) records these statuses; the [results](evidence/2026-10-28-population-z3-results.json) record the subsequent real three-public-row Equipment transaction witness.

That witness committed one Pool, Delivery and Reservation in two batches, checked all three source rows and the derived allocation/availability, passed native integrity and cleaned up. Its population time was 49.7 ms and total time 221.7 ms, excluding the preceding solver initialization/check from the population timing. These single potentially contended timings cannot compare solver and direct construction cost. The witness demonstrates that a caller can feed explicitly solved ordinary values to existing Next functions. It does not install Z3 into Next, prove arbitrary graph validity, implement a solver API, or establish solver scaling. Timeout/unknown must remain distinct from unsatisfiability, as the earlier [population plan](54-composable-developer-tools-plan.md) explains.

## Six models and 31 public contracts

Live developer catalogs from the existing `target/n6-final-native-default-v2/rebase-next` executable reported the following inventory. This separate accepted executable was used for catalog and existing workflow checks; it is not presented as a new build of the in-progress limit changes.

| Model | Public contracts | Ready-made native fixture names |
| --- | --- | --- |
| Calculation | Rule, Curve, Quote, Account, Subsidiary, Posting, Moment, Entry, Adjustment, Basis | causal-diamond |
| Equipment | Pool, Delivery, Reservation | equipment |
| Invoicing | Invoice, Issue, Credit, TaxRule, Assessment, Treasury, Payment, Refund, IssueShare | invoice, invoice-credit, invoice-paid, invoice-refund, issue-share |
| Measurement | Instrument, Observation, ObservationReport, LatestObservation | measurements, observation-report, latest-observation |
| Effect demo | Account, Dispatch | atomic-intent |
| Quantity | Source, Scale, Join | quantities |

The existing `tools/node/test/n5-model-snapshots.test.mjs` passed **1/1 tests with no skips** when `REBASE_NODE_N2_BINARY` selected that executable. It enumerated exactly these six models, requested each model's first native fixture, executed it through authenticated client prepare/execute, captured a complete snapshot and independently checked its structure. This checks one representative fixture per model, not every fixture or every public contract.

The focused existing population suite passed **10/10 tests with no skips** with `REBASE_NODE_N3_BINARY` selecting the same executable: `population-semantics.test.mjs`, `population-contract.test.mjs`, and `n3-population.test.mjs`. The real Equipment and Quantity cases cover typed anchors, stale-context native rejection, explicit continuation, exact rational references and receipt-bound progress. Synthetic contract controls cover nested arrays, optional edges, polymorphic/self references, bounds and mutated-plan/receipt rejection. They do not constitute a native all-contract population campaign.

## What the generator provides and what remains explicit

The [population module](../tools/node/population.mjs) consumes prepared authoritative model catalogs, restricts creation to public contracts, uses seeded schema-shaped generators, and accepts explicit strategies, rules, clocks, context readers, contract/reference selectors and supplied typed anchors. Reference usage records committed selections; supplied ID-only anchors do not imply known historical child counts. Default polymorphic selection weights compatible pools by record count. Required references normally depend on committed parent pools, so available reference shape alone does not construct valid cycles or prove business feasibility.

Exact per-parent cardinalities, interval feasibility, interacting capacities, arithmetic feasibility and scenario ordering require caller-authored logic or a directly invoked optional solver. Schema validation is local input validation; final authorization, OCC, native/global invariants and publication remain server responsibilities. A stalled proposal is not a proof of mathematical unsatisfiability. Unknown outcomes retain the original plan and require reconciliation; local accepted counts cannot substitute for a definite receipt.

Ready-made native fixtures and the two existing real population scenarios provide useful bounded compositions. There is no universal ready-made generator that populates all 31 public contracts with arbitrary counts while automatically satisfying all global rules. The tests and trials above do not cover every contract, concurrent schedule, backend, crash recovery, durable population restart, million-record admission or production deployment topology.

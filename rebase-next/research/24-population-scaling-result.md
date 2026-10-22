# ReBase Next 0.4: indexed selection and bounded population acceptance

**G2a/G2b/G2c accepted, 2026-10-22.** The unfinished `7d7e387` work was worth
retaining after targeted algorithm and source-oracle review. It was replaced by
verified checkpoint `348e9ea`, followed by population checkpoint `3dd8b56`.
All implementation remains inside `rebase-next/` on the existing `main`.
[The gate](22-population-scaling-gate.md) fixes acceptance;
[evidence](evidence/2026-10-22-g2-population.json) records exact execution and hashes.

## Result and scope

Both compiled models now admit **4,096 public sources**, with outer ceilings of
**8,192 active outputs** and **16,384 retained role reservations**. Incoming,
direct and ordered-read reverse registrations are separate point-addressed AVL
nodes; a local edit follows indexed paths instead of decoding an entire list.
Old/new member times and quote successor intervals determine affected reads.
Final-shape prefix gates preserve producer reachability and feedback detection
without materializing every dependency pair. Source arithmetic, authority,
historical invariants, role identities and atomic publication remain intact.

The runtime still uses one embedded redb writer with snapshot readers. Every
mutation has the same **200,000 charged work units**, 64 commands and 32 returned
IDs. Principal/stream, request/reply, receipt and backup limits remain separate.
A large causal closure can fail with `work_limit`; there is no partial success
or silent truncation. This is a bounded capacity increase, not a million-record,
unrestricted production, distributed or full-accounting certification.

## Real API observations

The optimized binary passes **eight workflows**: calculation and equipment at
64, 256, 1,024 and 4,096 public sources. Expected inputs, allocations and grouped
event arithmetic come from source scans, not cached native output amounts.

| At 4,096 public sources | After every read: selected /visits /loaded keys | Last read only: selected /visits /loaded keys |
| --- | --- | --- |
| Equipment | 0 /24 /45 | 1 /24 /54 |
| Calculation | 0 /24 /21 | 1 /24 /51 |

Equipment loads 24,213/26,479 native bytes for those zero/one edits. Both models
stay below the gate's 256 selector-visit and 256 loaded-key thresholds. A real
128-reservation equipment cascade at 4,096 sources commits in **77,089 work
units**, with 1,536 dependency checks and 638 graph edges. A moved quote interval
updates exactly 128 calculation subscribers in 11,255 work units.

Full fanout is measurably different: the authored equipment workload commits
252 producers and rejects 1,020; calculation commits 1,016 and rejects 4,088.
These are observed brackets, not exact or universal thresholds. Every observed
work-limit rejection preserves complete logical application-table bytes and
leaves no success receipt. Rejected invariant, stale-version, unauthorized,
65-command, 33-returned-ID and 4,097th-source requests also preserve state.

All populations exercise full public pagination, quote fallback/inclusive
boundaries or interval allocations, root retargeting, equipment role deactivation/reuse,
receipt replay, graceful restart, acknowledged process termination/recovery and
verified restore through HTTP. At 4,096 sources, equipment has 12,280 total
records, 8,187 data nodes and 77,765 native rows; calculation has 4,096 records,
8,179 nodes and 44,999 rows. Final backups are **45,149,245** and **34,834,185**
bytes, below the independent 64 MiB backup limit. Recorded peak server RSS is
123,836 KiB for equipment and 90,852 KiB for calculation in this run; that is
an observation, not a worst-case memory guarantee.

Separate cloned 4,096-source trials disable a principal and advance its
credential epoch. Old signed tokens receive the established `forbidden` result
before and after reopening. Complete source projections and structural/index
checks remain valid. Permission repair charges inventory visits against the
same transaction budget; these trials commit rather than exercising its
conditional quota-rejection branch.

A separate restored equipment trial reaches the **16,384 retained-role ceiling**
through 4,100 producer replacements in 129 batches, preserving 4,096 public
sources and 8,184 active outputs. Replacing only the current latest reservations
keeps each batch at 64 commands/candidates and at most 39,863 work units. Exact
source allocations and complete integrity pass with 8,200 retired roles. The
ceiling backup is 51,485,617 bytes. One additional atomic delete/create fails
with `state_limit`, preserves every logical table byte and leaves no receipt.
Use `tools/capacity.py --churn-from <accepted-equipment-4096-directory>` with
the ordinary `--binary` and new `--out` arguments to reproduce it. Authority
trials similarly use `--authority-from <accepted-capacity-suite-directory>`.

The existing concurrent harness also fills all 4,096 sources in legal batches,
checks duplicate/CAS races, runs 128 writes and 1,024 concurrent reads, rejects
overflow, invalidates cursors, and verifies crash recovery and restored service.
Its final state is valid at revision 196 with 4,106 records and 193 receipts.

## Independent and release checks

- **56 debug and optimized Rust tests** pass; formatting and warning-denying
  Clippy pass. The new data-tree checker depth guard rejects malformed chains
  before unbounded recursion. Route checks independently enforce membership,
  order, balance, heights, complete reachability and exact key inventory.
- All **68 foundation cases /93 operations**, **39 causal cases /55 operations**
  and **nine local cases /14 operations** pass real native execution and
  independent Python checking. G2b's exact affected-set control and all corruption,
  rollback, injected physical-write abort and reopening controls remain.
- Three previous quota fixtures retain their authored commands but now assert
  acceptance of 17 postings, 17 quotes and 65 sources. New real HTTP overflow and
  independent model-limit boundary checks replace their obsolete 16/64 rejection
  meaning. The foundation corpus now has 56 commits /37 rejections; the causal
  corpus still has 38/17. No arithmetic or structural check was removed.
- **Six client fault/TLS controls** and **three source-oracle controls** pass.
  The capacity tool keeps exact mutation plans and explicit session context;
  fixture generation and workloads use the ordinary authenticated operations.
- An isolated Git source archive builds through its explicit manifest outside
  the repository and produces an identical release executable. Its copied client,
  concurrent harness and both-model 64-source capacity workflow run without
  original ReBase imports or a Git checkout. The test tool's unnecessary Git
  metadata call was removed; source/executable fingerprints remain authoritative.

The final full-population scripts are archived with their reports and match
the recorded probe hash. Subsequent test-tool metadata/auxiliary-command changes
are distinguished in evidence; they do not reinterpret measured numeric results.
Mutation latency includes the client's destination-session check, but excludes
plan persistence and later verification. Hardware/load timings are observations.
No new library was added and the prior dependency audit remains dated.

## Identity and continuation

Release **0.4.0** uses `rebase-store-4`, `native-slice-kv-4`, calculation behavior
`rebase-calculation-contract-4` and equipment behavior `equipment-reservations-3`.
The private route layout is incompatible with format 3. Retain matching old
binaries/backups for old stores; no silent migration or cross-model restore is
provided. See [deployment](../docs/deployment.md),
[storage](../docs/storage.md) and [compiled models](../docs/compiled-models.md).

G2 is complete. Further work enters a named capability gate using the user's
current priority, rather than repeating G1/G2. A representative accounting
workflow and its missing exact-number/query contracts are useful next coverage.
Arbitrary monoids, general two-bound reactive reads, validator-only reactive
contracts, dynamic behavior loading, full accounting, external effects,
distributed adapters and populations beyond 4,096 remain unaccepted capabilities.
The full cross-product of graph shapes, source/output/receipt/lifetime maxima,
power loss, sustained service pressure and remote deployment was not tested.
Do not treat balanced paths or a small benchmark as a universal logarithmic
mutation guarantee. Frontend remains excluded.

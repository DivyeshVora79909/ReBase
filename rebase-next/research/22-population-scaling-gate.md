# G2: population and reactive dependency selection

**Implementation gate, 2026-10-22; starts at `609cb28`.** G1 remains accepted.
Keep implementation, fixtures, evidence and continuation inside `rebase-next/`.
Use authenticated HTTP and the normal mutation/receipt transaction. No frontend.

## Acceptance fixed before optimization

1. **G2a: reproducible baseline.** Add operator-only committed-work observations
   (including bytes loaded), and a source-arithmetic equipment workload. Measure
   16 and 24 active reservations within G1's existing limits. Retain the source
   revision, executable hash, timings, work counters and independent assertions.
2. **G2b: selection and scheduling.** Replace whole reverse-list rewrites/scans
   with bounded ordered point-addressed indexes. Prefix invalidation must use
   changed old/new member times; latest-quote invalidation must respect successor
   intervals. Keep direct dependencies and old/new retargeting complete. Replace
   pairwise final-shape comparisons with a graph whose size is linear in resolved
   reads/emissions, preserving precisely the producer dependency reachability.
   Verify against an independently constructed pairwise graph, including feedback,
   equal timestamps, whole-root reads, diamonds and moved/deactivated outputs.
3. **G2c: population acceptance.** Through the real HTTP process, populate **64,
   256, 1,024 and 4,096 public sources**, including active equipment reservations
   and calculation subscribers. Exercise local edits, real fanout, retargeting,
   authorization, replay, rejection, pages, restart and verified restore. Commit
   coherent tested checkpoints on `main`, then update the shared context/result.

For equipment, one pool and three deliveries leave `population - 4` reservations,
each with two outputs. Nonoverlapping intervals give a dense *logical dependency*
graph even though consume/release pairs cancel. A delivery after every read must
select **zero** producers; a delivery just before the last reservation must select
**one**, at every population. Those edits must stay below **256 selector visits**
and **256 loaded native keys** at 4,096 sources. Record bytes and dirty keys too:
one large decoded list must not masquerade as one cheap lookup. On a full fanout,
scheduler checks/edges must be bounded by **16 times (producers + reads + emits)**.
At least 128 affected producers must commit inside the existing **200,000 engine
work units**. Larger cascades may reject explicitly at that same budget; find and
report that boundary instead of silently increasing it or truncating the closure.
Latency and memory are observations, not hardware-independent pass thresholds.

The intended envelope is 4,096 public sources, 8,192 active outputs and 16,384
retained role reservations per model. Confirm codec, model, reverse-route,
inventory, authority, receipt and backup bounds together before accepting it.
Commands (64), returned IDs (32), principal/reader-stream limits, transport sizes
and receipt window (1,024) remain separately bounded. A graph/permission edit can
cost a full inventory repair and must also reject atomically when over budget.

## Correctness and rejection obligations

- Expected public fields, allocations, exact grouped event sums and prefix reads
  come from authored sources; never use writer-produced outputs as the oracle.
  Retain the independent native/local calculation corpora and full structural
  checker. Verify new selector membership, ordering, balance and complete inventory
  independently, with deliberate corruptions that the checker must reject.
- Test strict prefix boundaries, quote successor/fallback intervals, signed time
  extremes, direct-input bound moves, old/new root retargeting, inactive and zero
  outputs, role identity reuse and final-only causal cycle detection.
- Work, population, invariant and authorization failures preserve every logical
  application-table byte, revision, reader index and receipt inventory. Include
  real API rejections and the existing injected failure after physical writes.
  Oversized closures must not publish partial results or a success receipt.
- Current principal scopes continue to govern reads, authored writes/new links
  and replay disclosure; internal repairs retain engine authority. Original
  operation contexts survive retries and may not bypass archive/reset fences.
- New private route layouts require explicit codec/store versions and updated
  behavior identities. No silent reinterpretation or migration of format 3.

The indexed implementation remains a single embedded writer with snapshot reads.
Full fanout is real work; whole-store checking/backup remains an offline inventory
operation. This gate makes no universal logarithmic mutation, distributed adapter,
full accounting or unconstrained model capacity claim.

## G2a execution

The [baseline evidence](evidence/2026-10-22-g2-baseline.json) records successful
source-only HTTP assertions and complete native integrity at 16/24 reservations.
The after-all-reads edit unnecessarily selects 16/24 producers and checks
514/1,154 dependencies; loaded bytes are 50,714/74,610. The 24-producer case has
276 explicit producer edges. Independent expected allocations and root sums agree.
The new work log is emitted only after commit to operator stderr; it does not
change public responses or replay receipts. Six client controls and formatting
pass. Calculation behavior and store/codec formats are unchanged in G2a.

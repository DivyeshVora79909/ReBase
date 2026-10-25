# Ordered storage redesign contract — PROPOSED

Status: **PROPOSED; planning only.** No layout, implementation checkpoint,
performance result or migration is accepted by this document. S0–S3 below are
proposed checkpoints for the broader redesign plan. Existing accepted evidence
continues to describe the existing executable, not this proposal.

The objective is fewer pointer-dependent remote reads for ordered mutations and
queries, with ordinary supported storage APIs and automatic local balancing.
A page with roughly 50 or 64 entries is an experimental starting point, not a
correctness requirement or a claim that packing always improves performance.

## Current source baseline and the two layers

The inspected baseline has a linked AVL in `src/tree.rs`. Native occurrences
are ordered by `(business key, UUID, member slot)`; nodes store links, span,
height and the compiled family's summary. Roots and members are addressed by
UUID and slot. `src/index.rs` supplies family validation and ordered summary
composition. These are application-level augmented structures.

`Attempt` in `src/native_slice.rs` already caches original/current typed values
within an attempt, coalesces patches and counts loads and bytes. Repeated visits
do not necessarily mean repeated backend GETs. Its synchronous loader cannot
express arbitrary concurrent dependent reads. The FoundationDB adapter currently
uses `block_on` for point reads and range requests. Independent requests could
potentially overlap after an API change; a child address discovered from a
parent still requires a later dependent read.

`src/storage.rs` already exposes ordered range iteration, with bounded scan
batches. `src/storage/foundationdb.rs` maps these to native ordered keys and
range requests. Native ordered KV and the public reader index already exist;
this proposal must not describe either as missing. Logical native ordering in a
serialized node value does not automatically become a useful physical key order.

Two decisions must remain explicit:

1. **Physical ordered storage:** key encoding, key ranges, packed values or
   leaf pages, page discovery and byte/entry limits.
2. **Logical augmentation:** the hierarchy whose children cover ordered
   intervals and whose cached summaries enable whole-interval skipping.

A native database split of its internal pages does not alter the application
summary hierarchy. A physical split of a packed leaf need not change logical
membership or results. If application pages themselves form the augmented
hierarchy, their splits do change summary structure and must atomically repair
parent separators, coverage, counts and summaries. Neither interpretation
permits silently treating opaque database values as engine-managed summaries.

## Semantic contract retained by every candidate

Preserve current family validation, exact arithmetic and overflow rejection,
identity summaries, ordered composition, structural spans and corruption checks.
Associativity permits regrouping; commutativity and invertibility are not assumed.
For financial summaries, `(sum, min_prefix, ...)` is order sensitive: concatenation
uses `min(left.min_prefix, left.sum + right.min_prefix)`. A range aggregate cannot
in general be obtained by subtracting two prefix aggregates. Fold complete
covered subtrees and boundary fragments in occurrence order.

Zero-valued leaves remain real members. Preserve UUID and member-slot ties,
optional business-key uniqueness rules, conditional outputs, absent members,
old/new images and authored slot identity. Preserve inclusive/exclusive and
unbounded range endpoints, including all tied occurrences at a business-key
boundary. Structural coverage must not be inferred from a summary that can
cancel to zero. Empty ranges and empty roots retain their specified results.

Preserve latest/floor selection and any supported family-specific selection
semantics. A count field in a page header is not an implementation of rank or
select: those operations need ordered child counts, descent rules, maintained
metadata and independent acceptance cases. Rank/select is optional scope and
must not be advertised unless implemented and checked.

Keep one authoritative transactional state. No second database or asynchronous
dual-write copy becomes authoritative. A mutation, its derived memberships,
summaries, causal outputs and receipts commit atomically through the existing
persistence boundary. All reads in an attempt use one consistent transaction
view, including staged writes and protected negative reads.

Retain protected scans, including empty ranges and phantoms. Current conservative
scan conflict guards may remain until a narrower replacement has its own
conformance evidence. A faster scan must not silently replace a protected read
with an unprotected snapshot read. Preserve explicit original-plan reconciliation,
the absence of automatic adapter mutation retries, definite abort versus
uncertain commit classification, limits and independent recovery checks.

Start with transaction-local caching. Cross-request caching is optional and
requires a version-validation protocol tied to the transaction's read version;
a cached value must not escape required conflict registration. Revision strings
alone do not prove arbitrary cached data belongs to the current snapshot.
Never reuse stale transactional overlays after retry.

Avoid a common write key across unrelated existing roots. A per-root aggregate
or directory can still serialize writers to that root; measure that contention.
Do not introduce an all-roots root merely to simplify navigation. Existing shared
query partitions and population guards remain explicit coordination boundaries.

## The unresolved canonical regrouping problem

A metadata-free hierarchy defined solely by sorted rank is attractive because
its shape is reproducible. Reproducibility does not imply local maintenance.
Consider the rule: recursively choose the upper median as the node, cache each
subtree count, and give each existing occurrence its subtree summary.

Let `n = 2^k - 1`, `k >= 2`, with keys `1..n`. Append key `n+1` and reconstruct
that canonical upper-median tree. At every old nonminimum key, the represented
subtree cardinality changes; exactly `n-1` existing cached count aggregates
change. The old minimum remains a singleton. The initial perfect tree has root
`2^(k-1)`; after insertion the upper median is `2^(k-1)+1`, shifting recursively
chosen intervals. For example, `1..7` has old counts
`[1,3,1,7,1,3,1]`; after appending `8`, existing-key counts become
`[1,2,4,1,8,1,3]`, so six existing counts change, while key 1 retains count one.

**Unresolved implementation obligation:** this lower-bound example rules out a
universal logarithmic maintenance claim for that exact canonical rule. It does
not prove every metadata-free hierarchy impossible. The recursive shifted
intervals supply the count argument; the previously executed in-memory
experiment is historical observation, not a newly checked formal artifact here.
S1 must retain a small independent executable that specifies upper-median
selection, occurrence attachment and the before/after count maps. Alternative
canonical rules need their own locality argument rather than inheriting a bound
from associativity or reproducibility.

Stable groups with a page index avoid global rank regrouping by preserving page
identity until local split/borrow/merge. A key-prefix partition is another
candidate: stable encoded prefixes define coverage, while sparse levels,
compression and skew need explicit rules. Neither is automatically simpler or
faster. Compare bounded candidates and choose, rather than replacing one
unmeasured assumption with another.

## Candidate layouts and bounded costs

The S1 comparison includes these concrete alternatives:

| Candidate | Expected benefit | Obligation and likely cost |
| --- | --- | --- |
| Existing AVL with measured caching/batching | Lowest implementation risk | Dependent pointer depth remains; batch only known independent work |
| Native ordered member keys plus stable groups and augmented page index | Range locality and higher fanout | Directory discovery, atomic summary maintenance, packing writes |
| Integrated augmented B+ pages | One hierarchy for navigation and summaries | Splits/merges update parent summaries; more bytes per mutation |
| Stable prefix partition with augmentation | Stable interval identity | Skew, depth and sparse compression need bounded treatment |

A minimal comparison may eliminate a candidate analytically before implementing
it. It need not build all four production layouts. Retaining AVL is an acceptable
selection if it meets the declared criteria with less complexity.

For paged candidates define both a maximum entry count and an encoded-byte
budget, including keys, separators, leaves and summaries. Choose initial target
occupancy near 50/64 entries only where value sizes permit it. Define minimum
occupancy, oversized-entry handling, root exceptions, separator equality and
local borrow/merge rules. No unbounded page or whole-root repack is allowed in
the normal mutation path. A byte overflow can trigger a split below the target
entry count. Automatic balancing belongs to the selected implementation or a
verified library; FoundationDB cannot unpack and rebalance an opaque value.

Let `n` be membership in one root, `m` maintained slots/indices affected per
record and `r` the affected causal closure. Let `B` denote bounded effective page
fanout, not an arbitrary constant hiding unlimited values. A balanced augmented
page tree can target `O(log_B n)` page I/O for one point path, with
`O(B log_B n)` processing and corresponding bounded-page bytes for straightforward
summary recomputation. Splits and merges require their own worst-case or
amortized statement. Remote dependency rounds depend on discovery and batching,
not just that I/O count. Single-root bounds multiply or sum over affected slots
and closure; they do not erase `m` or `r`.

A reporting range returning `q` members must pay output/scan cost; generic queries
can visit many partial subtrees. Only explicitly supported summary queries get
a logarithmic boundary-path claim under their coverage assumptions. Large
causal fanout can dominate storage navigation. Existing limits and atomic
rejection remain unless a separate authorized checkpoint changes them.
No million-node capacity or deployment claim follows from these bounds.

## Supported libraries and native ordering first

Use official ordered-key and range APIs before considering an engine fork.
FoundationDB stores ordered opaque byte keys/values and supplies transactions;
it does not supply this application's monoid hierarchy or pack leaf records
inside a value. Preserve the portable backend contract where practical.

The FoundationDB Record Layer Java `BunchedMap` is relevant close-packing prior
art; its source/Javadoc is marked `EXPERIMENTAL`:
[official source](https://github.com/FoundationDB/fdb-record-layer/blob/main/fdb-extensions/src/main/java/com/apple/foundationdb/map/BunchedMap.java).
Its algorithms are useful for a bounded library investigation, not evidence that
it is a Rust drop-in or supports these summary/transaction contracts unchanged.
The FoundationDB Java `RankedSet` skip-list is marked `UNSTABLE`:
[official source](https://github.com/FoundationDB/fdb-record-layer/blob/main/fdb-extensions/src/main/java/com/apple/foundationdb/async/RankedSet.java).
There is no verified portable Rust drop-in selected by this plan. Pin versions,
license and supported APIs when actually selecting a dependency; do not promise
native automatic packing on the strength of these references.

## S0 — instrument and freeze an executable baseline (PROPOSED)

Produce a source-identified baseline trace and a reproducible workload manifest.
Instrument logical visits, unique transaction loads, cache hits, physical GETs,
range requests, returned rows, encoded/read/write bytes and commit/retry outcomes.
Record a serialized wait graph: each request's dependency, start/end and whether
its key was known before another request completed. Count remote dependent read
rounds separately from logical GET count and request count.

Run cold and transaction-warm cases; define cache reset and warmup explicitly.
A warm server or embedded cache does not imply a warm transaction cache. Include
an existing tiny correctness workload as a control. Retain raw per-operation
samples and report sample counts and p50/p95/p99 for latency and read rounds.
Capture backend/client versions, build identity, limits, hardware and topology.

Actual multi-host FoundationDB measurements require infrastructure. If absent,
record that evidence as incomplete; local latency or injected-delay experiments
can diagnose dependence but cannot substitute for actual multi-host results.
S0 exits with a reproducible local baseline and an explicit remote evidence gap,
not an invented distributed performance conclusion.

## S1 — compare bounded alternatives and select (PROPOSED)

Before running, freeze workloads, budgets and selection thresholds in a checked
manifest: minimum reduction in cold dependent rounds, maximum byte amplification,
maximum write/retry and tiny-case latency regression, and required correctness
checks. Choose numerical thresholds from S0 and product priorities; no threshold
may be chosen after seeing candidate results. Record any subsequent change as a
new experiment with its reason.

Use the same source-derived logical inputs and an independent sorted-fold oracle.
The executable matrix varies `n` across empty, singleton, tiny, page-boundary,
height-boundary and largest currently authorized populations; `m` across one and
multiple slots; and `r` across no propagation, short and bounded wide closures.
Include sorted/reverse/random insert, revalue, middle/end deletion, repeated
boundary churn, ties, zero leaves, conditional membership and variable-size data.
Include point/floor/latest, empty/tied/inclusive/exclusive ranges, covered folds,
partial scans and output-sized scans. Add rank/select only if offered.

Measure cold/warm reads and writes, split/borrow/merge bytes, conflict/retry rates,
same-root versus disjoint-root concurrency and p50/p95/p99. Compare identical
transaction boundaries. Demonstrate the exact canonical-regrouping counterexample
with a small independent executable, or correct its asserted count explicitly.
Select the simplest candidate meeting the frozen thresholds. If no replacement
wins within budget, retain AVL and close the comparison with that result.

## S2 — implement only the selected layout (PROPOSED)

Implement the selected encoding and maintenance rules with an independent checker
for membership, order, coverage, counts, summaries, occupancy and reachability.
Check random histories against sorted folds, targeted split/merge cases, rollback,
concurrent phantoms and same/disjoint-root conflicts. The checker must not trust
stored cached summaries or reuse the production maintenance traversal as oracle.
Bump affected persisted format versions and reject incompatible stores explicitly.
There is no implicit migration; any migration needs separate authorization and
its own recovery/rollback contract. Preserve transaction-local old/new images.

## S3 — conformance and bounded handoff (PROPOSED)

Run affected logical conformance across FoundationDB, redb and standalone
SurrealKV, including protected scans, overlays, atomic rejection and recovery.
Verify the selected build through a current extracted artifact and its independent
checker. Reuse unaffected accepted controls with exact identities. Repeat S0/S1
measurement boundaries for the selected implementation; report actual topology,
latency distributions, bytes and conflicts, including regressions and missing
multi-host evidence. Do not infer deployment or unrestricted capacity acceptance.

Stop on semantic mismatch, unbounded normal-path repacking, exceeded transaction
budgets, lost scan protection or unsupported library assumptions. Retain the last
passing baseline and the smallest failing case. A failed candidate ends at a
recorded reject/retain decision or one named bounded corrective experiment;
it does not create an ongoing research loop. The next artifact is the S0 trace
schema plus workload/threshold manifest, not an unapproved runtime rewrite.

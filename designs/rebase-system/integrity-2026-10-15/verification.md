# Packet D: trustworthy histories and final acceptance

Status: the named bounded checks for D0 and D2–D4 passed on the staged-capture
implementation. The seeded D1 campaign is partial; several originally requested
combinations remain deferred below. The [October 15 acceptance manifest](../evidence/2026-10-15-staged-capture-acceptance.json)
records the acceptance commands, exact source hashes, compiled accounting bundle,
engine versions and scope. These results do not prove every possible history or
multi-node deployment.

## D0: checker failure detection

The source-independent checker detects removed whole read inventories, readers,
groups, frames, conditional fallback calls and validation-only calls. Valid
zero-read controls pass. Corruption controls cover source-fence identities,
nested record IDs, group/read identities, generations, roots, leaves, neighbours,
point and interval trees, and exact decimal summaries/extrema. Accounting read
expectations come from the independent rational source model, not surviving
runtime registrations.

## D1: seeded logical-read histories

The observed-read state machine passed seeds `20261014`, `7`, and `1031`, with 216
checkpoints, 489 candidate reads and 196 derived refreshes. It exercises logical
read kinds, empty/fallback branches, reader/source moves, branch changes, nested
helpers and maps, publication and metamorphic edits. Its generated logical point
keys are integers; although the fixture defines a nanosecond quote, no seeded
reader consumes it, so this campaign does not exercise dated logical reads.
Accepted statements check exact expected reads, frames, fences, source references,
tree structure and values.

The seeded campaign also does not exercise required-output creation/deletion as a
lifecycle or expected rejected writes with asserted rollback histories. These
dated-reader, output-lifecycle and rejection-history combinations from the
original D1 scope remain deferred. Separate deterministic fixtures cover portions
of date, rejection and output behavior; they do not combine those cases in the
seeded history.

The deterministic observed-read fixture passed 50 checkpoints and eight
rejections, including a useful cycle rejection, an acyclic diamond, concurrent
first registration/source insertion, empty fallback, owner movement, competing
edits, whole-statement conflict reapplication and cleanup.

## D2: closure and concurrency

The native closure probe passed source-to-publication feedback rejection with
atomic rollback, a valid acyclic diamond, downstream rekeying and cleanup. The
observed-read probe passed the registration/source-write race and competing
whole-statement reapplications. These single-server fixtures do not imply
distributed or multi-node coverage.

## D3: bounded incremental cost

The point/range cost probe passed at 64 point subscribers and 48 interval
subscribers. Insertion used six and seven summary pulls, respectively; retained
queries did no topology repair. One matching range visited 22 interval nodes and
refreshed one reader; sixteen matching ranges visited 38 nodes and refreshed 16
readers. Source-group and staged-scope EXPLAIN plans used record-ID/index scans
without table scans. These are structural samples, not throughput or asymptotic
proof. Prefix edits may still affect a real suffix, and shared source fences can
contend.

## D4: final integration results

The committed acceptance manifest records the following results from disposable
SurrealKV databases on SurrealDB 3.3.0 and Node v24.19.0:

- Both `all-in-accounting` and `all-in-one` builds, freshness checks and native
  schema validation; compiler, architecture and derived-order probes.
- 48 developer-tool tests, 252 typed-tree mutation checkpoints, 1,570 ordered
  reads, 108 rollback snapshots and five conflict retries.
- Boundary algebra: 4,665 timestamp/delta sequences with 57,909 folds, plus 777
  missing-measure sequences with 3,477 folds.
- Required-output creation/deletion and rollback, causal feedback detection and
  rollback, observed-read histories, and the bounded point/range cost gate.
- The minimized purchase/tax/advance-settlement/adjustment regression: seven
  source/tree/read checkpoints and no staged rows after cleanup.
- The independent multi-currency accounting FX history: 76 per-write
  checkpoints, two exact rollback snapshots and cleanup.
- Full accounting acceptance: 103 source-oracle checkpoints, 51 complete
  rollback snapshots, exact populated-schema reapplication and child-first
  cleanup. The complete gate includes fee/tax/refund, claims, transfers,
  production reservations and cross-currency histories.
- `git diff --check`.

The exact command list and compiled/source fingerprints are in the linked
manifest. The failed first divergence and its minimized snapshots are retained
separately under `designs/rebase-system/evidence/2026-10-15-capture-order-*`.

Independent review verification on `3ee5205` used SurrealDB 3.3.0,
Node v22.23.2 and disposable SurrealKV. It reran the 48 developer-tool tests, the
seven-checkpoint capture regression, the 216-checkpoint seeded history and the
bounded read-cost probe. It did not rerun full consolidated accounting, the entire
repository verification command or the external accounting-lab campaign. The
manifest source fingerprints matched that revision, which confirmed artifact
identity but did not mean every manifest command was rerun in that review.

The subsequent review fixes reject mutating reactive helpers and make native
canonical identity checks mandatory in accounting, observed-history and cost
snapshots. The [follow-up evidence](../evidence/2026-10-16-review-fixes.json)
records the final source hashes and checks for those changes; the earlier
acceptance manifest remains an unchanged historical record. Synthetic corruption
tests retain the database-computed canonical IDs while changing persisted IDs
and references. They exercise the observed oracle and the accounting snapshot
path into the shared verifier; the accounting capture regression checks the
complete source oracle on a valid history.

The final implementation keeps calculation, subscription flushes, source fences,
derived updates, validation and cleanup in the originating transaction. A failed
statement rolls all staged and registered reads, tree edits, outputs and audit
rows back together. The completion claim is limited to these named fixtures and
bounded checks.

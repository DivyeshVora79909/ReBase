# G7.3 complete application publication

**Accepted 2026-10-24.** [Evidence](evidence/2026-10-24-g7-publication.json)
records the executed checks, source hashes and explicit limits. The expanded
application runner passes **58 FoundationDB /58 SurrealKV /49 redb** controls.
These include the previous 19 /19 /13 checks and 114 additional controls across
the three backends. The raw storage rerun passes 25 /21 /8 respectively.
This is G7.3 acceptance; G7.4–G7.6 remain open.

## Review of the received checkpoint

Pulled `643c8f6` onto the existing `main`. All 90 source fingerprints in its
[G7.2 evidence](evidence/2026-10-24-g7-shared-persistence.json) match the commit.
An independent source review found no supported correctness discrepancy in the
FoundationDB adapter/facade. Real reruns reproduced all 54 raw storage controls
and 51 previous application controls. The recorded 165 native tests were not
repeated in this review. The incoming context referenced uncommitted draft files
that were absent from the commit; this handoff discrepancy is resolved by the
new committed controls below. The overlapping unfinished local migration was
explicitly discarded in favor of the verified incoming baseline.

## What the new checks establish

`effects::conformance::run(factory)` uses ordinary signed fake-provider ingress,
worker transitions and engine settlement. It checks 27 cases on each backend:

- Signed inbox acceptance, exact-body deduplication, conflicting content and
  rollback after the actual inbox/runtime writes.
- Inbox consumption and worker-result publication, with aborts after fact,
  inbox, due, execution and runtime staging; an obsolete worker claim is fenced.
- Domain application with native/public/reader/fact/scheduling aborts. Literal
  balances are 12, then 9, then 6. Reusing an old application candidate cannot
  debit twice.
- A successful remote debit of 10 against balance 6 retains its durable success
  fact while domain application rejects atomically and becomes blocked.
- Independent decoding of three persisted facts and one signed consumed inbox
  row checks literal outcome fields and applied/unapplied markers. Complete
  application tables and integrity agree after a fresh persistent reopen.

`storage::concurrency_checks::run(factory, concurrent)` adds nine sequential
controls on redb and twelve controls on each optimistic adapter:

- Authority replacement aborts after real reader-index, repaired-native-record,
  graph and prepared-scope writes. Complete tables and receipts remain equal.
- A committed DAG reparenting repairs the independently authored public/reader
  inventory and non-administrator visibility. Stale authority CAS rejects.
- Referenced-parent deletion rejects, ordered teardown succeeds, and both
  reference creation versus parent deletion interleavings preserve integrity.
- Two overlapping initializations share the actual adapter and a commit
  barrier: exactly one commits. A populated destination rejects initialization;
  complete bootstrap tables remain unchanged and survive reopen.

The test wrapper delegates real reads, writes and commits. It only injects an
error after a real staged write or invokes a competitor before native commit;
it never synthesizes a transaction conflict. Redb uses sequential controls
because its writer is serialized. Each rejection compares the complete logical
application inventory, not a selected subset. The existing independent checker
supplements literal source expectations; it is not used as the arithmetic oracle.

## Reproduction and corrections

Build `examples/g7_application.rs` with `foundationdb,surrealkv`, then run it
with `foundationdb <cluster-file>`, `surrealkv <fresh-directory>` or
`redb <fresh-directory>`. Its result contains `application`, `effects` and
`predicates` sections. [The prior result](47-storage-integration-result.md)
describes the pinned native client/runtime and environment variables.

Formatting and Clippy for the library and all examples with both adapter
features pass. The new CLI draft is a separate, unaccepted G7.4 change and is
excluded from this checkpoint. One initial authority-control run incorrectly
gave ordinary fixture users administrator grants; their scopes consequently
allowed all principals. Explicit non-admin contract grants correct that test
setup. Clippy also removed needless closure borrows. No product correctness
failure was established by this review.

## Limits and next checkpoint

Global native metadata and receipt counters still conservatively serialize
application mutations. The tests establish safe results, not predicate-specific
conflict attribution or independent-root scale; G7.5 must remove those artificial
hot keys and rerun the affected races. Provider outcomes and HMAC validation are
real application paths, but provider HTTP transport, live service guarantees,
process/network failures and replicated failover are not certified here.

**Next: G7.4** ordinary CLI/server backend selection, actual HTTP outcome-loss
reconciliation, client process restart and bounded concurrent clients. Then
G7.5 scoped coordination and G7.6 cross-adapter closeout. TiKV, G6 accounting,
G8 workload/release expansion and frontend remain deferred.

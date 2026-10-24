# G7.5 scoped revision and receipt coordination

**Accepted 2026-10-25.** [Evidence](evidence/2026-10-25-g75-scoped-coordination.json)
records current source and executable hashes, 153 distinct native checks,
29 real FoundationDB coordination/lifecycle controls, 58 shared application
controls and the optimized secured HTTP workflow. This completes the
[G7.4 continuation](49-storage-api-result.md). G7.6 remains the subsequent
cross-adapter checkpoint; the accepted witness is bounded correctness evidence.

## Contract and implementation

Source 0.16.0 uses store 10 /native codec 7 /effect codec 4 /API 4. Every binding
behavior identity advances for the shared semantic change. Existing stores need
their matching executable; this checkpoint contains no migration.

Native Meta is immutable model/codec/tenant/bootstrap identity. A separate
Population record holds exact contract counts and retained output reservations;
an attempt writes it only when these counts change. Existing-record updates can
therefore share its tracked read without sharing a global write. Creates,
deletes and new output reservations can still coordinate on exact capacity.

Record versions, root revisions, mutation results, cancellation results and
effect application markers use canonical, nonnil UUID tokens. Equality tests
state identity; ordering and arithmetic have no meaning. Changed records and
roots receive the attempt token, while unchanged materialization preserves its
token. Delete/recreate obtains a fresh token without retaining tombstones.
Execution, inbox, credential and authority-administration fences remain numeric
within their declared scope. Inspection and integrity no longer invent a global
domain revision.

Public changes update the affected old/new `(reader, contract)` epochs, including
derived-only changes. A cursor carries one SHA-256 digest of its selected epochs
and authority-administration revision under the existing HMAC. The bounded
reader/contract vector stays on the server; it cannot overflow the cursor just
by adding partitions. True no-ops and unrelated partitions preserve cursors.
Every actual authority graph edit invalidates cursors conservatively. Authority no-op CAS
uses a same-value administration write so FoundationDB validates its tracked
reads even though the complete logical image and cursor epoch remain unchanged.

There are exactly 1,024 independently guarded receipt slots. An operation hashes
its actor-bound key to a start slot and probes at most all 1,024 slots. The slot
pointer and bound receipt publish with all application changes in one transaction.
Replay precedes allocation and succeeds at full capacity. Slots cannot strand
free capacity in another bucket. Near exhaustion, collisions and long probes can
increase contention. Ordinary mutations read the context header but do not
rewrite it; cancellation also stops rewriting native Meta.

Archive cleanup recomputes and compares the complete backup image digest inside
the cleanup transaction, protecting all tables and empty ranges. It clears slots
and receipts and advances context expiry atomically. Authority and effect changes
participate even when no domain record changes. A published stale backup remains
available while its cleanup rejects. Reset/restore and independent inventories
include all 13 secured application tables.

## Executed verification

`examples/g7_coordination.rs` runs actual adapter transactions through a recorder
that records writes, reads and scanned tables; it never manufactures conflicts.
Two populated Calculation accounts in distinct reader partitions update existing
members, independently producing balances 8 and 7. Both attempts committed with
no common application write key, no Meta/Population/header write and no range
scan. The witness also selects disjoint SurrealKV point-guard buckets.

Same-root attempts update distinct existing debit records and retain the real
business-root guard. A receipt-only no-op conflicts when its tracked source read
changes. Two existing-record reference schedules isolate empty reverse-discovery
and parent-read guards without population or common-write masking. Independent
literal values, exact winner images and original-ID receipt presence are checked.

The lifecycle controls exercise ordinary colliding operations, a final-slot race,
replay/exhaustion, context expiry, both archive/mutation orders and authority/effect
archive races. A directly constructed 1,023-receipt fixture is explicitly only a
structurally valid capacity fixture; it is not evidence of 1,023 executed requests.
The integrity checker independently reconstructs slot/receipt bijection, native
population, authority and scoped epoch inventories.

The earlier G7.3 create/delete reference schedules remain useful lifecycle checks,
but their necessary Population coordination cannot alone isolate reference
protection. The new existing-record schedules close that distinction. Historical
evidence is retained; broad population/workshop campaigns are not restarted.

The 153 native checks span 13 harnesses. The first run passed 149 and exposed
four stale test expectations: the secured table count was still eleven, and
three cross-store comparisons assumed identical numeric revisions. Their exact
reruns pass after using thirteen tables and normalizing only opaque-token
equality classes; authored values, derived values and token-change assertions
remain checked. The failed trial and its binary/source hashes remain in the
evidence. The shared application probe also needed its initial authority-row
fixture updated from three to four; the final 58-control run passes. No failed
result is relabeled as a passing execution.

The 29 new FoundationDB controls took 6.691 seconds and the final 58 shared
controls took 4.541 seconds. The independent existing-root commits took 2,389
and 2,748 microseconds in this local run. The HTTP workflow passes four rounds
each of four-client CAS and root races: 32 attempts, eight commits and 24
confirmed conflicts. It preserves all thirteen tables after SIGKILL/restart
and fresh restore, reconciles committed and deliberately unsent requests by
their original IDs, and checks complete archive preservation and context expiry.
These times describe the local correctness workload, not capacity.

Formatting, all-target Clippy with both optional adapters and default-feature
all-target compilation pass. Two Python archive-oracle tests (including eighteen
corrupt-image variants) and six client tests pass. A retained source-0.14.0
format-9 Calculation image rejects with unchanged physical bytes; strict header
decoding reports `corrupt_state` for its old `receipts` field. This is explicit
incompatibility evidence, not a migration or a `model_mismatch` classification.

One optimized build took 706.644 seconds. The executable is retained at
`target/g75-accepted/rebase-next`, SHA-256
`288232e18700d24ef63c7db785f3aff51426a4c6e35b579a949f846d5a36b632`.
G7.6 reuses this executable and the accepted FoundationDB controls, runs the
remaining adapters and final shared byte contract, then publishes a separate
checkpoint. The later authority-initialization fixture correction is test-only;
the evidence distinguishes build-start and final source fingerprints.

## Remaining bounds

Business-root guards, query-partition epochs, exact population changes and effect
runtime counters remain deliberate coordination. redb serializes writers;
SurrealKV has conservative table-range and hashed point guards. A disjoint-root
witness does not establish throughput or general capacity. FoundationDB evidence
uses one local process/coordinator with no replication. Native commit-acknowledgment
fault injection and replicated failover remain untested. TiKV, G6, G8 and frontend
remain deferred; the last packaged release remains 0.6.0.

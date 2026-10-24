# G7.4 backend selection and operation outcomes

**Accepted 2026-10-24.** [Evidence](evidence/2026-10-24-g7-api.json) records
source/build hashes and real secured HTTP workflows on FoundationDB, SurrealKV
and redb. Each adapter passes four rounds of four-client CAS races and four
rounds of four-client business-root races: 32 competing attempts, eight commits
and 24 confirmed rejections. Each complete workflow accepts 13 ordinary
operations and rejects 25, preserves complete tables after rollback/restart/
restore, and verifies original-ID receipts. This is bounded G7.4 acceptance;
G7.5 and G7.6 remain open.

## Changes and review

`storage::target::BackendTarget` routes the existing CLI to the selected backend.
There is one shared Store implementation. Default redb retains its create-only
file initialization and read-only compatibility preview. FoundationDB uses an
explicit cluster file and deterministic namespace label; SurrealKV uses an
explicit directory. Restore validates/quarantines before atomically importing
into an empty backend. Leading backend/model options compose; unavailable
features report the required build feature. See the
[operator/developer guide](../docs/storage-backends.md).

The FoundationDB network guard lives around the entire command and drops on
success and error; `main` returns an exit code rather than bypassing destruction.
Existing HTTP admission and bounded blocking workers remain unchanged. SDK
calls use the adapter's existing native timeout and no automatic retry loop.

Review found one public-path integration gap: `rpc::failure` previously hid the
new confirmed storage conflict/abort/limit categories as `internal`. They now
remain distinct from uncertain outcomes. A focused native control verifies all
three, uncertain commit classification and continued masking of private error
kinds. Source review found no additional supported correctness discrepancy in
the target, runtime guard, restore or proxy paths.

## Executed controls

`tools/g7_http.py` composes the existing Python client and harness with a private
backend-selection wrapper. All three runs use real signed identity, the ordinary
Calculation model and actual HTTP application processes. No generated model or
storage mock replaces the engine.

- Same-record CAS races accept exactly one submitted edit. Distinct debit IDs
  competing on one balance root accept exactly one debit of 8 from 10; the
  independently expected result is 2. HTTP submission barriers do not claim to
  force any particular database interleaving; G7.3 owns native commit barriers.
- A rejected debit of 11 preserves the complete eleven-table image and has no
  receipt. Accepted operations retain their original result on status/replay;
  rejected attempts remain unobserved, with no hidden automatic resubmission.
- A one-shot proxy closes before forwarding a mutation: the client reports
  unknown, same-ID status is absent and the plan remains unchanged. This is a
  controlled unsent operation, not proof that an arbitrary absent receipt means
  an in-flight operation aborted.
- A second proxy discards a completed server response: the client reports
  unknown, then reads the committed original receipt and replays it without a
  duplicate mutation or replacement identity. This exercises actual HTTP loss;
  it is not native database commit-acknowledgement fault injection.
- After acknowledged commits, SIGKILL of the application process and restart
  preserve every logical application table and receipt. Fresh-target restore
  preserves the exact complete image. Receipt archive expires original contexts
  while leaving business state unchanged; reset clears state and changes store
  identity. Application servers stop at the end of every workflow.

Four CLI checks pass: invalid backend rejection, conflicting cluster-file flag
rejection, missing SurrealKV open without directory creation, and option order.
Default-feature all-target compilation, all-target Clippy with both adapters,
formatting and the focused RPC native test pass. The local FoundationDB helper now recognizes an exited orphan/zombie during
shutdown; a live start/read/write/stop/repeated-stop control confirms that its
owned listener is closed. Existing G7.3/raw suites were not repeated because
this checkpoint changes target/transport presentation only.

Measured whole-workflow client times in this setup were about 5.2 seconds for
FoundationDB, 3.7 for SurrealKV and 3.4 for redb. Per-race latency and outcomes
are in the evidence. These small local runs are correctness evidence, not a
throughput ranking or production-capacity claim. FoundationDB has one local
process/coordinator with no replication; no disk, power or replicated-node loss
was injected. Native commit-acknowledgement injection remains untested.

## Continuation: G7.5, then G7.6

The user requested a clean budget handoff. G7.0–G7.4 are accepted; the next
agent should continue G7.5 on existing `main`, without restarting accepted
stages. No G7.5 migration code is retained. The following preparation is a
reviewed design direction, not implemented or accepted evidence:

1. Separate immutable model/store identity, authority administration version and
   population/reservation counters. Write population only when counts actually
   change. Exact global capacity and new output reservations can legitimately
   coordinate; do not pretend all creates become independent.
2. Use fresh opaque mutation/CAS tokens for changed records, roots, results and
   effect application markers, with explicit format revisions. UUID tokens
   prevent delete/recreate ABA without an unbounded tombstone registry. Keep
   ordered per-execution/inbox fencing counters numeric. Remove cancellation's
   incidental global Meta write. Document the meaning of each response token;
   do not expose an authority epoch as a global domain-mutation sequence.
3. Bind cursors to bounded scoped reader/contract epochs, including affected
   old/new readers, derived-only public changes and authority changes. Digest
   the selected epochs into one signed field; the full vector can exceed the
   existing 4,096-byte cursor bound. Decide the no-op contract explicitly: a
   genuine no-op can preserve cursors when the scoped result is unchanged;
   previous tests conservatively invalidated them. Preserve tracked no-op reads
   against concurrent edits either way. Update fixtures/documentation to the
   chosen new API contract, rather than silently weakening assertions.
4. Prefer 1,024 independently guarded receipt allocation slots with bounded
   hash-start/linear probing over fixed per-bucket quotas. This preserves exact
   existing receipt capacity without stranded buckets. Atomically publish a
   slot pointer with its bound operation receipt; check replay before allocation.
   Verify slot/receipt bijection, collision and final-slot races. Header reads
   still fence archive/reset, without rewriting the header on ordinary mutations.
5. Archive must protect the promised complete backup state, compare its digest
   inside the cleanup transaction, and atomically clear slots/receipts plus
   advance context expiry. Include authority/effect changes in the race controls.
   Update integrity inventories and remove numeric global-version comparisons;
   never order UUID tokens. Keep historical evidence unchanged.

Suggested ownership: one contributor for core tokens/population and binding
signatures; one for receipt/lifecycle; one for integrity/fixtures; root owns
shared local/query/security boundaries, formats and Cargo. Assign exact files
before parallel edits. Use one Cargo owner, two jobs, incremental off and the
existing cache. Commit only buildable verified checkpoints; no blanket deletes
of failing tests. Business calculations and codecs stay engine-owned, with no
storage-specific formulas or new plugin/query framework.

Before accepting G7.5, stage real concurrent updates to two already-populated
independent business roots in distinct reader partitions and receipt slots;
prove both commit without a common written coordination key. Re-run same-root,
reference, revocation and no-op guards after removing masking global writes.
Cover ABA, scoped cursor change/survival, exact receipt capacity, archive races,
original-ID outcomes and complete rollback. Then G7.6 runs the final shared
contract on all three adapters, publishes exact formats/dependencies and updates
operational documentation. Keep necessary business-root/global-capacity/effect
coordination and conservative adapter conflicts explicit.

TiKV, G6 accounting, G8 workload/release expansion and frontend stay deferred.
The last verified packaged release remains 0.6.0; no new production bundle or
replicated service is claimed by G7.4.

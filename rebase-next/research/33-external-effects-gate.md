# G5: bounded durable external work

**G5a accepted, 2026-10-23; G5b/G5c remain unaccepted.** The
[G5a result](37-atomic-intent-implementation.md) and
[evidence](evidence/2026-10-23-g5a-atomic-intent.json) establish atomic intent,
status/cancellation and checked bounded storage with dispatch disabled. This is G5 of the
[capability program](30-capability-program.md), after the accepted 0.6 release.
The small [lifecycle oracle](experiments/effect_lifecycle.py) has executed; its
limited result is recorded below. No production provider, worker, durable inbox
or effect-storage implementation is supplied by that experiment; G5a's separate
native evidence now establishes its stated storage scope.

## Meaning and selected scope

Preserve [atomic durable intent](02-transactions-and-storage.md#7-external-work),
[external-work authority](07-contract-wireframes.md#8-external-work-and-future-capabilities)
and the original [operations design](../../designs/rebase-system/operations.md).
Business state and intent commit together. Network actions follow confirmed
commit. Leases fence local changes; provider idempotency and reconciliation
handle remote uncertainty. A stopped worker, canceled request or lost response
does not prove that a remote action did not happen.

Use the existing single-process redb deployment, Axum HTTP server and Tokio
runtime. A bounded polling loop and disposable in-process wakeup suffice. No
Redis, BullMQ, Temporal, workflow graph, adapter registry, DSL or second
transaction runner enters G5. Such infrastructure can help later operational
workloads; none removes the transaction/provider uncertainty boundary here.
Use mature HTTP/TLS and provider signing libraries when a real adapter requires
them. The fake HTTP transport needs no new protocol framework or cryptography.

The selected first adapter is a deterministic, separately running fake provider
with an independent durable journal. Its sole action accepts positive integer
`units`, keyed by the immutable execution UUID, for a fixed account/version.
Repeated submission of the same key/content returns the same acceptance;
different content conflicts. The fake retains keys indefinitely for this gate.
Its query can confirm acceptance but an empty query is **inconclusive**. It has
controlled definitive nonacceptance, lost-response, waiting and signed-delivered
webhook modes. Real providers need separately documented retention and
reconciliation contracts before being enabled.

All provider-specific request, outcome, account and verification code stays in
ordinary trusted modules. Core owns only checked lifecycle/storage operations.
Request and result types belong to the compiled model; callers cannot select a
URL, credentials, handler name, file, SQL statement or arbitrary output patch.
No provider I/O, current time, random allocation or credential loading occurs
inside pure calculation or an automatically retried transaction closure.

## Chosen initial policy and envelope

The fake execution authority is the requester, rechecked against current stored
permissions at both claim and provider-start transactions. Capture actor and
credential epoch at submission. For the fake binding, authority means Create on
Dispatch and current Update authority over the pinned Account, using the existing
principal scope; no new capability language is needed. Claim/start require that
epoch still be current and those grants/ownership routes still permit the action.
A refreshed JWT cannot silently transfer an old request to a new authority
context. Revocation before start suppresses submission. A durable
provider fact after start remains evidence even after revocation/expiry;
read-only reconciliation and typed result application use restricted engine
authority, never authority to submit again.

Freeze inputs, account/configuration identity, action version, due time and
submission expiry at creation. No input editing or rescheduling enters G5.
One execution requests one action once; a new request gets a new execution UUID.
Credential rotation may preserve the pinned account; changing account identity
requires a new configuration version. Secrets stay outside persisted payloads.

`execute_at <= now < not_after` is required at claim/start. Expiry stops new
submission, not reconciliation, inbox acceptance or application of an existing
provider fact. An expired never-started request becomes `cancelled` with reason
`expired`; a started request stays uncertain until resolved. Store times are
checked integer milliseconds from a trusted clock, distinct from model business
time. Default `not_after` is creation time plus sixty seconds; explicitly authored
due/expiry must fit within twenty-four hours of creation. JWT expiry authenticates
the ingress request; the stored execution deadline and current actor/epoch checks
govern later execution, so a short-lived token need not remain live until delivery.
Freeze generated times/identities once outside any retried mutation. Use explicit
`now` arguments for pure transition tests. Wall-clock jumps
do not establish distributed fencing; multiple active hosts remain outside G5.

| Limit | Initial value and purpose |
| --- | --- |
| Unresolved executions | 64, including nonterminal phases and pending/blocked result applications; bounds recovery obligation. |
| Retained executions | 256 per store; no automatic deletion/pruning in G5, so source reuse cannot erase deduplication evidence. |
| Durable inbox rows / provider facts | 256 / 1,024 total; duplicate identity/content consumes no new row. |
| Request / normalized outcome / raw webhook | 1 KiB / 2 KiB / 8 KiB, independently enforced before allocating/parsing further. |
| Sanitized diagnostic | 256 UTF-8 bytes; no secret, authorization header or raw provider error dump. |
| Encoded effect tables | 8 MiB total; account all rows/indexes atomically before growth. |
| Discovery / application turn | At most 16 visited rows or 100 ms of planning, then yield; one row may use the existing bounded mutation budget. |
| Provider calls | Two concurrent calls, five-second transport deadline, ten-second lease; finite renewal, at most thirty seconds of ownership. |
| Submission attempts | Three claims maximum, including prestart claims lost to crashes; exhausted never-started work fails diagnostically. |
| Poll/reconcile observations | Six automatic observations; then retain `uncertain` and stop automatic calls until an explicit bounded operator retry. |
| Automatic backoff | 1, 2, 4, 8, 16, 32 seconds, capped by eligibility/expiry; webhook arrival need not wait for a poll. |

Submission claims are conservatively budgeted even when a crash precedes start.
This can stop work early but never authorizes an unsafe repeat. Deadline and
lease values bound ordinary cooperative work, not a guarantee that a paused
process or remote server has stopped. A timed-out HTTP future keeps its permit
until the owned operation terminates; no detached unbounded retry tasks.

These small limits test real overflow/rollback and reserve recovery capacity;
they are not measured production capacity. Submission at the 64/256 boundary
rejects atomically. Completion of an already accepted execution must not require
an unused execution slot. Reserve one provider-fact slot and bounded result bytes
per accepted execution; discretionary observations cannot consume that reserve.
Storage pressure on webhook acceptance returns a retryable failure without ACK.
No overflow silently drops evidence or evicts an unresolved row. The existing
64 MiB backup bound and 200,000-unit mutation limit remain independent; prove
the complete fake-store boundary fits backup, rather than assuming the private
8 MiB budget proves this for every model.

## Authoritative row and transition table

Execution rows store immutable execution UUID, originating operation/action slot,
source correlation, model/action behavior version, requester/epoch, tenant,
target identity, provider account version, frozen request/hash, due/expiry;
mutable revision, phase, eligibility, budgets, lease and provider-start marker;
and cancellation, provider correlation, application state and safe diagnostics.
Provider keys use execution UUID plus a stable action slot, never a changing
lease, retry count, source ID, operation-archive epoch or row revision.

`phase` describes remote execution. `application` independently describes
`none`, `pending`, `blocked` or `applied`. A remote success cannot be rolled back
by rejecting its business-state application. Running status derives from a live
lease, rather than another persisted `running` flag.

| Current state and input | Committed result and permission |
| --- | --- |
| New authorized domain mutation | Business state, immutable `ready` intent, due index and operation receipt commit atomically. |
| `ready`, due, unexpired, authorized, budget available | Claim rotates revision, charges attempt and stores fresh token/expiry; no network action yet. |
| Claimed `ready`, live token, current authority, unexpired, not canceled | Commit provider-start marker under that claim; only confirmed commit permits submission. |
| Expired claim without provider-start marker | Clear lease/rotate revision; `ready` may be reclaimed if time, authority and budget still permit. |
| Expired claim with unresolved provider-start marker | Clear lease/rotate revision and enter `uncertain`; never enter normal submission. |
| Started call returns documented definitive nonacceptance | Record evidence, clear unresolved marker and lease; retry `ready` only within remaining budget/expiry, otherwise `failed`. |
| Started call returns accepted/pending | Record typed acceptance fact/correlation, clear lease and enter `waiting` with next poll. |
| Started call times out, loses response or has unknown commit outcome | Retain marker/evidence and enter `uncertain`, or allow lease expiry to do so; no blind repeat. |
| Matching success from live completion, reconciliation or verified inbox | Persist immutable provider fact; enter `succeeded`, clear superseded lease, rotate revision, set application `pending`. |
| Permanent provider rejection with definitive semantics | Persist typed rejection fact and enter `failed`; terminal phases have no submission handler. |
| Reconciliation/poll returns no matching observation | Stay `uncertain`/`waiting` under bounded backoff; an empty report does not establish nonacceptance. |
| Success fact, application `pending` | Separate atomic shared-engine attempt applies typed domain change and marks `applied`; replay does neither twice. |
| Application rejects invariant/reference/work budget | Domain attempt rolls back completely; provider fact stays durable; record `blocked` in a short separate transaction. |
| Cancel wins before provider-start marker | Rotate revision, clear lease, set `cancelled`; stale worker start fails. |
| Cancel after start/acceptance | Record cancel intent, rotate revision, clear superseded lease and enter `uncertain`; reconcile actual outcome, without compensation/resubmission. |
| Success/rejection repeats or older pending event arrives | Identical fact is a no-op; do not regress terminal state/application. Contradictory terminal facts are retained as conflict evidence and flagged for operator reconciliation. |

Claim, renewal, start and completion compare tenant/store, fresh worker activation,
execution UUID, revision, lease token, expected phase/mode and unexpired lease in
the same write transaction. Reconciliation claims permit provider reads, not
submissions. Inbox application can rotate the revision and invalidate a worker
completion. A cancellation after start similarly forces reconciliation rather
than letting the canceled lease write a result.

An unknown start-marker commit outcome requires reading and confirming the
exact live claim/marker before submission. An unknown finish commit outcome
requires reading durable facts/status, not another provider call. The private
start marker is conservative write-ahead evidence, not proof of acceptance.
Even a correctly fenced stale worker may already have made, or resume making,
a remote call; a local lease token cannot fence the provider itself.

## Small API and shared-core integration

Public request creation stays in `records.mutate`, using a compiled fake-model
Dispatch contract. There is no independently committed `enqueue`. Operation
identity/content/context replay is checked before creating more intent or
charging limits. Public additions are:

```text
effects.status {model, execution_id}
effects.cancel {model, context, operation_id, execution_id, if_revision}
```

Status performs a current authorized read; it does not require refreshing an
old operation context. Cancellation retains the ordinary actor/store/archive
operation context and receipt semantics. Status exposes only model-declared
safe fields to current readers of the pinned Account. Cancellation additionally
requires the original requester or a tenant administrator and current Update
authority over that Account. Model catalogs describe typed requests/results
and these methods from the same compiled declarations used by clients. An
optional bounded status wait can follow acceptance; inline waiting adds no
second lifecycle and is not necessary for G5.

Internal ordinary functions are `claim`, `renew`, `mark_provider_started`,
`finish`, `claim_reconciliation`, `record_fact`, `accept_receipt`, `apply_fact`
and `scan_due`; transport wakes identify only store/execution/revision. No
internal worker capability or arbitrary patch enters public RPC. Keep the
binding seam concrete: model-owned pure preparation freezes intents from final
authorized source changes; a pure typed result function builds the permitted
domain command from frozen request plus validated fact and current domain data.
Extract a shared compiled trait only when the concrete fake use requires it.

The relevant current seams are `local::Store::mutate`/its private mutation
runner, `mutation::settle_authorized`, `security::write_authority`,
`security::repair_readers`/reader-index repair, `rpc::dispatch`, `server::router`,
`binding::Binding` and the observation/lifecycle/integrity paths. Do not add an
alternate domain writer:

1. Extract the existing transaction-owned staging/publication steps narrowly
   enough for both client mutation and typed effect application. Preserve one
   attempt, normal settlement, terminal invariants, revisions, authority,
   public/reader index repair and the original work limit.
2. During an ordinary successful mutation, prepare intents from the settled final
   change set and write them/indexes/counters **inside that same redb transaction**,
   before its operation receipt/commit. A thrown error or later receipt failure
   rolls all tables back. No after-commit callback establishes durability.
3. After confirmed commit, an in-process wake is optional. Polling is the recovery
   path. Provider calls occur with no transaction open and only after a confirmed
   start marker under restricted credential resolution.
4. Completion/receipt acceptance first commits the immutable provider fact. A
   separate bounded `apply_fact` transaction runs ordinary typed mutation staging
   and atomically marks that fact applied. A rejected application does not erase
   the previously committed fact. Domain repair plus explicit reapplication may
   later succeed. Never automatically resend because application was blocked.

Private effect tables are `effect_executions`, `effect_due`, `effect_facts` and
`effect_inbox`, with versioned checked keys/rows. Use an explicitly versioned
effect-runtime header/table for activation, counters and scan state; the existing
`local_runtime` checker permits exactly its single header row. Keep native
calculation KV and effect payload storage distinct; neither becomes a second
business record identity. Integrity reconstructs expected due indexes/counters,
validates request hashes, fact/application bindings and unique operation/action
identities, and rejects orphan/duplicate rows.

Update complete inventory checks and raw observation in `local.rs`, offline
backup/restore/reset/archive in `lifecycle.rs`, and binding integrity checks.
Receipt archiving cannot delete effect/inbox evidence or change provider keys.
Allocate the next format after G4c: **expected store 7 /native codec 6 /effect
codec 1**. G4b owns store/native codec 5, and G4c owns store/native codec 6;
G5 adds effect tables/headers and therefore owns the next store format. Native
codec 6 stays unchanged only if G5 leaves native KV keys/values unchanged. Bump every
affected binding behavior contract for actual G5 calculation/domain semantics;
a new effect-demo binding has its own behavior/version. Recheck unaffected
models' identities rather than assuming they changed. Catalog/cancellation
additions must have a declared API identity; choose `rebase-local-api-2` for the
combined G5 API release, with explicit old-store rejection and no automatic
migration. Any intervening accepted format/API change owns its assigned version:
recheck actual G4b identities and never reuse a version for different bytes or
meaning.

## Minimal domain fixture and provider harness

Use an explicitly experimental compiled `effect-demo` binding through the same
model preparation, CLI selection, secured store, RPC, receipts and checker.
Its authored Account has a mutable nonnegative integer `balance`; Dispatch has
immutable account and positive units. This is a synthetic delivery-credit
example, not payment accounting. The balance remains ordinary authored business
data; the private immutable provider fact is the authoritative provider evidence.
No new protected-source framework is needed to make a fake result appear.

A successful typed result subtracts the frozen units from that account's
**current** balance, subject to the normal nonnegative final-state invariant.
The compiled function can alter only that balance; it cannot change tenant,
owner, reader, account identity or another execution. Application uses restricted
engine repair authority with current tenant/reference/invariant checks, and
does not require a now-revoked requester to submit anything again. Reject account
deletion while any retained execution targets it, so an old result cannot target
a reused account UUID. Dispatch source deletion/recreation does not erase or
retarget the independent execution; result correlation always uses execution UUID.

Literal workflow: create Account balance 12; atomically change it to 10 and
create Dispatch units 3. Assert one operation receipt and one ready intent.
After provider success/application the balance is 7. In a second case change
balance to 2 after provider start: success fact persists, application rejects,
balance stays 2, application becomes blocked. An authorized edit to 5 plus an
explicit application retry produces 2 exactly once, with no provider resend.

The independent fake provider runs as a separate process/journal, surviving a
backend restart or restore. Record actual calls separately from unique accepted
actions. Inject lost responses after journal commit, definitive failure before
acceptance, delayed pending/delivered status and raw signed webhook replay.
The HTTP harness derives expected balances/facts from authored operations and
the independent provider journal, never from writer-maintained effect indexes.

## Webhooks, discovery and grants

Use one static fake-provider Axum route. Enforce raw size/read deadline before
parsing; verify HMAC over the exact bytes with the configured account secret
using existing HMAC/SHA-256 support and constant-time verification. Fake headers
carry an account/event identifier, signed timestamp and signature; accept at
most five minutes of clock skew. Normalize only after verification. No custom
cryptographic algorithm or protocol generalization is required.

Uniqueness is provider-account/event ID; bind it to execution, body hash and typed
payload. Same identity/different content rejects. Commit receipt before ACK;
duplicates ACK only after recognizing the identical durable row. Invalid input
or signature rejects; storage/capacity failure returns retryable failure.
Application transaction marks receipt consumed while recording the checked
provider fact/transition; domain application follows the independent fact path.
Out-of-order pending events cannot regress delivered success. A contradictory
terminal event is conflict evidence, not an overwrite. Unknown execution is not
ACKed as applied; retain only if it fits a separately bounded uncorrelated inbox
policy, which G5 does not introduce.

Due indexes cover first submission, polls/reconciliation, lease expiry, inbox
application and unapplied facts. Eligibility keys are
`(work_class, next_eligible_ms, execution_id)`; a due sweep captures its `now`
cutoff and greatest currently eligible full key, then advances a full-key cursor
within that bound. Inbox/fact sweeps instead use their stable row identities.
Backoff after a visit places renewed work beyond the captured cutoff. Each class
has bounded turns. Advance after rejected/capped
rows; cycle classes and wrap completed sweeps so backdated insertions are found.
Persist scan progress with the effect state or safely restart a bounded sweep;
neither restart nor a permanently blocked first row can starve later eligible
work. Backoff/budgets live in durable state. Report oldest eligible age, expired
leases, blocked applications, uncertain outcomes and rejected hints.

Pure signing/read-only grants are explicitly deferred beyond G5: they do not
need a durable execution lifecycle. A later grant function must use current
authority, pinned account/object identity, bounded expiry and a mature provider
SDK. If a grant's lifetime constrains cleanup, persist that domain obligation
atomically; a signed URL alone is not durable cleanup scheduling. No live S3,
email, payment, recurring schedule or provider-specific business workflow is
included here.

## Restore, activation, reset and evidence retention

Every worker activation gets a fresh unpredictable identity before claims are
enabled. Restart clears old activation ownership; unresolved started work still
requires reconciliation. Stable execution/provider keys survive activation.
This fences stale local completion but cannot stop a paused remote call.

Restore writes and checks a temporary store as today, then publishes it with
dispatch disabled, a fresh activation identity, no live old claims and quarantine
on every unresolved execution, including succeeded/pending or blocked domain
application. Preserve source, execution and provider idempotency identities.
Allow safe reads and an explicit reconciliation-only activation; submission
cannot bypass per-row quarantine. Remote-confirmed outcomes can be applied;
empty lookup remains uncertain, even if the backup contained no start marker.
Never infer nonexecution from an old backup. Inconclusive rows require an explicit
provider-specific resolution, not a force-ready switch. No such unsafe override
is exposed in G5.

One restored writable copy replaces the old one after workers are stopped.
Do not promise simultaneous active clones or distributed activation fencing.
The test must restore a snapshot taken **before** provider start while the
provider journal already contains success, then resolve with exactly one remote
acceptance and no resubmission.

Reset requires the existing expected store UUID and a stopped worker. Reject
reset with any unresolved execution, unapplied fact or unapplied inbox row;
there is no abandonment override in G5. A clean reset changes store/activation
identity; old hints/claims/receipts fail. Never ACK a late old-execution webhook
as an event for a new source. Keep effect/inbox/fact rows for the lifetime of
the bounded store. Automatic retention/pruning, migrations and account deletion
with archived executions need separate gates.

## Implementation checkpoints and acceptance

**G5a — atomic intent, types and complete inventory.** Implement typed fake
preparation, immutable execution rows, exact transition functions, capability
catalog/status/cancellation, common mutation staging integration and complete
inventory/codec/integrity/backup handling. Exercise replay/content conflicts,
authorization, expiry, source reuse and full physical rollback after actual
intent/receipt/index writes. Fill 64 unresolved and 256 retained rows, reject
the next insertion with unchanged application bytes and no operation receipt;
duplicates replay even at capacity. Record format/model identities and complete
observations. This checkpoint alone proves no provider delivery.

Until G5c quarantine handling is implemented, restoring any effect-bearing store
must reject activation or leave dispatch durably disabled. G5a backup support
does not authorize an interim restore path that can submit restored work. This
safety restriction remains explicit in tooling/checkpoint documentation until
the predating-snapshot acceptance has passed.

**G5b — bounded worker and independent provider.** Implement fenced claim,
start, finish, safe retry, waiting/uncertain reconciliation, bounded scan and the
separate fake HTTP journal. Run the literal authenticated workflow and application
failure/retry through actual shared mutation/invariant/index paths. Kill actual
backend processes before start, after start, after provider acceptance and after
fact commit. Verify duplicate claim losers do no provider work, stale completion
cannot commit, renewal/budgets terminate, cancellation behavior is conservative,
and missed wakes/restarts/backdated rows do not lose work. Observe provider calls
and accepted actions separately. No Rust-only mock substitutes for these tests.

**G5c — durable ingress and storage lifecycle.** Implement signed bounded
webhook ingress, inbox rediscovery/deduplication/conflict handling and monotone
typed transitions; test invalid signature/timestamp, duplicate/conflicting IDs,
failed inbox storage, delayed and out-of-order delivery, full-capacity retry and
fact/application atomicity. Prove restore quarantine with the predating snapshot,
new activation fences, reset rejection and a clean reset's old-identity controls.
Restore/check the full bounded store and demonstrate that receipt archiving does
not erase effect evidence. Verify compiled action-version mismatch rejection.

For every checkpoint preserve independent expectations, concrete source/build
fingerprints and current limits. Run formatting/Clippy, affected native controls
and the changed optimized real-process workflow with one build owner. Repeat an
existing population or full optimized Rust campaign only when a changed contract
requires it; accepted evidence remains dated. Native execution, durable atomicity, authentication,
crash recovery and capacity remain unaccepted until those checkpoints execute.
No frontend or production/distributed/exactly-once claim is implied.

## Executed logical transition probe

Command, run on 2026-10-23:

```sh
python3 -B research/experiments/effect_lifecycle.py
```

The standalone dependency-free probe passed **14 named logical expectations**
and rejected **24 named unsafe controls**. Its JSON output includes its own
source SHA-256 and all names. It uses immutable logical rows and copied snapshots,
with an independent provider journal; symbolic identities stand for fresh UUIDs.
It imports no implementation or repository state. It is not a storage engine,
worker, cryptographic verifier, HTTP test or proof of production conformance.

The positive expectations cover atomic abort visibility; one execution on
replay; expired-start uncertainty; durable success despite rejected domain
application; exactly-once logical application retry; fact retention after
revocation; cancellation uncertainty and a previously authorized remote call;
prestart-backup reconciliation without remote resend; inconclusive empty lookup;
inbox-abort absence; duplicate durable ACK; source/execution separation; and
replay at the unresolved cap.

The exact rejected controls are:

```text
atomic_intent_abort
rebind_operation_content
duplicate_claim
provider_call_before_marker
requester_revoked_before_start
stale_claim_start
resubmit_expired_started
finish_after_lease_expiry
cancel_before_start
late_cancelled_worker_completion
confirmed_event_cannot_regress_prestart_cancellation
restored_dispatch_disabled
prestart_snapshot_cannot_resubmit
old_activation_completion
empty_lookup_authorizes_no_resend
unverified_webhook
no_ack_on_inbox_failure
event_id_conflicting_body
claim_after_request_expiry
start_after_request_expiry
requester_revoked_before_claim
fourth_provider_submission_attempt
sixty_fifth_unresolved
two_hundred_fifty_seventh_retained
```

`unverified_webhook` supplies a logical verification result; it does not test
HMAC. `atomic_intent_abort`/`no_ack_on_inbox_failure` discard candidate snapshots;
they do not establish redb rollback. Byte-budget, scan fairness, action-version,
reset, waiting-event ordering and real clock/network controls remain native G5
acceptance obligations, not results of this probe. The probe closes the selected
transition ambiguities and intentionally stops short of a parallel runtime.

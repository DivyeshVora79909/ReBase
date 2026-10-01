# Core stabilization handoff

Updated 2026-09-29. **Start here for core work.** This file retains K1–K5
acceptance and restart requirements. The [core audit](./core-audit.md) and its
linked evidence are canonical for current findings and checks; the
[accounting handoff](../all-in-accounting/implementation-handoff.md) owns
current H1–H8 domain status and evidence. The larger system plan is historical
context.

## Current assignment

Stabilize the compiler, ordered calculation engine, authorization, and durable
operation runtime one bounded packet at a time. Accounting, logistics, resource
exchange, and basic assembly are active domain scope under the
[revised blueprint](../all-in-accounting/blueprint.md); CRM/HRM remain future
scope. For latest core outcomes and limits, use the [audit](./core-audit.md)
and its evidence. For settings use [configuration](./core-configuration.md);
for credential ownership use the [credential contract](./credential-ownership-contract.md).
Open only the active packet's source list below. Live providers, production
rollout, and representative resource bounds are not established by disposable
or mock-backed checks.

## Requirements that override older plans

1. **Direct client table access requires authentication.** Anonymous actions
   enter through a narrow trusted boundary. They never get generic privileged
   record CRUD, credential selection, or arbitrary-recipient access.
2. **Two reusable credential families are required:** email and phone/SMS.
   Keep the existing typed fields and reuse the two existing delivery-config
   tables where possible. Platform records owned by `rebase_group:root` and
   tenant BYOC records are both valid. Developers provision and bind them;
   the engine does not create provider accounts, defaults, tenants, or policy
   hierarchies. Auth, CRM, and HRM should be able to use the same records.
3. **An organization has its own identity. A user already has an identity.**
   A personal treasury, stock, or tax account must be able to belong to that
   user without an artificial organization/book. Record ownership in the core
   already supports users and groups. H1 now defines direct user/organization
   economic identity in the accounting profile and verifies a bounded mapping
   fixture. A full populated migration from a deployed older profile remains
   open. The older organization/book requirement is an upstream design
   assumption, not evidence of a smaller model inventing it.
4. Preserve explicit valid configuration values, including `false` and zero
   where the particular setting allows zero. Do not replace validation with
   blanket `value || default` fallbacks.

`rebase_group:root` is a business authorization record. It is **not** a SurrealDB
root login, namespace/database system user, or automatic bypass of native
`PERMISSIONS NONE`.

## Baseline and what can be retained

- Original handoff marker: `9581208`; audited HEAD: `a6626c0`. The working tree
  contains substantial subsequent uncommitted and untracked work. Preserve it.
- Recorded baseline passes: compiler, environment, authentication unit, architecture,
  direct-reader/security/audit, full runtime fixture, queue/adapter unit,
  typed trees, multiple positions, complete-key summaries, derived ordering,
  required outputs, causal outputs, and quick temporal integration.
- Retain typed `datetime`/`int` ordering, finite owner/slot declarations,
  state-passing deletion repair, private managed outputs, final transactional
  validation, direct-parent readers, field-selected audit, native Node HTTP,
  one-shot execution identities, and durable SurrealDB task/receipt truth.
- The runtime fixture uses disposable SurrealDB/Redis and mock providers.
  Passing it does not establish live-provider behavior. K2 now verifies the
  Redis live-hint cap with an atomic admission check; the separate dead-letter
  age policy does not imply a hard byte or process-memory bound.
- Full `npm run verify`, live services, large-load resource bounds, full-width
  numeric transport, and production rollout are not certified by this audit.

## Ordered work packets

K1–K5 are complete on the recorded working snapshot (see the linked core audit
and evidence). Do not start all domain packets together. A packet may need
several turns; checkpoint exact progress instead of reopening the full history.
Model allocation is a routing guide, not correctness evidence.

### K1 — Scheduled work reaches its queue horizon — complete

**Suggested executor:** Luna or Sol. **Problem:** the queue admits at most five
minutes ahead, but the default reconciler sleeps thirty minutes after each
scan. A task due in ten minutes can be admitted twenty minutes late, even
with no backlog. The pending query separately hardcodes `"5m"`.

**Read:** `config/environment.js`; `gateway/reconciler.js`;
`gateway/runtime.js` (`enqueue`, `reconcile`); `gateway/store.js`
(`pendingPage`); existing corresponding cases in `dev-tools/runtime-probe.js`.

**Original acceptance criteria:**

1. Add one deterministic failing case for admission on time without manual
   reconciliation: task due beyond the horizon, no subsequent client write,
   startup scan followed by timer-driven scans. Use a controlled clock or
   scaled durations; do not wait thirty real minutes.
2. Use a single horizon value in queue admission and the database query.
   Retain five minutes initially. Make the default scan cadence shorter than
   that horizon; a one-minute base cadence is an initial implementation
   choice, not a guarantee under backlog. Validate unsafe combinations.
3. Bound each scan, then continue promptly when a page is full. Avoid an
   immediate busy loop when capacity is exhausted. Maintain the persisted
   cursor and table/context fairness. Scanning all future tasks into Redis is
   not a solution.
4. State the scheduling contract: prompt admission under spare capacity;
   durable eventual recovery plus observable queue age under saturation.
   Include scan duration and number of pages/contexts in any lateness bound.
5. Update configuration docs/default examples with the actual implementation.

**Acceptance:** default-equivalent timer case passes; changing an internal
horizon affects both paths; future tasks stay outside Redis until eligible;
multi-page and capacity-deferral cases progress after recovery; configuration
probe and runtime probe pass. No tree/domain suite is needed for this packet.

**Implementation and verification:** `config/runtime-timing.js` owns the shared
five-minute milliseconds value and SurrealQL duration formatting. The process
default is one minute; validated profile intervals must be shorter than the
horizon. Runtime passes the formatted horizon into `pendingPage`. Reconciler
immediately follows an unfinished page only when every item was admitted; it
waits the regular interval after deferral/error. `.env.example` reflects the
new default. `npm run probe:scheduling` and `npm run probe:environment` passed
on 2026-09-28. The full disposable runtime regression passed on the same date,
closing K1. It exercises the real runtime and SurrealDB query path; the
scheduling probe's controlled clock remains a stub-store test.

### K2 — Atomic queue capacity admission — complete

**Problem found at baseline:** a producer could pause after its final lease
check, outlive the Redis lock, and later add a hint above the cap. The retained
[historical reproducer](./evidence/admission-lock-expiry.cjs) obtained three
live hints with a configured limit of two before this fix.

**Read:** `gateway/queues/{bullmq,port}.js`; shared-admission cases in
`dev-tools/runtime-probe.js`; installed BullMQ **6.2.0** backend/add-job code.
Inspect the installed version: do not assume a BullMQ 5 `Scripts` API.

**Original acceptance criteria:**

1. Turn the audit interleaving into a regression that requires the cap to hold.
   The audit specimen currently asserts that the old bug is reproduced; it
   is evidence, not a passing correctness test to add unchanged to `verify`.
2. Write down the exact Redis linearization point. The capacity decision and
   admission mutation must share an atomic boundary, or use an equivalently
   fenced reservation whose stale producer cannot consume reclaimed capacity.
   A longer lock TTL, another JavaScript check, or a heartbeat alone cannot
   close this race.
3. Keep one BullMQ work queue, stable versioned job IDs, operation/receipt
   priority, and receipt headroom. Reuse a supported backend extension if one
   fits; do not edit `node_modules`, replace BullMQ wholesale, or add a generic
   transport framework. Check delayed and prioritized insertion paths.
4. Cover the paused-producer interleaving, producer death before insertion,
   Redis reconnect, duplicate identity at capacity, completion/re-add, and
   separate clients. Failed admission must leave the durable source
   recoverable without a leaked capacity reservation.

**Acceptance:** reproduce the original pause interleaving with live count
never above the configured cap; preserve operation limit `max - reserve` and
receipt total limit; queue and runtime probes pass. Record any dependency on
BullMQ internals and pin compatibility. Redis Cluster is not an existing
certified deployment target; do not claim support by inference.

**Implementation and evidence:** `gateway/queues/atomic-admission.js` wraps
BullMQ's Redis backend factory. For the three job-insertion scripts used by
BullMQ 6.2.0, it adds a live-state count and capacity decision inside the same
Redis Lua invocation as job insertion, after duplicate/deduplication handling
and immediately before the job hash is stored. Lua serial execution is the
linearization point. The guard counts wait, paused, prioritized, delayed, and
active jobs; operation jobs use `maxLiveHints - receiptReserve`, while receipt
jobs can use the full cap. `publish` maps the script's capacity result to the
existing deferred response. The old distributed admission lease and split
pre-count were removed. The adapter checks BullMQ's exact version and fails
fast if the internal script shape or insertion markers change.

`npm run probe:admission` pauses a producer process before queue insertion,
fills the cap from a separate process using prioritized and delayed jobs, then
confirms the resumed producer is rejected without exceeding the cap. It also
checks duplicates at capacity. `npm run probe:queues` and the disposable
`npm run probe:runtime` pass, including receipt reservation and recovery after
Redis returns. The old lease-expiry file is historical failure evidence; the
passing regression is `dev-tools/admission-capacity-probe.js`. Redis Cluster
is not certified.

### K3 — Bound dead-letter retention — complete

**Baseline problem:** `operations-dead` received jobs but had no consumer or
pruner. Its `removeOnComplete` setting did not trim jobs left waiting.

**Read:** `deadLetter` and `health` in `gateway/queues/bullmq.js`; dead-letter
case in `dev-tools/runtime-probe.js`; durable task outcomes in `gateway/store.js`.

The policy applies to the state actually stored: failed durable business work
remains in SurrealDB; expired Redis diagnostics do not erase recoverable task
truth. The probes cover repeated failures, multiple producers, and restart.
Health reports live hints and retained diagnostics separately. An age policy
does not bound bytes or process memory.

**Acceptance:** a short test retention removes diagnostics after repeated dead
letters; necessary task outcome remains queryable; pruning/retry is idempotent;
focused queue/runtime checks pass. No environment setting was exposed because
the fixed retention policy is sufficient for this core path.

**Implementation and evidence:** the dead-letter queue now removes waiting
diagnostics older than 30 days, using BullMQ's `clean(..., "wait")` operation.
A single in-flight cleanup is triggered at startup and once per minute; each
pass handles up to 1,000 entries. A restart immediately begins another pass.
The focused `npm run probe:dead-letters` uses a short test retention to cover
repeated failures from two producers, batched periodic pruning, restart
pruning, and unchanged source-failure markers. The full runtime probe also
confirms SurrealDB's failed task outcome remains after its Redis diagnostic is
removed. This is age-bounded diagnostics, not a strict count, Redis-memory, or
RSS limit.

### K4a — Specify credential ownership and use with two tables — contract recorded 2026-09-28, refined 2026-09-29

**Suggested executor:** Luna, small contract/documentation task before edits.

**Read:** `framework/authentication.surql` (first 42 lines);
`gateway/authentication.js` (`findDeliveryPolicy`, challenge enqueue);
`gateway/operations/authentication-delivery.js`; `src/generators/security.js`;
framework-table discovery in `dev-tools/compiler/pipeline.js`.

Keep `rebase_email_delivery_config` and `rebase_sms_delivery_config` as the
initial names to minimize migration. Write a short matrix covering:

| Actor/action | Required behavior |
|---|---|
| Anonymous direct CRUD/read | Denied on every credential table and secret field. |
| Developer with system connection | Can provision platform/BYOC records and select deployment bindings. |
| Credential owner/delegated administrator | Can manage only authorized metadata and credentials; secrets never become generally readable. |
| Authenticated permitted consumer | Can reference/use an authorized config through a specific operation without receiving secrets. |
| Unrelated authenticated user | Cannot use an inaccessible config through a root-service confused-deputy path. |
| Anonymous challenge caller | Trusted service selects identity, recipient, channel and config; caller cannot supply arbitrary privileged targets. |

Use existing ownership/group/operation permission concepts, with explicit
native policies where required. **Every framework table is currently classified
as a system table and bypasses generated ownership/RLS.** Merely adding
`owned_by` or placing a table under `framework/` will not install these rules.
Keep secret values out of SELECT projections, value audit, queues, and logs.

The existing private `rebase_authentication_delivery_policy:default` is a
developer-populated auth binding, not another credential family. It can remain
for continuity; it must not grow into automatic provisioning or a generic
credential policy system. The request for two tables does not require deleting
challenge, identity, or durable delivery-task infrastructure.

**Outcome:** the actor/action map, current access gaps, platform binding rule,
BYOC ownership/use distinction, and K4b cases are recorded in
[`credential-ownership-contract.md`](./credential-ownership-contract.md).
This closed the design packet before implementation. K4b later confirmed the
native policies and source guards in the linked evidence. The refined boundary
is: platform root credentials are invisible and unwritable to clients, with
IDs resolved only through fixed trusted bindings; authenticated BYOC
owners/delegates may
write secret fields through a write-only path but may never select them back.
An operation must establish authority before privileged secret loading.

### K4b — Implement and prove the small credential contract — complete

**Suggested executor:** Sol. Implement the accepted K4a matrix. Reuse the two
typed tables in ordinary mock email/SMS operations as well as authentication.
Consolidate the test email-config duplication as a fixture migration; defer
CRM/HRM feature work. Retain expiry, attempt limits, single use, revision/nonce
fencing, uniform responses, and encrypted atomic challenge/task creation.

**Acceptance:** root-group-owned shared config and user-owned BYOC config both
work with local mock transports; root-config direct CRUD/metadata access,
secret reads, unauthorized BYOC use/writes, cross-context record spoofing, and
anonymous CRUD fail; owner-scoped BYOC secret writes succeed without returning
the value. Auth/security/runtime checks and affected compiler artifacts pass.
No real message is sent by a verification probe. Email/SMS availability is a
developer deployment precondition, not something the core provisions.

### K5 — Integration and release evidence — complete

**Suggested executor:** Sol. After K1–K4, rebuild/check the test and all-in-one
profiles with the same explicit configuration used for their check. Validate
schema and migration artifacts. Run the full `npm run verify` once against
the final source snapshot. Also run `node dev-tools/temporal-tree/positions-probe.js`
if its source fingerprint changed: it is **not included** in today's `verify`.

The [K4b/K5 evidence](./evidence/2026-09-29-k4b-credentials.json) records the
whole dirty-worktree fingerprint, commands, approximate durations, and limits;
it has no per-file K4b/K5 hashes. One full attempt stopped at dead-letter queue
readiness; the standalone probe and later full run passed, so that failure was
not reproduced. H7/H8 enforce gross input through the schema-owned
`stock_account.z_gross_input` root; H5a alone remains an account floor. Domain
fixture limits and H8 lifecycle details are maintained in the accounting
handoff. The bounded fixture is not a migration and excludes workforce and
costing.

## Work discipline for every packet

1. `git status --short`, then the packet's scoped diff, including untracked
   files. Do not reset the tree, rename broad layers, or assume HEAD contains
   the implementation being tested.
2. State the invariant and smallest failing case before implementation. Reuse
   an existing disposable fixture. Do not source the personal `.env` for probes.
3. Make one coherent change; run focused checks after it. Reuse unchanged
   evidence. Parallelize independent reads and small checks; avoid concurrent
   heavyweight DB probes when measuring their durations.
4. After two repetitions of the same unexplained failure, retain the minimal
   input, exact error, source fingerprint, and hypothesis. Seek lead review or
   reduce the case; do not widen the framework or rerun the full suite blindly.
5. Finish with the changed contract/files, checks with timings, limitations,
   and next packet. A successful import or plan checkbox is not runtime proof.

### Restart instruction

Read this handoff and the [core audit](./core-audit.md), preserve the dirty
tree, and continue only the selected K packet. Read the accounting handoff for
domain work. Reuse evidence within its recorded profile and limits; do not
infer statutory completeness, production migration, live-provider behavior,
or physical cost from functional fixtures. Never source personal `.env` or
contact real providers for these checks.

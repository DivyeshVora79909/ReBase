# ReBase Architecture

Status: canonical project architecture

ReBase is a database-centered backend framework. Clients authenticate and query
SurrealDB directly; the Hono runtime exists only for privileged provider work,
managed queues, webhooks, and scheduling. SurrealDB remains the source of truth
for data shape, authorization, reference validity, and user-facing effect state.

## Design invariants

1. SurrealDB owns authentication, row/field authorization, schema validation,
   references, audit, and current user-facing effect state.
2. Application tables are strongly typed and domain-specific. A central generic
   execution table is not required for dispatch.
3. An effect handler is identified by table name. Namespace and database select
   data context; trigger/process type selects an adapter.
4. Sync events, async queue delivery, schedules, webhooks, and reconciliation
   invoke the same stateless table handler contract.
5. Queue envelopes contain only `{ namespace, database, id }`. Handlers reload
   committed state and declared references.
6. Effect records contain generated durable lifecycle facts such as leases,
   wake deadlines, cancellation, and final outcome, but never SQS receipt
   handles, BullMQ attempts, visibility deadlines, or queue retry counters.
7. Runtime patches are restricted to domain fields in the compiler-generated
   build contract; handlers do not duplicate output metadata.
8. Duplicate delivery is normal. State checks, conditional updates, stable
   idempotency keys, and provider reconciliation provide safety.
9. External APIs are never transactionally atomic with SurrealDB.
10. SurrealDB-version-sensitive behavior remains probe-gated.
11. Anonymous recovery and OAuth verification are narrow access adapters. They
    do not create tenant contexts or introduce a second identity store.

## Independent execution axes

`sync`, `async`, `queue`, and external capability responses are properties, not
a Cartesian-product mode registry:

| Axis | Values | Question |
| --- | --- | --- |
| Completion | inline / durable | Does the caller wait for the handler result or receive a pending record? |
| Trigger | client write / schedule / webhook / repair | What caused the record to be created or revisited? |
| Provider actor | client / platform worker | Who communicates with the external service? |
| Result | database data / bounded capability | Is the result stored data or a token, URL, or grant used elsewhere? |

The table declaration selects the invocation adapter; the handler does not gain
a different identity for each combination.

## Table families

### Storage tables

Storage tables hold ordinary business data, configurations, templates,
credentials, and metadata. They do not directly represent one external side
effect. Examples include `email_brevo_config`, `file_storage_config`, and
`invoice`. Recurrence lives on the ordinary typed effect row rather than a
separate schedule/template table.

### Effect tables

An effect table represents one externally meaningful operation and its current
user-facing projection. It is simultaneously the validated request and current
result, but it is not a transport queue or immutable attempt ledger.

Examples include `send_brevo_email`, `razorpay_order`, and
`test_attachment`. An effect table declares, directly or through markers:

```text
table name
process: sync | async
handler input fields
runtime-owned output fields
record references and delete policies
optional provider, timeout, schedule, and webhook declarations
```

Common fields are domain-dependent, but normally include a SurrealDB-generated
record ID, `owned_by`, timestamps, provider correlation, bounded result and
error fields, and optional scheduling fields. Async tables receive
compiler-owned `rebase_*` lease, wake, cancellation, outcome, error, cursor,
and computed-status facts; queue attempts remain in BullMQ.

## System flow

```text
client
  -> SurrealDB validation + set-based authorization
      -> sync event  -> Hono -> table handler -> provider -> bounded patch
      -> async event -> Hono -> managed queue -> worker -> table handler -> patch

provider webhook
  -> raw-body signature verification -> correlation -> bounded patch

scheduler/reconciler
  -> due or unfinished effect IDs -> same managed queue and handler
```

## Account access adapters

The principal row remains the only account identity. Email and optional
username are normalized in SurrealDB and protected by native unique indexes.
Account signin accepts either identifier. Invite redemption and password
recovery use the same unique, expiring `invite_token`; recovery rotates that
token and extends its deadline without clearing the current password. This
keeps an unauthenticated request from disabling a valid login before the email
recipient proves possession of the token.

Anonymous recovery accepts only contexts from the deployment allowlist, applies
per-address and hashed context/identifier limits, and returns one generic
response for existing, absent, and disallowed records. Platform-owned recovery
email is configured in the deployment profile and is separate from tenant BYOC
email configuration records.

OAuth is signin-only. A generated record access method sends the opaque provider
token to an authenticated internal runtime endpoint. An injected provider
adapter returns only `{ verified, email }`; SurrealDB then selects an existing,
login-enabled principal in the current namespace/database. The runtime stores
no provider subject, creates no principal, consumes no invite, and provisions no
namespace or database. Builds without a complete runtime binding omit the OAuth
access method.

The detailed registry and adapter contract is in
[`runtime-dispatch.md`](./runtime-dispatch.md). Engine transaction facts are in
[`../surrealdb/synchronous-events.md`](../surrealdb/synchronous-events.md) and
[`../surrealdb/async-events.md`](../surrealdb/async-events.md).

## Synchronous effects

Use sync for bounded capability issuance, quotes, reads, previews, credential
verification, or provider operations whose ambiguity and recovery semantics are
acceptable.

```text
client mutation
  -> SurrealDB validates provisional record
  -> synchronous event posts compiler-selected $after fields
  -> Hono dispatches handlers[table] and awaits the handler
  -> handler returns an allowlisted patch
  -> event applies patch inside the transaction
  -> transaction commits
  -> query re-selects record
  -> client receives committed result
```

The event must send a bounded provisional snapshot because a separate runtime
connection cannot read the uncommitted record. A plain `CREATE ... RETURN AFTER`
does not include a nested event update on SurrealDB 3.2.0; generated sync helpers
capture the returned ID and re-select:

```surql
LET $created = CREATE ONLY test_attachment SET
    owned_by = $auth,
    storage_config = $storage_config,
    attached_to = $attached_to,
    file_name = $file_name,
    media_type = $media_type,
    byte_length_limit = $byte_length_limit;
RETURN (SELECT * FROM $created.id)[0];
```

Mutable synchronous inputs require the explicit `@rebase-mutable-inputs`
declaration. The handler remains awaited inside the same transaction and each
update receives its own bounded provisional snapshot. If a future adapter moves
mutable issuance outside that transaction, it must add explicit request/result
generation fencing and base provider idempotency on `record ID + generation`.

A provider call can survive a database rollback. Sync therefore guarantees only:

```text
fulfilled committed record
  => runtime returned success and the database patch committed
```

It cannot guarantee that an absent record means the provider did nothing.

## Asynchronous effects

Use async for slow, irreversible, webhook-driven, retry-heavy, or ambiguous
provider work.

```text
client creates a validated record with generated lifecycle facts
  -> transaction commits
  -> ASYNC event posts { namespace, database, id }
  -> Hono publishes locator to managed queue
  -> worker reloads committed record and declared references
  -> conditional lease claim derives a running status
  -> handler calls provider and returns bounded patch
  -> record becomes waiting, succeeded, failed, or ambiguous
  -> webhook or reconciliation may revisit unresolved work
```

The async event is a low-latency notifier, not the durable source of truth.
Managed queue retry/redrive remains transport state. The effect row remains the
client-visible source of current business state.

Concurrent initial deliveries must not both claim a pending record. A redelivery
may recover a record after its lease expires following worker termination. Stable
provider idempotency is still required because the provider and database cannot
share a transaction.

## Locators and IDs

Effect tables do not declare an application-managed `id` field. SurrealDB
generates the record key; runtime locators preserve that returned key verbatim.

Infrastructure boundaries use the full locator `{ namespace, database, id }`.
The record ID contains the table and selects the handler, but it is scoped to a
database. UUID entropy is not logical idempotency: retrying the same submission
with a new UUID creates a different effect. See
[`../surrealdb/uuidv7-record-ids.md`](../surrealdb/uuidv7-record-ids.md).

## References and provider credentials

Client-supplied record fields receive strict types, native delete behavior, and
compiler-generated existence assertions. On the supported version,
`ASSERT record::exists($value)` rejects both missing and client-hidden rows in a
field assertion. This is a version-sensitive authorization boundary documented
in [`../surrealdb/reference-authorization.md`](../surrealdb/reference-authorization.md).

Provider configuration model:

- make harmless configuration metadata selectable under normal row policy;
- hide credential fields with field permissions and redact them from audit data;
- require the authorized owner to store provider fields directly in the typed
  configuration row; there is no `env:` or `secret:` naming contract and no
  platform fallback;
- keep the physical object-storage bucket in the deployment profile as one
  shared `REBASE_STORAGE_BUCKET` value; namespace/database hashing in object
  keys provides tenant isolation without repeating the bucket in every row;
- for shared integrations, keep the configuration row owned by `groups:root`
  and make only its harmless metadata visible; clients can reference the row
  while the credential field evaluates to `NONE` in their session;
- send only configuration record locators for credential access in sync snapshots
  and queues; the privileged runtime loads the declared configuration reference
  immediately before provider work.

An event’s privileged ability to dereference a row does not prove that the
triggering client was allowed to use it.

## Reconciliation

For each selected namespace/database, one generated SurrealQL request queries
every compiled async effect table for indexed unleased, due, ambiguous, or due
scheduled records and returns their IDs. The
runtime republishes the same locators.

Reconciliation is a correctness sweep, not the primary dispatch path. Do not
query SQS for exact membership; duplicate enqueue is expected and must be safe.
Deployment-level context discovery and schedule timing are owned by
[`scheduler.md`](./scheduler.md).

## Webhooks

Webhooks are external input adapters, not handler identities. The route must:

1. preserve the raw body;
2. verify the provider’s official signature, timestamp, and replay rules;
3. derive a provider event/deduplication key;
4. open a runtime-authenticated route capsule or correlate an indexed provider
   object ID;
5. load the capsule's referenced configuration and verify the provider
   signature with that configuration;
6. apply an idempotent, allowlisted patch;
7. acknowledge only after the local update is durably accepted.

Never trust namespace, database, table, or record ID merely because an
unauthenticated payload contains it. Internal database-to-Hono wakes use a
separate deployment credential or workload identity, strict body/time limits,
and preferably a private network.

## Schedules

A schedule is a time-based input adapter over an ordinary effect. At the due
time it copies validated inputs and `owned_by` into a fresh record in the same
effect table, clears schedule-only fields, lets SurrealDB generate its record
ID, and then follows the normal async path. The occurrence does not require a
template reference.

Repeated alarms are repeated submissions. Provider idempotency or an
effect-specific policy decides whether they are harmless or intentionally
distinct. Detailed timing, catch-up, and optional heap strategies are in
[`scheduler.md`](./scheduler.md).

## Responsibility matrix

| Owner | Responsibilities |
| --- | --- |
| SurrealDB | Authentication, table/row/field authorization, schema/assertions/references, sync transaction, async notification trigger, audit, current effect and schedule records. |
| Hono runtime | Internal wake authentication, stateless OAuth verification, rate-limited recovery mail, registry lookup, privileged declared-reference loading, provider SDK calls, queue adapters, webhook verification, reconciliation orchestration, operational telemetry. |
| Managed queue | Delivery retry, visibility timeout, redrive, dead-letter transport, and queue-level concurrency. |
| Provider | External object state, signatures/webhooks, provider idempotency, expiry/revocation, and reconciliation APIs. |

## Compiler contract

The compiler must:

1. discover storage/effect declarations from SurrealQL syntax and markers;
2. validate each effect table against exactly one table handler;
3. let SurrealDB generate effect IDs and generate lifecycle fields, field
   permissions, and indexes;
4. generate record-reference assertions;
5. generate bounded sync snapshot and async locator events when deployment
   context is supplied;
6. emit a private runtime contract that drives principal discovery, patch
   allowlists, reference loading, schedules, webhooks, and reconciliation;
7. copy validated table handlers into the build artifact;
8. keep deterministic output and architecture probes in the upgrade gate.

Deployment configuration is supplied through an explicit environment profile.
`SURREAL_NAMESPACE` and `SURREAL_DATABASE` select the default database context;
`REBASE_RUNTIME_URL` and `REBASE_RUNTIME_SECRET` enable generated runtime events.
Either pair may be omitted for context-neutral compilation. Partial pairs are
ignored with a concise compiler notice. Runtime modules receive resolved config
objects and do not read process environment directly.

Gateway database connections use the SDK authentication provider so finite
system-user JWTs renew before expiry and authentication is restored after a
WebSocket reconnect. Record-access clients have a separate lifecycle described
in [`session-lifecycle.md`](./session-lifecycle.md).

It must not generate an operation catalog, universal job schema, namespace-
specific behavior registry, duplicated queue mechanics, or a second client CRUD
authorization layer.

## Adding an integration

1. Add a storage/config table if the provider requires reusable context.
2. Add one strongly typed effect table shaped for its request and current result.
3. Mark handler inputs and runtime-owned outputs.
4. Add one `table-handlers/<table>.js` module.
5. Add a self-describing named adapter under `gateway/providers/` and export it
   from the static `createAdapters()` registry.
6. Build; validation must reject handler/table/process/output drift.
7. Add a disposable probe for provider transformation and failure semantics.

The test design intentionally covers the broad examples:

- `email_brevo_config`: selectable configuration with hidden credentials;
- `send_brevo_email`: durable async effect, queue/retry/reconciliation/schedule;
- `file_storage_config` and `test_attachment`: inline bounded URL/token issuance.

## Alternatives retained for future evidence

- **Dynamic KV handler registry:** justified only when plugins deploy
  independently of the runtime; otherwise it adds activation and cache drift.
- **Central execution table:** may later support platform observability or
  cross-tenant rate limiting, but should not replace typed effect tables.
- **Capability/operation catalog:** rejected while direct typed database writes
  provide the required authentication, authorization, and validation boundary.
  A separate command gateway is justified only for behavior that cannot be
  represented by that boundary; its security requirements live in
  [`runtime-dispatch.md`](./runtime-dispatch.md).
- **Queue mechanics in tenant rows:** rejected while the managed queue owns
  retries, visibility, redrive, and dead-letter transport.
- **Separate handler per invocation source:** rejected because record state, not
  caller identity, determines behavior.
- **External API transactional claims:** impossible; use idempotency,
  reconciliation, or the durable async path.

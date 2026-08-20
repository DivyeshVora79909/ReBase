# ReBase Architecture

## Invariants

1. SurrealDB owns authentication, authorization, field permissions, validation, references, audit, and user-facing effect state.
2. The runtime handler key is the effect table name. Namespace and database select data context, not behavior.
3. Sync and async are invocation adapters over the same stateless handler contract.
4. Queue envelopes contain exactly `{ namespace, database, id }`.
5. Effect tables contain business state, not SQS receipt handles, visibility deadlines, retry counters, or leases.
6. Runtime patches are bounded and restricted to fields declared by both the schema and handler.
7. Provider calls should use the effect record ID as their idempotency key when the provider supports it.

## Components

```text
client
  -> SurrealDB schema + set authorization
      -> sync event  -> Hono -> table handler -> provider -> bounded patch
      -> async event -> Hono -> managed queue -> table handler -> provider -> patch
provider webhook
  -> Hono signature verification -> table handler webhook -> bounded patch
reconciler
  -> pending/waiting record IDs -> managed queue
```

The compiler scans SurrealQL material by syntax and markers. For effect tables it validates the paired module in `designs/<project>/table-handlers/`, copies those modules into the build, and optionally generates database events for a deployment context.

## Sync Flow

Sync is for bounded capability issuance, read-like calls, verification, quotes, or provider operations with acceptable idempotency/recovery semantics.

1. A client mutation passes SurrealDB validation and permissions.
2. The synchronous event posts `id`, `owned_by`, and fields marked `@rebase-effect-input`.
3. The runtime dispatches by the table parsed from `id`.
4. The handler loads privileged referenced records as needed and calls the provider.
5. The event merges only fields marked `@rebase-effect-output`.
6. Any runtime or patch failure aborts the database mutation.

The provider call is not transactionally atomic with SurrealDB. Use sync only where that boundary is acceptable. The event snapshot exists because a separate runtime connection cannot read the provisional record before commit.

## Async Flow

Async is for externally meaningful work that should outlive the client request.

1. The client creates an immutable effect request with `effect_state = 'pending'`.
2. A SurrealDB `ASYNC RETRY 0 MAXDEPTH 0` event publishes its locator after commit.
3. The queue worker reloads the committed record.
4. A conditional database update claims `pending | waiting -> processing`.
5. The handler calls the provider and returns an allowlisted patch.
6. Retryable errors move the record to `waiting`; terminal errors move it to `failed`.
7. Managed queue retry/redrive remains outside tenant schemas.

Concurrent first deliveries cannot both claim a pending record. A redelivered queue message may recover a record already in `processing`, which covers worker termination after claim. Stable provider idempotency remains necessary because no database can make an external API atomic.

## Reconciliation

Reconciliation is a correctness sweep, not the primary dispatcher. For a selected namespace/database, one SurrealQL script returns IDs from every async effect table whose state is `pending` or `waiting` and whose optional `scheduled_for` is due. Those locators are republished to the same queue.

The current API reconciles one database context per call. A deployment-level scheduler can enumerate configured contexts and invoke it without changing handler identity or queue payloads.

## Webhooks

Webhook routes are table-keyed, but the handler must verify the provider signature before any database context or record locator is trusted. Namespace/database headers are not accepted. The verified payload supplies or correlates the effective namespace, database, and provider object; a configured default context is only for single-context deployments. Patches must target the route table and still pass through the handler output allowlist.

The local test provider uses HMAC over the raw body. Production adapters should use each provider's official verification mechanism and correlate opaque provider IDs where available.

## Effect Contract

Every effect table must have:

- `id TYPE uuid`;
- an output-marked string `effect_state` denied for client create/update;
- a handler whose `table`, `process`, and exact output set match the schema;
- at least one input-marked field for sync effects;
- `pending`, `processing`, `waiting`, `succeeded`, and `failed` states for async effects.

Every handler receives:

```js
{
  context: { namespace, database, id, table, event },
  record,
  load,
  providers,
  signal,
}
```

Handlers return `{ patch }`. They do not receive arbitrary client credentials or a general database mutation API.

## Adding an Integration

1. Add a config/storage table when provider configuration is required.
2. Add one effect table shaped for the user-facing request and current result.
3. Mark sync inputs and all runtime-owned outputs.
4. Add one module in `table-handlers/` keyed by that table.
5. Add the provider adapter behind `gateway/providers/`.
6. Build; compiler validation rejects missing handlers, process mismatches, writable outputs, and output drift.
7. Add one live probe for the provider-specific transformation and failure semantics.

Schedules remain an input adapter: at a due time, a scheduler creates a fresh ordinary async effect record with a new UUIDv7 and copied ownership/input. The resulting record follows the same event, queue, handler, and reconciliation path.

# Table Handler Registry and Dispatch Findings

Status: blank-sheet runtime design

This document intentionally supersedes the current capability/outbox-oriented
edge runtime for the redesign. Existing `gateway/` code is not a migration
constraint.

## Decision

The handler identity is the effect table name. Process type is an invocation
adapter selected by the table declaration; it is not part of handler lookup. A
handler is not a client capability, namespace, database, record ID, or event
name.

For the initial runtime, use a static build-time registry:

```js
const handlers = new Map([
  ["send_brevo_email", sendBrevoEmail],
  ["razorpay_payment", razorpayPayment],
  ["file_access_grant", fileAccessGrant],
]);
```

The record locator selects the handler:

```js
const table = parseRecordTable(locator.id);
const handler = handlers.get(table);
```

The handler is stateless and invocation-source agnostic. It does not know
whether it was called by:

- a synchronous SurrealDB event;
- an asynchronous SurrealDB event;
- SQS;
- a scheduler;
- an authenticated provider webhook;
- a periodic reconciliation pass.

All of those adapters provide the same handler input and the same output/state
transition contract.

## Why table name is sufficient

Namespace and database select the data context. They should not select behavior:

```text
locator = { namespace, database, id }
handler = registry[record::tb(id)]
```

The same `send_brevo_email` table semantics can be used by many tenant
databases. A per-tenant behavior catalog would duplicate deployment state and
make registration drift harder to diagnose.

The record ID is not globally unique across every possible SurrealDB instance,
so the queue envelope retains namespace and database even when a single current
deployment instance happens to be used.

## Build-time source of truth

Use a dedicated file rather than comments or annotations embedded in schema:

```text
designs/<project>/handlers.js
designs/<project>/handlers/send_brevo_email.js
designs/<project>/handlers/razorpay_payment.js
```

The compiler should emit a generated registry or copy a validated registry into
the build artifact. It must fail when:

- an effect table has no handler;
- two handlers claim one table;
- a handler claims a non-effect table;
- a handler module does not implement the contract;
- a handler declares an unsupported lifecycle/process mode;
- generated events refer to a table missing from the registry.

At runtime, a missing key remains a deployment error:

- sync invocation returns non-2xx and rolls back the originating write;
- async invocation logs a deployment failure and leaves the effect reconcilable;
- webhook invocation returns a controlled 4xx/5xx and does not mutate an
  uncorrelated record.

Build-time validation is the normal guard. Runtime failure behavior prevents
silent success when a deployment is inconsistent.

## Handler contract

Conceptual contract:

```js
export default {
  table: "send_brevo_email",
  process: "async", // or "sync"

  async execute({
    context,       // namespace, database, record ID
    record,        // committed record for async; snapshot for sync
    references,    // privileged, declared reference loads
    provider,
    signal,
  }) {
    return {
      state: "succeeded",
      patch: { provider_message_id: "..." },
    };
  },
};
```

The exact JavaScript shape is a compiler contract choice, but these invariants
should remain:

- input is already schema-valid;
- the handler does not trust arbitrary client-shaped objects;
- the handler can load declared references by ID;
- secret fields are loaded only in privileged runtime code;
- result patches are allowlisted by the generated schema;
- a handler is idempotent for the same logical generation/submission;
- timeout/abort signals are honored;
- provider errors distinguish retryable, terminal, and ambiguous outcomes.

The handler may transform the database shape into an SDK-specific object. The
compiler should generate useful reference metadata and aliases, but it must not
force every table schema to be identical to an external provider SDK.

## Invocation adapters

### Sync adapter

```text
Surreal sync event
  -> POST { namespace, database, event, minimal snapshot }
  -> registry[table]
  -> await handler
  -> return allowlisted patch
  -> event applies patch
```

The snapshot is necessary because the record is provisional and not visible to
a separate runtime connection. See
[SYNC-EVENT-SNAPSHOT-FINDINGS.md](./SYNC-EVENT-SNAPSHOT-FINDINGS.md).

### Async adapter

```text
Surreal ASYNC event after commit
  -> POST { namespace, database, id }
  -> queue.publish(locator)
  -> worker receives locator
  -> worker loads committed record
  -> registry[table]
  -> await handler
  -> handler writes an idempotent state patch
```

The queue envelope should be small:

```js
{
  namespace,
  database,
  id,
}
```

Do not put secrets, expanded references, or a mutable client payload in the
queue envelope. SQS owns visibility timeout, delivery retry, redrive, and
dead-letter transport behavior.

### Webhook adapter

The provider-facing adapter is not selected by the tenant record ID supplied by
the HTTP caller. It must first:

1. verify the provider signature using the configured provider account;
2. derive a provider event ID and dedupe key;
3. correlate the provider object ID to a locally indexed effect/config record;
4. verify that the provider account matches the locally referenced config;
5. apply an idempotent patch to the same effect record.

The resulting state transition uses the same table handler/reconciler when
possible. A webhook is an input adapter, not a new business handler family.

### Reconciliation adapter

Reconciliation queries declared async effect tables for records whose promise or
state is still pending. It republishes the same locator. The handler sees the
same record and decides whether work remains.

Do not make queue membership a correctness dependency. SQS does not provide a
reliable exact “is this locator currently queued?” query. A duplicate enqueue is
safe when the handler is state-driven and idempotent.

## State-driven handler model

The handler should inspect the record state before calling a provider:

```text
pending -> provider submission -> submitted/waiting
waiting -> provider query or webhook reconciliation
succeeded/failed/cancelled -> no-op (unless explicit repair)
```

This is why the same handler can be invoked by a direct adapter, a queue
delivery, a scheduler wake, or reconciliation. Invocation context is metadata;
record state is the decision.

For mutable sync grants:

```text
requested_generation = 4
issued_generation = 3
```

The handler returns the generation it processed. The database patch is applied
only if the requested generation is still current.

For async provider effects, use the stable effect record ID as the provider
idempotency key where supported. If the provider has a separate idempotency
namespace, store and reuse that key.

## Scheduled jobs

Scheduling is an adapter over ordinary async effect records, not a separate
handler architecture.

Template:

```text
send_brevo_email:<scheduled-input>
  schedule = { cron, timezone, repeats, deadline }
  state = scheduled
  owned_by = user:alice
```

At the scheduled time, the scheduler copies the input fields and `owned_by` into
a fresh ordinary `send_brevo_email` record with a new UUIDv7, clears the
schedule-only fields, and sets `state = pending`. No template reference is
required. The new record follows the ordinary async event and queue path.

Repeated alarms are repeated submissions. Provider idempotency or an
effect-specific policy handles duplicates; the dispatch registry does not need a
template/occurrence identity index.

The admin server may maintain an in-memory min-heap for a single deployment,
rebuilt from schedule records on startup. An external managed scheduler may be
used later. In both cases, database schedule records remain authoritative and a
periodic repair/reconciliation pass is required.

## Reconciliation

The minimal model is:

```text
for every compiled async effect table:
  query pending/scheduled records in one scripted request
  publish { namespace, database, id }
```

The direct record ID locators make this compatible with SurrealDB's record/range
access model. The number of tables is a compiler concern, not a reason to make a
central business table. Keep the generated query bounded and indexed by state
and due time.

Filtering out rows that are already “in SQS” is not required and should not be a
correctness condition. SQS may deliver duplicates, hide messages during a lease,
or lose a message before the repair pass observes it. The handler must tolerate
all three.

## Security boundary

The internal wake endpoint is not a public tenant API. Require at least:

- a deployment-managed authentication secret or mTLS;
- a timestamp/nonce and replay window;
- a request signature over the exact body;
- strict body-size and timeout limits;
- allowlisted network sources where available.

Provider webhooks use provider-specific HMAC/signature verification and raw-body
canonicalization. Do not rely on a generic `x-signature` header without
provider-specific verification rules.

The handler registry is trusted code. It must not be selected by a client
string, provider payload, or arbitrary table name without compiler/runtime
validation.

## What is deliberately not in the core

- no universal `edge_execution` table;
- no capability name in every queue envelope;
- no operation catalog keyed by namespace/database;
- no queue status, lease, retry, or dead-letter fields duplicated in tenant
  effect records;
- no separate handler for each source of invocation;
- no assumption that provider side effects are transactionally atomic with
  SurrealDB;
- no dynamic key-value registry until independently deployed runtime plugins
  require it.

SQS, the provider SDK, SurrealDB events, and the scheduler each retain the
responsibility that only they can implement reliably. ReBase owns the schema,
authorization, locator, handler contract, idempotent state transition, and
reconciliation policy.

## Alternatives

### Dynamic registry

Use a KV registry only if handlers are installed/reloaded independently of the
runtime process. Store a versioned module reference and validate it before
activation. This adds deployment and cache invalidation complexity and is not
the initial default.

### Central execution table

A central table can be useful for platform-wide observability or cross-tenant
rate limiting. It is not required for dispatch and should not replace the typed
effect tables. Add it later as an append-only operational index if metrics prove
the need.

### Versioned handler identity

If a table's semantics must evolve incompatibly, introduce a new table or a
compiled handler version inside the static registry. Do not make namespace or
database silently select different behavior for the same table name.

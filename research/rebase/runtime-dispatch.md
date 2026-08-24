# Runtime Dispatch

Status: adopted table-handler contract

This document owns behavior identity, handler validation, invocation adapters,
and the runtime trust boundary. End-to-end effect semantics belong in
[`architecture.md`](./architecture.md); schedule timing belongs in
[`scheduler.md`](./scheduler.md).

## Handler identity

The effect table name is the behavior key:

```text
locator = { namespace, database, id }
table   = table parsed from id
handler = handlers[table]
```

Namespace and database select data context. Record ID selects one effect
instance. Process and trigger select an adapter. None of them create a second
handler identity.

The compiler copies a directory of modules into the build artifact and the
runtime auto-discovers it into a build-validated map. Production freezes that
map after startup; controlled registration is available only for tests and
explicit local plugins. The same table semantics can run in many tenant
databases without duplicating a deployment catalog per tenant.

## Source of truth and validation

The business schema declares the effect table/process/input/output boundary.
The matching module lives in `designs/<project>/table-handlers/<table>.js`. The
compiler copies validated modules into the build artifact and rejects:

- an effect table without a handler;
- a handler for a non-effect or unknown table;
- duplicate table keys;
- missing `execute`, incompatible aliases, or unsupported module shape;
- handler-authored process/output/timeout metadata that duplicates the compiled contract;
- generated events targeting a table outside the registry.

Runtime missing-key behavior remains fail-closed:

- sync request returns non-2xx so the database mutation rolls back;
- async delivery records/logs a deployment failure and leaves the effect
  recoverable by reconciliation;
- webhook returns controlled failure without mutating an uncorrelated record.

## Handler contract

Current conceptual shape:

```js
module.exports = {
  table: "send_brevo_email",
  async execute({ record, load, providers, signal, trigger }) {
    return { outcome: "success", patch: { provider_reference: "..." } };
  },
};
```

Invariants:

- input is already schema-valid, but the handler still validates provider/domain
  facts it alone understands;
- the handler does not trust expanded client or queue objects;
- only declared root references can be loaded;
- required opaque credential fields on configuration rows are available only
  through privileged loading;
- patches are bounded by the intersection of schema and handler output sets;
- timeout/abort signals are honored;
- retryable, terminal, and ambiguous outcomes remain distinct;
- terminal records are no-ops unless an explicit repair path exists;
- provider idempotency is stable for one logical submission. Schedules create
  fresh effect IDs, so each emitted occurrence is intentionally a new logical
  submission.

The handler may freely transform database shape into SDK input. ReBase does not
require the SurrealQL schema to mirror a provider SDK object.

## Invocation adapters

### Synchronous event

```text
SurrealDB sync event
  -> authenticated POST with minimal provisional snapshot
  -> registry lookup by snapshot record ID table
  -> await handler
  -> validate/return bounded patch
  -> event applies patch
```

The snapshot contains referenced IDs and required scalar inputs, not secrets or
the complete `$after` object. It is required because another connection cannot
read the provisional row. See
[`../surrealdb/synchronous-events.md`](../surrealdb/synchronous-events.md).

### Asynchronous queue

```text
SurrealDB ASYNC event after commit
  -> authenticated POST { namespace, database, id }
  -> queue.publish(locator)
  -> worker reloads committed row
  -> conditional claim/state check
  -> registry lookup and handler execution
  -> bounded patch
```

The envelope contains no secrets, expanded references, receipt state, or client
payload. BullMQ/Redis owns local delivery retry, stalls, delay, and dead-letter
transport; other providers implement the same lane-aware port.

### Provider webhook

The route cannot dispatch from an untrusted tenant ID. It first verifies the raw
body/signature and replay rules, derives the provider event ID, correlates an
indexed provider object or signed token, and verifies the provider account. Only
then may it invoke table-specific reconciliation/patch logic.

### Reconciliation and scheduling

These adapters publish the same locator used by normal async notification. The
handler decides work from record state, not from the caller’s identity:

```text
pending/running       -> submit provider request
waiting/ambiguous     -> query provider or await webhook
succeeded/failed/cancelled -> no-op
```

## Claiming and duplicate delivery

The queue may redeliver, reconciliation may enqueue a duplicate, and a worker
may die after a provider call. Correctness therefore cannot depend on exact
queue membership or single delivery.

Use:

- an atomic/conditional claim of executable state;
- state-driven no-op behavior for terminal records;
- stable provider idempotency based on the immutable async effect ID;
- provider reconciliation for ambiguous outcomes;
- allowlisted patches and provider/account correlation.

Managed queue retry counters are not duplicated into tenant effect rows. Store
only business state the client or handler needs to understand the effect.

## Internal endpoint security

Database-to-runtime calls are trusted infrastructure requests, not tenant APIs.
Require:

- a deployment-managed bearer/HMAC credential, mTLS, or workload identity;
- exact-body authentication when using signatures;
- timestamp/nonce replay protection where the transport does not already supply
  it;
- strict content type, method, body size, and timeout limits;
- private networking and source allowlists when available;
- a narrow SurrealDB `--allow-net` rule.

Compatibility note: SurrealDB `3.2.0` does not expose an HMAC signing function
to the event query. Generated database events therefore send a deployment
bearer to an explicit runtime binding. Development may bind that URL directly
to the runtime. Production runtime instances reject bearer wakes, so the
binding must be a private trusted proxy that validates and rotates the bearer,
then forwards HMAC/workload identity/mTLS. Direct production event-to-runtime
delivery remains unsupported until SurrealDB can sign the request or another
trusted identity adapter is installed.

Do not reuse tenant bearer tokens. Do not select handlers from arbitrary client
strings, provider fields, or a table name that has not passed registry
validation.

## Deliberate exclusions

- no namespace/database behavior catalog;
- no handler key composed from process or event type;
- no universal `edge_execution` record for typed effects;
- no operation/schema discovery API;
- no unrestricted privileged database object passed to ordinary handlers;
- no dynamic registry until independently deployed plugins create a real need;
- no implicit handler-version routing by tenant context.

For an incompatible behavior change, use a new effect table or an explicit
compiled handler version. A central append-only operational index may be added
later for observability without replacing typed tables or dispatch identity.

# Historical Capability Gateway Alternative

Status: preserved historical design; not current architecture

This file preserves useful material from the earlier `STANDARD.md` capability/
outbox gateway model. It is intentionally isolated so the current table-keyed
effect architecture is not confused with the rejected alternative.

## Named edge-function contract

The earlier model exposed known JavaScript-style functions rather than a schema
write path:

```text
edge/campaignMail.js
capability: campaignMail
POST /v1/edge/campaignMail
```

Breaking changes were manually versioned (`campaignMailV2`): grant the new
capability, migrate callers, let old jobs finish, then retain/delete old code
and records as appropriate. No automatic historical payload migration was
planned.

Handlers declared a mode and named record slots:

```js
module.exports = {
  mode: "job",
  records: {
    config: "email_brevo_config",
    profile: "email_campaign_profile",
    template: ["invoice_template", "campaign_template"],
    files: { tables: ["file"], many: true, required: false, max: 20 },
  },
  timeoutMs: 60_000,
  maxAttempts: 5,
  async execute({ auth, records, args, providers, signal, execution }) {},
};
```

Record slots declared accepted tables/cardinality; transport validation checked
JSON shape, record-ID syntax, declared tables, bounded counts, and body size.
Scalar/structured arguments stayed raw JSON and were validated beside the code
that consumed them, rather than in a centralized operation-schema registry.

Example request:

```http
POST /v1/edge/campaignMail
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "records": {
    "config": "email_brevo_config:production",
    "profile": "email_campaign_profile:weekly"
  },
  "args": { "subject": "Hello" },
  "requestId": "optional-client-correlation-id"
}
```

## Historical gateway authorization flow

1. authenticate the bearer token;
2. load the current actor and graph capabilities;
3. discover the exact named handler;
4. verify the actor’s capability;
5. validate record slots, IDs, tables, cardinality, and duplicates;
6. resolve all IDs in one bounded database operation;
7. apply the same table/row select policy as direct SurrealDB access;
8. require every requested record to resolve;
9. invoke `{ auth, records, args, providers, signal, execution }`.

Unavailable, nonexistent, wrong-table, and unauthorized records were to return
a generic unavailable/not-found result so their existence was not leaked. The
gateway could use a privileged query only when the authorization predicate came
from the same shared policy source as the compiler. Handlers did not receive an
unrestricted privileged database connection by default.

## Historical execution modes

The earlier gateway distinguished:

- **request:** authorize, invoke immediately, apply timeout, record outcome,
  return result;
- **job:** authorize at enqueue, persist args/record IDs/actor/function/
  attempts/idempotency, write a transactional outbox entry, relay to a queue,
  claim with a lease, reauthorize at worker execution, then finish/retry/cancel;
- **webhook:** verify raw-body provider signatures and parse/provider logic in
  the handler while the gateway owned body limits, route lookup, deduplication,
  receipt leases, duplicate behavior, outcome persistence, and logging.

The job model explicitly retained idempotency keys, outbox delivery, leases,
lease expiry, retry limits/delay, cancellation, terminal records, and bounded
execution logs. It required worker-time reauthorization because access could be
revoked after enqueue.

Its durable records separated application behavior from provider adapters:

```text
design operation
  -> validate args and declared record slots
  -> authorize/resolve records
  -> prepare typed adapter invocation

global adapter
  -> validate adapter input
  -> resolve secret references
  -> call provider SDK
  -> return bounded result
```

An example prepared invocation was:

```js
{
  adapter: "email.sendCampaign",
  version: 1,
  input: {
    configSecretRef: "secret:brevo-primary",
    recipients: ["person@example.com"],
    subject: "Invoice",
    html: "..."
  }
}
```

The adapter could choose only compile-declared integrations and never received
an unrestricted database connection.

## Historical operational state and permissions

The durable job alternative used a state machine such as:

```text
pending -> running -> succeeded
        -> running -> pending at a future available_at
        -> running -> failed
        -> cancelled
```

Its internal fields were `available_at`, `next_dispatch_at`, `attempts`,
`max_attempts`, `lease_owner`, `lease_expires_at`, `idempotency_key`, and
`revision`. A scheduler atomically reserved due jobs, published queue hints, and
set a redispatch deadline so lost publication was recoverable and duplicate
messages were lease-claimed.

Generated operational permissions were intended to ensure that actor identity
was derived from `$auth`; capability submission was authorized; status,
attempts, leases, result, error, and revisions were server-owned; records/args
became immutable after dispatch; users could inspect/cancel only accessible
jobs; cron mutation had a separate capability; logs were server-created; and raw
args could not carry credentials. Webhook receipts could be represented as a
job kind with a unique provider event key.

The current design leaves these transport concerns to the managed queue and
keeps only user-facing effect state in typed tenant tables.

## Historical API rules

The gateway did not expose `/v1/operations`, `/v1/schemas`, or equivalent
discovery APIs. Dynamic application data belonged in ordinary context tables
with normal select/visibility rules. Read-only data denied create/update/delete.

The current architecture retains these useful security rules but replaces the
named capability/job transport with table-keyed effects and a managed queue.

## Why this alternative was superseded

- direct SurrealDB writes already provide the ordinary schema/auth/RLS boundary;
- operation catalogs and JSON Schema registries duplicated schema authority;
- namespace/database-specific behavior catalogs increased deployment drift;
- generic jobs hid typed effect state and introduced queue mechanics into the
  application model;
- the new runtime uses the same handler contract for sync, async, schedule,
  webhook, and reconciliation.

The alternative remains useful when a future product needs an external API that
cannot be represented as a direct typed effect write, or when a provider
requires a distinct command authorization model.

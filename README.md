# ReBase

ReBase compiles SurrealDB tables, graph-derived authorization, reader propagation, audit events, reactive views, and a capability-gated edge runtime. SurrealDB is the source of truth; the gateway is only for authenticated external effects, durable jobs, and webhooks.

`ARCHITECTURE.md` is the canonical engineering reference.

## Layout

```text
framework/                  Shared auth, access, audit, and edge tables
src/                        Deterministic schema compiler
gateway/                    HTTP gateway, worker, providers, and queues
designs/<name>/schema.surql Business tables and native field rules
designs/<name>/views.surql  Capability-scoped aggregate views
designs/<name>/data/        Scalar fake-data JSON Schemas
designs/<name>/edge/        Self-describing edge handlers
dev-tools/workbench.js      Interactive development shell
dev-tools/populate.js       Schema-driven random data populator
dev-tools/probe.js          Disposable live verification
```

## Commands

```bash
npm run build
npm run check
npm run probe
npm run verify
npm run gateway
npm run workbench
npm run populate -- --table all --count 100
```

The compiler emits only `build/<project>/schema.surql` and copied `edge/` handlers. It does not create operation catalogs, schema registries, manifests, or compatibility artifacts.

## Database Security

Every business table receives one model:

```surql
FOR select WHERE '<table>_select' IN $auth.permissions
  AND (!!visibility
    OR readers_index CONTAINS <string>$auth.id
    OR <string>owned_by IN $auth.z_access_index)
```

Create and update require the table capability plus a resulting owner that is the actor, a direct parent group, or a dominated principal. Delete excludes direct parent groups and requires self ownership or domination. `owned_by` also enforces one-way delegation: an owner may delegate upward to an accessible group, but cannot reclaim it merely through parent-group membership.

`visibility` is an ordinary boolean business field. An absent field evaluates false and never bypasses the table select capability.

Only `readers_index` is materialized. A scalar strict business `REFERENCE` inherits the referenced owner and readers. Arrays are excluded unless their comment contains `@rebase-readers`; marked arrays must also declare `REFERENCE`. Declarations containing `user` or `groups` never contribute readers. Groups are the sharing primitive; there is no `shared_with` model.

The compiler emits a non-materialized `rebase_reader_sources` field and cycle guard. Cyclic reader graphs fail with `REBASE_READER_CYCLE`, preventing stale access after revocation. Views intentionally use only their source-table capability and do not inject row ACLs.

## Edge Handlers

An edge function is one camelCase filename and one capability:

```js
module.exports = {
  mode: "job",
  records: {
    config: "email_brevo_config",
    profile: "email_campaign_profile",
  },
  timeoutMs: 60_000,
  maxAttempts: 5,
  async execute({ auth, records, args, providers, signal, execution }) {
    // Validate scalar args beside the behavior that uses them.
  },
};
```

The gateway validates the capability, record slots, ID syntax, declared tables, cardinality, and row access before invocation. `args` are raw JSON validated by the handler. Handlers receive authorized records, not a privileged database connection.

```json
{
  "records": {
    "config": "email_brevo_config:production",
    "profile": "email_campaign_profile:weekly"
  },
  "args": { "subject": "Hello" },
  "requestId": "optional-correlation-id"
}
```

Routes are `GET /healthz`, `POST /v1/edge/:capability`, `GET /v1/jobs/:job`, `POST /v1/jobs/:job/cancel`, and `POST /v1/webhooks/:capability`.

Jobs retain idempotency, transactional outbox delivery, leases, retries, cancellation, worker reauthorization, terminal state, and bounded logs. Webhooks retain raw-body verification, receipt leases, and deduplication.

## Development Tools

`npm run populate` reads topology from the compiled Surreal schema and scalar rules from `data/*.schema.json`. It samples committed records with keyset pagination into bounded reservoirs, inserts dependency-aware batches, and prints a replay seed.

`npm run workbench` provides `.build`, `.deploy`, `.populate`, `.as <email> <password>`, `.query`, `.sample`, `.edge`, and `.probe`.

`npm run probe` starts disposable SurrealDB and verifies ownership, visibility, reader derivation and revocation, DAG behavior, cycle rejection, handler contracts, request execution, durable jobs, worker execution, webhook verification, deduplication, schema-driven population, and replay-seed determinism.

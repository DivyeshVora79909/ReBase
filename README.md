# ReBase

ReBase compiles SurrealDB authorization, validation, audit, views, and table-keyed external effects. Clients use SurrealDB directly; the Hono runtime only performs work that requires privileged provider access.

[`research/rebase/architecture.md`](./research/rebase/architecture.md) defines
the current runtime contract. [`research/README.md`](./research/README.md)
indexes project decisions separately from measured SurrealDB behavior.

## Layout

```text
framework/                    Shared auth, access, and audit SurrealQL
src/                          Schema parser, analysis, and generators
dev-tools/compiler/           Stateless compiler stages and CLI
gateway/                      Hono runtime, providers, and queue adapters
designs/<name>/schema.surql   Business and effect tables
designs/<name>/views.surql    Aggregate views
designs/<name>/data/          Development data JSON Schemas
designs/<name>/table-handlers Table-keyed effect handlers
```

## Commands

```bash
npm run build
npm run check
npm run verify
npm run server
npm run workbench
npm run populate -- --table all --count 100
```

The compiler emits `build/<project>/schema.surql`, a private `runtime-contracts.json`, and validated `table-handlers/` modules. It does not emit tenant operation catalogs, generic job schemas, or compatibility artifacts.

Runtime event generation is explicit because namespace and database are deployment context:

```bash
node dev-tools/compiler/cli.js \
  --project designs/test \
  --namespace tenant \
  --database app \
  --runtime-url https://runtime.internal \
  --runtime-secret "$REBASE_WAKE_SECRET"
```

## Database Security

Each business table receives table permissions plus set-based row authorization:

```surql
FOR select WHERE '<table>_select' IN $auth.permissions
  AND (!!visibility
    OR readers_index CONTAINS <string>$auth.id
    OR <string>owned_by IN $auth.z_access_index)
```

Create and update require the matching table permission and an allowed resulting owner. Delete requires self ownership or domination. Direct parent groups can receive delegation, but parent membership alone cannot reclaim a delegated record.

Strict schema fields, assertions, references, field permissions, and record visibility remain in SurrealDB. The runtime receives either a compiler-selected provisional snapshot or a committed record locator; it is not another client authorization layer.

## Table Effects

An effect table declares its adapter on the table and its sync snapshot/output boundaries on fields:

```surql
DEFINE TABLE file_access_grant SCHEMAFULL COMMENT '@rebase-effect sync';
DEFINE FIELD object_key ON file_access_grant TYPE string COMMENT '@rebase-effect-input';
DEFINE FIELD access_url ON file_access_grant TYPE option<string>
  PERMISSIONS FOR select WHERE true FOR create, update NONE
  COMMENT '@rebase-effect-output';
```

Its handler is keyed only by table name:

```js
module.exports = {
  table: "file_access_grant",
  async execute({ record, load, providers, signal, trigger }) {
    return { outcome: "success", patch: { access_url: "..." } };
  },
};
```

The test design provides the reference examples:

- `email_brevo_config`: configuration storage with a required API-key field hidden from normal reads.
- `send_brevo_email`: committed async record, BullMQ delivery, retry/reconciliation, scheduling, and webhook patching.
- `file_storage_config` plus `file_access_grant`: synchronous issuance of a bounded external URL/token using required hidden S3-compatible fields.

`npm run probe:runtime` verifies generated sync and async events against a disposable SurrealDB, including duplicate claims, retry recovery, reconciliation, wake authentication, and webhooks.

The runtime uses Redis/BullMQ locally and exposes three transport lanes:
`task`, `schedule`, and `webhook`. SQS deployments provide
`REBASE_SQS_TASK_QUEUE_URL`, `REBASE_SQS_SCHEDULE_QUEUE_URL`,
`REBASE_SQS_WEBHOOK_QUEUE_URL` plus the matching
`REBASE_SQS_DEAD_LETTER_*` URLs. Queue payloads remain only
`{ namespace, database, id }`.

Provider selection defaults to `REBASE_PROVIDER=local`; set it to `real` for
real provider calls, or override it with `startServer({ provider: "real" })`.
Provider credentials are never read from environment variables. They are
required, typed fields on the strict configuration rows and hidden from normal
client reads. The real adapter consumes `email_brevo_config.api_key` directly,
and maps `file_storage_config.access_key_id`, `secret_access_key`, `endpoint`,
`region`, and `bucket` to the S3-compatible SDK. Custom adapters can be supplied
without changing the server:
`startServer({ provider: createCloudProvider, providerOptions })` or by passing
a ready provider object.

## Development Tools

`npm run populate` derives topology from the compiled schema and scalar generation rules from `data/*.schema.json`. `npm run workbench` provides build, deploy, populate, authentication, query, sample, and probe commands without a fixed namespace/database.

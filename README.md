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
gateway/                      Hono runtime, named service adapters, and queue drivers
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
npm run server -- --env-file .env.local
npm run workbench -- --env-file .env.local
npm run populate -- --env-file .env.local --table all --count 100
```

Commands read one explicit environment profile. For example:

```bash
node gateway/server.js --env-file .env.local
node dev-tools/compiler/cli.js --env-file .env.cloud
node dev-tools/populate.js --env-file .env.local --count 100
node dev-tools/workbench.js --env-file .env.local
```

Profiles use `SURREAL_NAMESPACE` and `SURREAL_DATABASE` for the default context.
Use `--namespace` and `--database` for one-off command overrides. Provider API
credentials remain typed fields in SurrealDB configuration records.

The compiler emits `build/<project>/schema.surql`, a private `runtime-contracts.json`, and validated `table-handlers/` modules. It does not emit tenant operation catalogs, generic job schemas, or compatibility artifacts.

Runtime event generation is explicit because namespace and database are deployment context:

```bash
node dev-tools/compiler/cli.js \
  --project designs/test \
  --env-file .env.cloud
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

## Account Access

The compiled principal table supports normalized optional usernames. Account
signin accepts either an email address or username. Nullable usernames use a
native unique index; no application-side uniqueness event or identity table is
required.

`POST /anonymous/accounts/recovery` accepts a configured namespace, database,
and email/username identifier. It returns the same `202` response for present,
missing, and disallowed accounts, rate-limits both the client address and a
hashed context/identifier key, and emails a rotated one-time invite token. The
existing password remains valid until that token is redeemed, so an anonymous
request cannot lock the account.

Platform recovery mail is an infrastructure exception to tenant BYOC credentials.
Enable the direct Resend adapter with `REBASE_PLATFORM_EMAIL_RESEND_API_KEY`;
tenant email integrations continue to use strict configuration rows. The default sender is
`ReBase <onboarding@resend.dev>` until a verified domain is configured.

When a runtime URL and wake secret are supplied at compilation, the compiler
also emits the `oauth` record access method. It calls the authenticated,
stateless `/internal/oauth` verifier and selects an existing principal by the
returned verified email. OAuth has `SIGNIN` only: it never creates a user,
redeems an invite, provisions a namespace/database, or stores provider identity.
OAuth verifier functions are explicitly allowlisted and injected into the server;
no OAuth provider is enabled by default. SurrealDB reserves `$token`, so the SDK
signin boundary uses `variables: { provider, oauth_token }`; the internal HTTP
verifier receives the normalized `{ provider, token }` body.

## Table Effects

An effect table declares its adapter on the table and its sync snapshot/output boundaries on fields:

```surql
DEFINE TABLE test_attachment SCHEMAFULL COMMENT '
  @rebase-effect sync
  @rebase-adapter createS3UploadGrant
  @rebase-adapter createS3AccessGrant
  @rebase-adapter deleteS3Object';
DEFINE FIELD file_name ON test_attachment TYPE string READONLY COMMENT '@rebase-effect-input';
DEFINE FIELD access_url ON test_attachment TYPE option<string>
  PERMISSIONS FOR select WHERE true FOR create, update NONE
  COMMENT '@rebase-effect-output';
```

Its handler is keyed only by table name:

```js
module.exports = {
  table: "test_attachment",
  on: {
    async CREATE({ record, load, adapters, signal }) {
      const config = await load(record.storage_config);
      const grant = await adapters.createS3UploadGrant({
        accessKeyId: config.access_key_id,
        secretAccessKey: config.secret_access_key,
        endpoint: config.endpoint,
        region: config.region,
        objectKey: "...",
        contentType: record.media_type,
        contentLength: record.byte_length_limit,
        expiresIn: record.access_duration,
        signal,
      });
      return { outcome: "success", patch: { access_url: grant.uploadUrl } };
    },
  },
};
```

The test design provides the reference examples:

- `email_brevo_config`: configuration storage with a required API-key field hidden from normal reads.
- `send_brevo_email`: committed async record, BullMQ delivery, retry/reconciliation, and scheduling.
- `file_storage_config` plus `test_attachment`: a deterministic, typed file entity that issues S3-compatible upload/download grants and removes the object on deletion.
- `razorpay_config` plus `razorpay_order`: synchronous Razorpay Test Mode order creation with required database-owned credentials and a signed `order.paid` webhook that updates the same order row.

`npm run probe:runtime` verifies generated sync and async events against a disposable SurrealDB, including duplicate claims, retry recovery, reconciliation, wake authentication, and webhooks.

The runtime selects a queue driver with `REBASE_QUEUE_DRIVER=bullmq|sqs` and
exposes three transport lanes:
`task`, `schedule`, and `webhook`. SQS deployments provide
`REBASE_SQS_TASK_QUEUE_URL`, `REBASE_SQS_SCHEDULE_QUEUE_URL`,
`REBASE_SQS_WEBHOOK_QUEUE_URL` plus the matching
`REBASE_SQS_DEAD_LETTER_*` URLs. Queue payloads remain only
`{ namespace, database, id }`.

There is no provider mode. `createAdapters()` statically composes the five named
functions available in this build, and runtime contracts inject only the
functions named by each table's repeatable `@rebase-adapter` markers. Missing
functions fail closed. Tests and embedding code can replace exact names through
`startServer({ adapters })` or `createAdapters({ overrides })`; arbitrary names
are rejected.

Tenant credentials are never read from environment variables. They are required,
typed fields on strict configuration rows and hidden from normal client reads.
`sendBrevoEmail` consumes `email_brevo_config.api_key` directly,
maps `file_storage_config.access_key_id`, `secret_access_key`, `endpoint`, and
`region` to the S3-compatible SDK. `REBASE_STORAGE_BUCKET` is one shared
profile value for every namespace/database; the object key contains a
namespace/database hash so records remain isolated. `createRazorpayOrder` maps
`razorpay_config.key_id` and `key_secret` to the Razorpay Orders API. Razorpay
webhook secrets are loaded from the referenced configuration row after the
signed route capsule resolves its context. Webhook adapters remain a separate
static map because raw-body signatures cannot be dispatched from request data.

## Development Tools

`npm run populate` derives topology from the compiled schema and scalar generation rules from `data/*.schema.json`. `npm run workbench` provides build, deploy, populate, authentication, query, sample, and probe commands without a fixed namespace/database.

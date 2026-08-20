# ReBase

ReBase compiles SurrealDB authorization, validation, audit, views, and table-keyed external effects. Clients use SurrealDB directly; the Hono runtime only performs work that requires privileged provider access.

[ARCHITECTURE.md](./ARCHITECTURE.md) defines the current runtime contract. The measured SurrealDB behavior behind it remains in `research/`.

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

The compiler emits only `build/<project>/schema.surql` and validated `table-handlers/` modules. It does not emit operation catalogs, manifests, generic job schemas, or compatibility artifacts.

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
  process: "sync",
  outputs: ["effect_state", "access_url"],
  async execute({ context, record, load, providers, signal }) {
    return { patch: { effect_state: "succeeded", access_url: "..." } };
  },
};
```

The test design provides the reference examples:

- `email_brevo_config`: credential/configuration storage with hidden secret reference fields.
- `send_brevo_email`: committed async record, SQS-compatible delivery, retry state, reconciliation, and webhook patching.
- `file_storage_config` plus `file_access_grant`: synchronous issuance of a bounded external URL/token.

`npm run probe:runtime` verifies generated sync and async events against a disposable SurrealDB, including duplicate claims, retry recovery, reconciliation, wake authentication, and webhooks.

## Development Tools

`npm run populate` derives topology from the compiled schema and scalar generation rules from `data/*.schema.json`. `npm run workbench` provides build, deploy, populate, authentication, query, sample, and probe commands without a fixed namespace/database.

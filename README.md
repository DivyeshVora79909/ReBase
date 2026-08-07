# ReBase

ReBase is a small SurrealQL-first Schema-as-Code compiler. Projects define normal tables, fields, assertions, references, views, and business indexes. The compiler adds hierarchical DAG RBAC, polymorphic ownership, RLS, auditing, reactive cascades, computed-view fields, and framework indexes.

There is no custom schema DSL, frontend package, TypeScript, or runtime dependency.

## Project structure

```text
framework/
  auth.surql              User/group DAG RBAC and cycle protection
  access.surql            Record authentication
src/
  compiler.js             Build orchestration
  project.js              Configuration and CLI loading
  analyze.js              References and system-table validation
  generators/             Security, indexes, views, and cascades
designs/<project>/
  rebase.config.js        Compiler choices only
  schema.surql            Business schema
  views.surql             Grouped reactive views
  seed.surql              Optional non-secret seed data
scripts/
  verify-runtime.js       Authorization regression suite
  benchmark-permissions.js Query-plan and response-time benchmark
```

Each build contains one deployable artifact:

```text
build/<project>/schema.surql
```

## Configuration

```js
module.exports = {
  authorization: {
    selectMode: "readers",
  },
  ownership: {
    inheritArrayReaders: false,
  },
};
```

`authorization.selectMode` accepts:

- `readers`: direct owners and readers inherited from referenced resources may select.
- `owner`: only records owned by the user, an immediate parent, or a dominated node may select.

The default is `readers`. Connections, credentials, namespace, database, build paths, and benchmark values belong in `.env`, copied from `.env.example`.

## Authorization contract

- `parents` contains immediate mixed user/group DAG parents.
- Only immediate parent groups contribute roles to a user's capabilities.
- `dominates` contains transitive user/group descendants.
- Parent records must exist and descendant-as-parent cycles are rejected.
- Every business record has one `owned_by: record<user | groups>`.
- A user may privately own a resource; a group may own a shared resource.
- `readers` is a computed mixed user/group ACL inherited through typed record references.
- `readers_index` materializes record IDs as strings for supported array indexes.
- `z_access_index` contains the authenticated user, immediate parents, and dominated users/groups.
- Deleting an owner is rejected while owned resources still exist.
- Table permissions remain the final security boundary for every query shape.

Indexes are generated on `owned_by` and `readers_index.*`. ReBase intentionally avoids direct indexes on mixed record arrays.

## Business schema and settings

Write all domain data directly in `schema.surql`. A setting registry is optional business schema, not a framework feature:

```surrealql
DEFINE TABLE setting SCHEMAFULL;
DEFINE FIELD scope ON setting TYPE record REFERENCE ON DELETE CASCADE READONLY;
DEFINE FIELD key ON setting TYPE string READONLY;
DEFINE FIELD schema_version ON setting TYPE int DEFAULT 1;
DEFINE FIELD enabled ON setting TYPE bool DEFAULT true;
DEFINE FIELD values ON setting TYPE object FLEXIBLE DEFAULT {};
DEFINE FIELD secrets ON setting TYPE object FLEXIBLE DEFAULT {}
  PERMISSIONS
    FOR select NONE
    FOR create WHERE true
    FOR update WHERE true;
DEFINE INDEX setting_scope_key ON setting FIELDS scope, key UNIQUE;
```

Because this is an ordinary table, projects can add typed references, assertions, indexes, and views. The compiler then supplies normal polymorphic ownership, readers, auditing, and reactive behavior.

Use settings for configurable values. Use normal typed tables for relational entities such as attachments, templates with a lifecycle, invoices, or storage objects.

Configuration stores state, not executable routing. Trusted external actions may read write-only secrets only after an authorization probe performed with the caller's record token.

## Reactive views

Grouped views remain normal SurrealQL:

```surrealql
DEFINE TABLE v_invoice_organization AS
SELECT organization AS target, count() AS invoice_count
FROM invoice
GROUP BY target;
```

The compiler discovers grouped record targets and generates lookup indexes, computed fields on target tables, guarded upward pings, and downward dependency cascades. User and group records may participate as view targets and relation targets.

## Commands and performance

See [COMMANDS.md](COMMANDS.md) for environment setup, generic build/check commands, manual deployment, interactive administrator bootstrap, runtime verification, benchmarks, and isolated test servers.

See [PERFORMANCE.md](PERFORMANCE.md) for measured ACL query plans, complexity guidance, and business-index strategy.

Typical commands:

```bash
cp .env.example .env
npm run build -- --project designs/test
npm run check -- --project designs/test
npm test
npm run verify
npm run benchmark
```

## Maintenance rules

- Prefer documented SurrealDB fields, references, permissions, events, indexes, and `EXPLAIN FULL`.
- Keep business rules and optional domain tables in project SurrealQL.
- Keep generators deterministic and table-driven.
- Declare workload-specific business indexes explicitly.
- Deploy generated schemas through `surreal sql`, not import mode.
- Recreate development databases after this greenfield polymorphic-ownership change; no migration is generated.
- Re-run runtime verification and permission benchmarks after SurrealDB upgrades or authorization changes.

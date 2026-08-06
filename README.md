# ReBase

ReBase is a small Schema-as-Code compiler for SurrealDB. You write normal SurrealQL tables, fields, assertions, views, and business indexes. The compiler adds the repetitive ownership, hierarchical DAG RBAC, RLS, audit, reactive event, computed-view, and framework index definitions.

There is no custom schema DSL and no frontend package. The project uses JavaScript only for configuration and compiler code.

## Project layout

```text
ReBase/
  framework/
    auth.surql             Array-native DAG RBAC and cycle protection
    access.surql           Record authentication and password flows
    settings.surql         Scoped public/private configuration registry
  src/
    compiler.js            Build orchestration
    project.js             Config and CLI loading
    schema.js              Schema/view discovery
    surql.js               Small SurrealQL statement utilities
    analyze.js             Dependency graph and validation
    generators/
      security.js          Ownership, readers, RLS, audit, flags
      reactivity.js        Cascades, view events, computed fields
      indexes.js           Framework indexes and index metadata
  designs/<project>/
    rebase.config.js
    schema.surql
    views.surql
    seed.surql             Optional, non-secret bootstrap data
  scripts/
    deploy.js
    verify-runtime.js
    benchmark-permissions.js
```

Generated builds contain only:

```text
build/<project>/
  schema.surql             Complete deployable schema
  optimizer.json           Verified query-plan findings and indexes
```

## Schema project

`rebase.config.js` stays intentionally small:

```js
module.exports = {
  ownership: {
    inheritArrayReaders: false,
  },
};
```

Keep only compiler/schema choices in this file. Connections, credentials, namespace, database, build path, bootstrap values, and benchmark options belong in the root `.env`.

Write business definitions directly in `schema.surql`:

```surrealql
DEFINE TABLE organization SCHEMAFULL;
DEFINE FIELD name ON organization TYPE string ASSERT string::len($value) > 0;

DEFINE TABLE invoice SCHEMAFULL;
DEFINE FIELD organization ON invoice TYPE record<organization>
  REFERENCE ON DELETE REJECT;
DEFINE FIELD status ON invoice TYPE string
  ASSERT $value IN ['draft', 'posted', 'void'];

-- Business indexes stay explicit because only the application knows query selectivity.
DEFINE INDEX invoice_status_created ON invoice FIELDS status, created_at;
```

Write grouped reactive views in `views.surql`:

```surrealql
DEFINE TABLE v_invoice_organization AS
SELECT organization AS target, count() AS invoice_count
FROM invoice
GROUP BY target;
```

The compiler discovers record links and grouped view targets, then generates ownership inheritance, reverse cascade events, view lookup indexes, and computed fields on the target table.

Keep secrets and environment-specific admin users out of `seed.surql`. Provision them through deployment secrets or a separate bootstrap command.

## Commands

Compile a project:

```bash
npm run build:test
```

Or invoke the compiler directly:

```bash
node --env-file=.env compile.js --project designs/test --output build/test
```

Validate generated files are current:

```bash
npm run check:test
surreal validate build/test/schema.surql
```

Deploy:

```bash
npm run deploy
```

Bootstrap the first record user explicitly. This keeps credentials out of source and seed files:

```bash
npm run bootstrap:admin
```

Verify authorization behavior:

```bash
npm run verify:runtime
```

The scripts read these deployment values directly from `.env`: `SURREAL_ENDPOINT`, `SURREAL_USER`, `SURREAL_PASS`, `SURREAL_NAMESPACE`, `SURREAL_DATABASE`, and `REBASE_BUILD_DIR`. Bootstrap also uses `REBASE_ADMIN_EMAIL`, `REBASE_ADMIN_PASSWORD`, and optional `REBASE_ADMIN_NAME`.

## Authorization contract

The framework preserves these invariants:

- `parents` contains immediate mixed user/group DAG parents.
- Only immediate parent groups contribute roles to a user's `permissions`.
- `dominates` contains transitive descendants for hierarchy administration.
- Proposed self-links and links to existing descendants are rejected as cycles.
- New parent records must exist.
- Resources have one `owned_by` group and computed inherited `readers`.
- Clients cannot write computed permission fields.
- Table permissions are the final RLS security boundary for every query shape.

The compiler materializes `readers_index: array<string>` and indexes `readers_index.*`. Direct indexes on `array<record>` ACL fields are intentionally avoided because SurrealDB 3.2 produced incorrect empty index-scan results in testing.

## Scoped configuration

User-, group-, workspace-, resource-, and root-scoped configuration is stored in the framework `setting` table. The pattern is a **scoped configuration registry** with a **tagged envelope**:

```surrealql
CREATE setting SET
  scope = organization:acme,
  key = 'object-storage',
  schema_version = 1,
  values = {
    provider: 's3',
    bucket: 'acme-uploads',
    region: 'ap-south-1'
  },
  secrets = {
    access_key: '...',
    secret_key: '...'
  },
  owned_by = groups:acme_admins;
```

The stable fields are:

- `scope`: any SurrealDB record, immutable, with `REFERENCE ON DELETE CASCADE`.
- `key`: immutable slug identifying the contract, such as `ui-theme` or `object-storage`.
- `schema_version`: the payload contract version understood by consuming code.
- `enabled`: allows a configuration to be disabled without deleting it.
- `values`: flexible object visible through normal table RLS.
- `secrets`: flexible object writable through normal table RLS but `FOR select NONE` for record users.
- `owned_by`, `readers`, audit fields, and permission indexes: generated like every other ReBase table.

`(scope, key)` is unique. Use one record per independently updated configuration. Do not build one giant settings object.

This table replaces deployment-like user customization only when the values are not relational and are not central to database queries. Keep a normal typed table when:

- Other records reference the value.
- Database events, assertions, or views depend on its internal fields.
- Individual payload fields need indexes.
- The data has a business lifecycle of its own.

For example, a frontend-only default currency can be a setting. A currency used by accounting assertions and materialized views should remain a typed field.

### External actions

Configuration stores state, never executable routing. Do not store function names, source code, or endpoint names in `setting`.

For SMTP, storage, payments, password recovery, and similar actions:

1. The frontend calls an explicit action endpoint, such as `POST /storage/upload-url`.
2. The action receives the SurrealDB record token and setting record ID.
3. It queries the setting ID using the record token. An empty result means RLS denied access.
4. Only after that authorization probe, it reads `secrets` using a trusted SurrealDB system credential.
5. It validates `key`, `schema_version`, and the payload expected by that endpoint.
6. It performs the external action and returns only the result, never the stored secret.

The browser should not receive SMTP passwords, storage secret keys, or payment credentials even when RBAC is strict. Once delivered to browser code, a secret is exposed to extensions, injected scripts, logs, and developer tools. Direct clients may update the write-only `secrets` field when authorized, but only trusted action code reads it.

Password recovery follows the same boundary. SurrealDB stores an expiring invite/reset token and performs the token-to-password exchange. Issuing the token, rate limiting requests, and delivering email belong to an explicit trusted action. ReBase no longer contains email hooks or database-side HTTP calls.

### Payload evolution

Do not add a generic schema registry or class hierarchy. That would require maintaining a second validation language.

Each consuming action or frontend feature owns a small validator for the setting keys it understands. It accepts supported `schema_version` values and rejects unknown versions with a clear error. Old records are migrated only when the consuming feature changes. Unknown extra keys should be ignored where possible.

## Query-plan findings

These are database findings, not frontend implementation code. They are also emitted in every build's `optimizer.json`.

### 1. Dynamic ACL array

```surrealql
WHERE readers_index CONTAINSANY $auth.z_access_index
```

On SurrealDB 3.2, permission-only `EXPLAIN FULL` reports `TableScan`. Binding the full array to `LET` does not make it indexable. RLS remains correct, but worst-case work grows with table size and ACL comparison cost.

### 2. Scalar reader OR branches

```surrealql
LET $r0 = $auth.z_access_index[0];
LET $r1 = $auth.z_access_index[1];

SELECT * FROM invoice
WHERE readers_index CONTAINS $r0
   OR readers_index CONTAINS $r1;
```

Scalar branches can force reader index scans and are approximately `O(m log n + candidates)`, where `m` is the user's access-key count and `n` is table size. Always confirm the exact query with `EXPLAIN FULL` after SurrealDB upgrades.

### 3. Selective filters and sorting

For a query such as:

```surrealql
SELECT * FROM invoice
WHERE status = 'posted'
ORDER BY created_at DESC
LIMIT 50;
```

SurrealDB can use a composite `(status, created_at)` business index and apply RLS as a residual filter. This is usually preferable when the business predicate sharply reduces candidates.

### 4. Cost policy

- Narrow ACL and weak business filters: consider scalar reader `OR` branches.
- Selective filters/sorts: lead with the business index and let RLS filter candidates.
- Wide ACL plus small `LIMIT`: a native scan can sometimes return early and beat many reader branches.
- Full exports, rare readers, and counts have different crossover points from first-page queries.
- Use measured plans and representative data distributions; asymptotic complexity alone does not choose the fastest plan.

Run the included benchmark to capture plans and response percentiles:

```bash
npm run benchmark:permissions
```

Configure it through `.env` with `REBASE_BENCHMARK_SCALES`, `REBASE_BENCHMARK_MEMBERSHIPS`, `REBASE_BENCHMARK_SAMPLES`, `REBASE_BENCHMARK_BATCH_SIZE`, and optional `REBASE_BENCHMARK_OUTPUT`.

The benchmark uses an isolated synthetic table and deletes that table during setup. Never point it at a production database.

## Maintenance rules

- Prefer documented SurrealQL fields, events, references, permissions, indexes, functions, and `EXPLAIN FULL`.
- Keep business rules in project SurrealQL, not compiler conditionals.
- Keep framework generators deterministic and table-driven.
- Add raw business indexes explicitly; the compiler must not guess workload selectivity.
- Treat destructive schema changes as reviewed deployments, not automatic compiler behavior.
- Run compiler tests, `surreal validate`, runtime verification, and permission benchmarks before upgrading SurrealDB.

# ReBase developer tools

The developer tools are ordinary JavaScript modules. Import the public
functions from `dev-tools/index.js`, or start the Node.js REPL with
`dev-tools/workbench.js` for an interactive session.

For the current backend model, read the [tenant/tree contract](../designs/rebase-system/tenant-tree-redesign.md).
Use SurrealDB 3.3.0. Provision tenant records deliberately before population;
`populate({ tenant: "rebase_tenant:demo" })` or `--tenant rebase_tenant:demo`
limits sample owners/references to that tenant. If exactly one tenant exists,
population can infer it. The compiler never creates a production tenant.

## Workbench

The default project is the [direct accounting model](../designs/all-in-accounting/README.md),
`all-in-accounting`. The October 7 model uses direct accounts, temporal taxes
and ordinary production rows; the old recipe profile was removed.

```bash
node dev-tools/workbench.js
```

Load a local process profile when database access is needed:

```bash
node --env-file path/to/profile.env dev-tools/workbench.js --project all-in-accounting
```

The workbench starts without opening a database. It puts a plain `project`
options object and these functions into the normal Node REPL context:

- `build(overrides?)` compiles the current project.
- `check(overrides?)` checks its generated artifacts.
- `connect(context?)` opens one configured database connection.
- `deploy(connection, overrides?)` applies that project's built schema.
- `populate(overrides?)` uses the existing bounded data population tool.
- `closeConnections()` closes all workbench-managed connections.

`closeConnections()` begins terminal cleanup for that workbench and rejects
later connection attempts. It waits for pending opens and close attempts, then
reports any close failures. Close an individual handle with `await admin.close()`
when you intend to keep working and open another session; repeated calls share
the same close result.

Use standard JavaScript, including top-level `await`:

```js
await build()
const admin = await connect()
const [rows] = await admin.db.query("SELECT id, name, currency FROM treasury LIMIT 10;")
rows
```

Change the plain options object at any time, or override one call:

```js
project.outputDir = "/tmp/accounting-build"
await build()
project = { projectDir: "designs/test", outputDir: "/tmp/test-build" }
await build()
await build({ project: "all-in-accounting", outputDir: "/tmp/accounting-build" })
```

An explicit per-call `project` replaces an inherited `projectDir`; an explicit
`projectDir` is always a path. Node's `.clear` restores the initial project and
helpers without losing ownership of already opened connections. Bare build and
check results display a compact summary in the REPL. Assign the result to a
variable to inspect its full properties deliberately; these can contain private
schema and process configuration.

A process profile selects exactly one namespace/database design. An explicit
context must match it; tenants are records within that database:

```js
const admin = await connect({ namespace: "demo", database: "books" })
await deploy(admin, { project: "all-in-accounting" })
```

Each `connect()` call opens a separate session. The returned `db` is the
SurrealDB SDK client, so use SDK operations such as `query`, `select`, and
`signin` directly. Sign in on a second connection when you need to keep the
admin session available. Do not type passwords or tokens as REPL literals;
the workbench does not configure a persistent REPL history file.

`--project` accepts a design name or source directory. The compiler and
workbench accept the project, output, and framework paths as ordinary options;
the process profile remains the source of connection credentials and allowed
contexts.

## Public JavaScript API

```js
const { build, check, connect, deploy, populate } = require("./dev-tools")

const accounting = { project: "all-in-accounting" }
const built = build(accounting)
const admin = await connect({ namespace: "demo", database: "books" })
await deploy(admin, accounting)
const [accounts] = await admin.db.query("SELECT id, name, currency FROM treasury LIMIT 20;")
await admin.close()
```

`project` may be a design name; `projectDir` may be an explicit source path;
`outputDir` may select the build destination. `build` and `check` use the
existing compiler pipeline. `deploy` reads `schema.surql` from the selected
build directory and sends it through the supplied SDK client. Build first.

`connect(context?)` uses the environment profile resolved by
`config/environment.js`. Credentials are never accepted as per-call endpoint,
username, or password overrides. A selected namespace/database must be present
in the process profile; if the profile is ambiguous, pass the configured pair.

`populate({ project, context, ...limits })` calls the existing bounded
population tool and requires a previously built schema and configured context.
It does not create missing schema or infer application-specific fixture data.

## Configuration and defaults

The JavaScript API and workbench default to `all-in-accounting`. The existing
compiler CLI, `npm run build`, and population CLI retain their `test` default.
Use `npm run build:all-in-accounting` for the accounting CLI build.

[`config/environment.js`](../config/environment.js) is the configuration source.
Use a local profile based on [`.env.example`](../.env.example) for connections:
`SURREAL_ENDPOINT`, `SURREAL_USERNAME`, `SURREAL_PASSWORD`, and the
`SURREAL_NAMESPACE`/`SURREAL_DATABASE` pair. `REBASE_ALLOWED_CONTEXTS` may list
additional allowed pairs. These are database contexts; the design project name
does not select or create a database. See the
[configuration reference](../designs/rebase-system/core-configuration.md) for
the other existing settings.

Offline compilation needs no connection profile. A profile-bound build embeds
its namespace/database and, when provided, its runtime event binding. Choose
the same intended context when deploying that build; `deploy` executes its
SurrealQL through the supplied SDK session. It does not provision a runtime or
select an application user.

## Public JSON Schemas

Author a flat `designs/<project>/schemas/*.schema.json` directory with standard
draft-07 JSON Schema. The compiler validates it with strict Ajv and copies the
source bytes into `build/<project>/client/schemas/`. A missing source directory
removes an older public schema export on build; check mode reports stale files
without changing them. Keep output directories separate from source directories.

The direct accounting profile exports thirty editable create-input schemas for
identities, accounts, issues, taxes, payments, corrections, and exchange. They
exclude protected derived fields and tree storage. The preserved recipe profile
retains its original five-schema subset. Decimal quantities use
strings, dates use ISO strings, and record references accept simple
`table:custom-key`, SDK `table:⟨custom-key⟩`, or canonical `table:u"uuid"` strings;
bind their native SDK types before writing. Reference existence,
authorization, uniqueness, and aggregate constraints are enforced by SurrealDB.
`economic_entity` accepts the existing user or an organization; it is separate
from authorization ownership in `owned_by`.

For a frontend, copy only the generated `client/schemas/` contents into the
frontend's public assets or import those JSON files with its normal bundler.
Compile the chosen JSON Schema with Ajv and `ajv-formats`. The exported files
need no Node helpers, fake-data variables, or ReBase fixture vocabulary.
External references are not fetched by the build. If schemas share `$ref`, use
explicit public `$id` values and register those schemas in the consuming Ajv
instance; do not depend on Node loader internals.
They do not infer a form layout, permissions, or a query. The surrounding build
contains private schema/runtime material and is not a browser asset directory.

Private `data/*.schema.json` files remain generation inputs for `populate`.
Their `x-rebase-*` sampling metadata is intentionally absent from public schemas.
When adding another public input, compare its fields with the current SurrealQL
table, author the JSON shape explicitly, and add only the boundary cases that
matter for that input. Computed fields belong in database output.

## Development data in JavaScript

The [direct accounting examples](../designs/all-in-accounting/examples.md) show
ordinary source records and their dependencies. Preview the current example
without opening a database:

```bash
node dev-tools/accounting/fixture-example.js
```

`prepareFixture()` from that module validates eleven editable objects and returns
rows with SDK `RecordId`, `Decimal`, and `Date` values ready for bound writes.
It targets `all-in-accounting`; a field generator cannot infer an accounting
scenario. Re-running it uses the same explicit record IDs.

The population adapter also recognizes the database's `<string>id` output:
single-quoted UUID literals and backtick-quoted simple keys. UUID literals stay
typed UUIDs; UUID-looking custom keys stay strings. This bounded fixture helper
does not parse arbitrary SurrealQL record keys.

To insert them deliberately, use a configured disposable database with the
`all-in-accounting` schema and an explicitly provisioned `rebase_tenant:default`.
From the workbench
started in the ReBase root:

```js
const { prepareFixture } = require("./dev-tools/accounting/fixture-example")
const fixtureDb = await connect()
const transaction = await fixtureDb.db.beginTransaction()
try {
  for (const row of prepareFixture()) {
    await transaction.query("CREATE $id CONTENT $content RETURN AFTER;", {
      id: row.id,
      content: row.content,
    })
  }
  await transaction.commit()
} catch (error) {
  await transaction.cancel().catch(() => {})
  throw error
} finally {
  await fixtureDb.close()
}
```

The example does not deploy schema, create a database, or clean up committed
rows automatically. Use a fresh disposable database for another run, or remove
only those fixture rows in reverse dependency order. This keeps creation,
transaction boundaries, and cleanup visible as ordinary SDK code.

For existing generic fixture schemas, keep simple value edits in JavaScript.
After building and deploying the `test` profile to a development database with
suitable owner records, the workbench can run:

```js
await populate({
  project: "test",
  table: "test_primitive",
  count: 5,
  seed: "example",
  transform: (document) => ({
    ...document,
    a_int: Math.abs(document.a_int ?? 0),
  }),
})
```

The callback receives `(document, { table, index, seed })` and returns the
document, synchronously or asynchronously. `index` is zero-based within a table
across batches. The returned value is schema-validated before native SDK
conversion. Built-in generation is seeded; randomness inside the callback is
caller-owned. Population commits each batch separately, so a later failure
does not undo earlier batches. Preserve the existing batching and sampling caps.

## Testing and boundaries

The public module and workbench tests run without a database:

```bash
node --test dev-tools/tests/workbench.test.js
node --test dev-tools/tests/client-schemas.test.js
```

Build writes generated files to its requested output directory. Deployment and
population require explicit calls to write to the selected database. The
workbench is a trusted local JavaScript REPL, not a sandbox; do not use it with
untrusted input.

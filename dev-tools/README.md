# ReBase developer tools

Use SurrealDB 3.3.0 and the Node version in `.nvmrc` (currently 26.12.0).
The tools are ordinary Node modules;
the workbench is Node's native REPL with top-level `await`. For core schema
work, start with the [developer blueprint](../designs/rebase-system/developer-blueprint.md).
Install development dependencies with `npm ci`; Faker, JSON Schema Faker, Z3,
and the inspector's build/browser libraries are development-only packages.
The project records npm 12.2.0 in `packageManager`; use the local setup commands
in the [root README](../README.md#runtime-and-dependencies).

## Workbench and build

```sh
npm run workbench
node --env-file path/to/profile.env dev-tools/workbench.js --project all-in-accounting
```

The workbench opens no database until `connect()` is called. Its context contains
`project`, `build`, `explain`, `connect`, `prepare`, `fixtures`, and `closeConnections`.
The default project is `all-in-accounting`; the compiler CLI defaults to `test`.

```js
const built = build()
build({ check: true })
explain("issue_adjustment.amount_delta")
const admin = await connect()
await prepare(admin.db, { schema: built.bundle })
```

`check()` and `deploy()` have been removed. Check mode belongs to `build`;
use the SDK directly for SQL or `prepare` for checked, atomic installation of
large schemas and clearing data without reinstalling. Existing compiler `--check` and npm
check scripts remain available for CI. Build and install with the same process
profile when the bundle contains a namespace/database or runtime event binding.

Change `project` or supply explicit build options:

```js
project = { projectDir: "designs/test", outputDir: "/tmp/test-build" }
const testBuild = build()
const elsewhere = build({ project: "all-in-accounting", outputDir: "/tmp/books" })
```

An explicit `project` replaces an inherited `projectDir`. Bare build results
have a compact REPL display; assigned results retain full compiler metadata.
`.clear` restores the initial helpers without losing connection ownership.

`connect(context?)` reads credentials and allowed contexts from
[the process profile](../designs/rebase-system/core-configuration.md), not per-call
credentials. Each call opens a separate SDK session. Close one handle using
`await admin.close()`. `closeConnections()` and REPL exit wait for pending opens
and close every managed connection; terminal cleanup rejects new connections
and reports close failures. The SDK remains available as `admin.db`.

The build also writes `devtools.json` and returns the same plain data as
`built.catalog`. This developer catalog includes every table and view, including
framework and nonreactive tables without a public JSON Schema. Native types,
polymorphic references, calculations, declared queries, root/member contracts,
indexes and authored helper source come from the compiler. It describes possible
relationships; helper conditions and actual query bounds can depend on records.
Public input schemas remain separately authored and are included unchanged.
No deployment context, runtime secret or database records are included.

## Browser inspector

Build a design, then open **`build/<project>/inspector.html`** directly in a
browser. The single file embeds the catalog, Cytoscape, Dagre, the SurrealDB SDK,
and styles. It needs no server, CDN, or installation on the viewer's computer.
The shared implementation lives in [inspector/](./inspector/); each build supplies
its own data. Open or drop another build's `devtools.json` to switch designs.

The table list includes framework tables, views, nonreactive tables and isolated
entities. Selecting a table focuses its immediate neighborhood; **All** restores
the overview. References point from parents to dependents, with parents above
children in acyclic portions. Cycles keep their edges and receive dashed borders.
Use **Upstream** and **Downstream** to trace a path, or search by table/field name.

- **Fields** shows inputs, types, validation and calculations. Polymorphic
  reference swatches contain one segment per possible parent table.
- **Dependencies** shows evaluation order, direct scalar reads and declared
  ordered queries, including the descriptor/helper that supplies bounds.
- **Trees** shows roots, participating slots, consumers and provider functions.
  Expand shared aggregation functions for the monoid's identity, leaf and combine.
- **Source** shows authored functions, invariants, annotations, native indexes
  and unchanged public JSON Schemas. The generated-fields toggle exposes internals.

Colors are evenly spaced around the hue circle and assigned by a seeded hash
ordering of the full table catalog. Filtering and graph layers cannot recolor
tables; a changed catalog can. Text labels and split swatches supplement color.
Static metadata describes possible memberships and dependencies. Conditional
memberships and query bounds come from record state; a connection enables the
record inspector under Dependencies and Trees.

**Access** replaces the old `visualizer.html`. Supply an explicit WebSocket
endpoint, namespace, database and tenant, with a server login or existing access
token. Reads use native SDK bindings and permissions. The diagram uses direct
`parents`, including multiple parents, and displays native roles/effective
permissions. There are no write controls. Reads are capped per table (1,000 by
default, at most 10,000); truncation and unloaded parents are shown explicitly.
The result also depends on what the login can read.

Connection credentials are never saved in URLs, browser storage or exported
snapshots; password/token inputs are cleared after use. **Save snapshot** exports
the current catalog or tenant access snapshot for offline browsing, and **PNG**
exports the graph. Catalogs contain authored source; access snapshots contain the
selected tenant's visible identities and permissions.

```sh
npx playwright install chromium                 # once, for browser verification
npm run probe:inspector                         # disposable database + file:// browser
npm run probe:inspector -- --screenshots build/inspector-evidence
```

The probe checks graph focus/direction, polymorphic colors, cycles, escaping,
keyboard interaction, mobile sizing, imports/exports, native access boundaries,
record state, and cancelled/late login responses. It never connects to the
application's configured database.

## Database preparation

`prepare` takes an explicitly selected, privileged SDK client. It never opens
or closes a connection, chooses a profile, or builds a schema. Use a dedicated
development connection and pause application writers and workers first.

```js
const { prepare } = require("./dev-tools") // already available in the workbench
const built = build()
const admin = await connect()

const installed = await prepare(admin.db, {
  schema: built.bundle,
  onProgress: ({ phase, completed, total, elapsedMs }) =>
    console.log(phase, completed, total, Math.round(elapsedMs)),
})

const cleared = await prepare(admin.db, { clear: true })
// Populate again using the installed schema. No build or schema replay needed.
```

Schema installation splits at existing parser-recognized statement boundaries
and commits one WebSocket SDK transaction. Failed statements or progress
callbacks cancel earlier batches. The helper reports all failed responses,
the affected source-line range, and cancellation failures. A matching compiler
`USE NS ... DB ...` header is checked and removed; foreign contexts, explicit
transaction controls, and `OPTION` statements are rejected. Schema text should
contain self-contained statements: top-level `LET` bindings do not span requests.
Progress callbacks run before commit and may be asynchronous. No callback runs
after commit, so a callback error cannot disguise a successful commit.

Clearing reads the live database catalog and projects reference policies from
native `INFO ... STRUCTURE`; it does not need compiler metadata or JSON schemas.
One explicit transaction checks that the target and definitions are unchanged,
temporarily sets reference-delete policies to `IGNORE`, deletes all table
records under `OPTION IMPORT`, and restores the exact policies. All tables,
including materialized views, are included. Fields, indexes, events, functions,
parameters, access definitions and database users stay installed. Ordinary
tenant, credential, configuration, job and audit **records are deleted**.
Provision those records explicitly afterward. Reference cycles need no Node
traversal. Native deletion maintains indexes and reference bookkeeping.

`batchBytes` defaults to 256000 UTF-8 bytes. For installation it bounds schema
statement text per request, with small additional context-guard and protocol
overhead; a single larger statement is rejected. For clearing it bounds the
complete SQL and JSON bindings, excluding protocol overhead. Clear cannot span
requests because SurrealDB 3.3 rejects `OPTION IMPORT` in interactive SDK
transactions. Small atomic combinations are supported:

```js
await prepare(admin.db, {
  clear: true,
  schema: "DEFINE TABLE example SCHEMALESS;",
})
```

An oversized combination fails before mutation; increase `batchBytes` only
within your server's request limits. Clear still deletes records and indexes
in one transaction: request batching does not bound total transaction memory.
For repeated single-connection tests, install once, use `db.beginTransaction()`,
run fixture operations with `fixtures.insert(transaction, plan)`, and cancel.
External effects cannot be rolled back by database cancellation.

Clearing requires **no outstanding background work**. Native ASYNC event
definitions cause rejection because their pending queue cannot be cleared by
ordinary table deletion. Previously queued work can also outlive a removed
event; removing its definition is not a workaround. This helper does not reset
Redis, external services, or other non-table resources. Use an isolated test
database without native async work for this operation.

The returned report contains `operation`, sorted `tables`, `references`,
`statements`, SQL `requests`, `durationMs`, and inspection/execution/commit
`timings`. Clear's commit time is included in its execution request. Reports
contain no row data. This is tested against pinned SurrealDB 3.3.0; installation
and clearing require the administrative privileges needed by their SQL.

## Fixture primitives

```js
const { build, connect, fixtures } = require("./dev-tools")
const { loadClientSchemas } = require("./dev-tools/client-schemas")
const built = build({ project: "all-in-accounting" })
const model = fixtures.createModel({
  schema: built.bundle,
  schemas: loadClientSchemas("designs/all-in-accounting/schemas"),
})
```

Create the model once and reuse it. It compiles input validators, native type
bindings, and public reference metadata from the complete emitted SQL using the
existing compiler parser. Inspect `model.tables.get("account_entry").relations`
in the REPL to see the inferred reference targets and array cardinalities.
`schemas` accepts either the existing public catalog or a plain
`{ tableName: jsonSchema }` object. Complete parsed compiler metadata is also
accepted; raw source metadata can lack generated fields such as `owned_by`.

| Primitive | Responsibility |
| --- | --- |
| `createModel({ schema, schemas })` | Validate inputs and bind native SDK types |
| `plan(options)` | Generate an inspectable, reproducible plan without a connection |
| `generate(options)` | Choose and accept one row at a time, with explicit read/apply effects |
| `insert(transaction, plan, { batchSize })` | Write ordered statements in caller-owned transaction |
| `populate(db, options)` | Run an offline recipe or incremental counts in one transaction |
| `withSolver(callback, { timeoutMs })` | Optional native Z3 session with automatic worker cleanup |

No global Faker configuration, connection discovery, hidden tenant selection,
private sampling keywords, or population CLI is involved. Use a normal Node
script or the REPL. Import external libraries directly for other needs.

## Named spaces and recipes

A space is an object of named record arrays: `{ owners: [{ id: ... }] }`.
Records may include any attributes useful for selecting compatible combinations.
Keep different tenant, currency, or role subsets in different named pools.
Input records and recipe schemas are copied before generation.

```js
const options = {
  model, seed: "currency-demo",
  space: { owners: [{ id: "rebase_tenant:demo" }] },
  recipe: [
    { name: "business", table: "subsidiary",
      refs: { owned_by: "owners", currency: "currencies" },
      values: { name: "Demo", effective_at: "2027-01-01T00:00:00Z" } },
    { name: "currencies", table: "currency", refs: { owned_by: "owners" },
      values: { code: "DEMO", name: "Demo currency", precision: 2 } },
  ],
}
const preview = await fixtures.plan(options)
preview.space.business
```

Steps have unique `name`, `table`, optional `count` (default 1), `refs`, `after`,
`values`, and `id`. A `refs` entry names an existing space or generated step.
The planner orders prerequisites automatically, so `currencies` runs before
`business`. `after: ["funding"]` adds a business prerequisite independent of
references. Unknown prerequisites and cycles fail clearly. Cycles need an
existing anchor or an explicitly staged scenario.

`values` is an object or an async function receiving
`{ index, seed, space, faker, pick }`. `recipe` itself can be an async function
of `{ seed, space, faker, pick }` returning steps. This is where a reusable
recipe can calculate ranges or solve coupled constraints before generation.
`id` can be a full record ID or a function of the same row context; otherwise
IDs are deterministic hashes of seed, step name, and index.

```js
values: ({ space, pick }) => {
  const invoice = pick(space.invoices)
  const cash = pick(space.cash.filter(row => row.subsidiary === invoice.subsidiary))
  return { invoice: invoice.id, treasury: cash.id }
}
```

Select related fields together in `values`; independent `refs` selections do
not infer cross-record business compatibility. Dependencies used only inside
callbacks need explicit `after` entries. `pick` reports empty pools. Typed array
references sample distinct matching IDs within their schema cardinality.

Remaining fields are generated with JSON Schema Faker 0.6.3. Values are pinned
before generation so schema conditionals can see them. Optional fields are
omitted by default; opt into them through `values`. Reference IDs are never
invented from regex patterns. Required references need `refs` or `values`;
optional references are omitted unless supplied. Every final document passes
the original Ajv validator and native-type validation. Referenced IDs must be
in the supplied space or preceding generated rows.

An optional `assert(plan)` callback checks whole-plan invariants before any
writes. Throw an error or return `false` to reject; asynchronous checks work too.

Money uses decimal strings and native `Decimal`; dates and references become
native SDK values. Nanosecond timestamps retain their precision. Supported
record text includes numeric, string, and typed UUID keys; compound record keys
and unsupported database types fail explicitly. Public schemas stay standard
JSON Schema and contain no fixture-specific annotations.

## Existing records and atomic writes

Provision the tenant and install schema explicitly. Population never bootstraps
application records or opens/closes a connection.

```js
const admin = await connect()
const result = await fixtures.populate(admin.db, {
  ...options,
  space: async transaction => {
    const [owners] = await transaction.query(
      "SELECT * FROM rebase_tenant WHERE id = $owner;",
      { owner: new (require("surrealdb").RecordId)("rebase_tenant", "demo") },
    )
    return { owners }
  },
  batchSize: 100,
})
await admin.close()
```

Use a WebSocket SDK connection for interactive transactions. The space callback
runs inside the same transaction as the writes. `batchSize`
limits statements per request, not commit scope: a later failure cancels the
whole recipe, including earlier batches. Returned `rows` contain bound inputs;
`space` contains JSON views of inputs, and `created` contains database responses.
Later reactive writes may change previously returned database objects; query
again for final derived state. No conflict retry or partial-success mode is
hidden. SurrealDB enforces actual existence, uniqueness, permissions, tenant
compatibility, and business assertions.

For custom transaction ownership, call `plan` and `insert` separately and use
the SDK's commit/cancel operations yourself. Offline spaces may become stale.
Repeatable inputs require the same seed, schema/library versions, recipe, and
ordered space contents. Explicit callback randomness/time is caller-owned.
Reusing IDs in an already populated database fails; use a fresh space or seed.
Planning holds the requested fixture in memory; page large source queries and
use deliberate transaction-sized scenarios for large runs.

## Incremental counts and current database values

Use `counts` when later rows depend on earlier database calculations. Required
references are selected automatically from the existing and newly accepted
records. Tables become eligible as parents appear; a table with more remaining
rows is more likely to run next. Existing records never consume the requested
new-row counts.

```js
const generated = await fixtures.populate(admin.db, {
  model, seed: "businesses",
  space: [{ id: "rebase_tenant:demo" }], // an already provisioned tenant
  counts: { subsidiary: 10, currency: 1 },
  rules: {
    currency: {
      refs: { owned_by: {} },
      values: { code: "DEMO", name: "Demo currency", precision: 2 },
    },
    subsidiary: {
      refs: { owned_by: {} },
      values: ({ faker }) => ({
        name: faker.company.name(), effective_at: "2027-01-01T00:00:00Z",
      }),
    },
  },
})
generated.space.subsidiary
```

The currency is created before any subsidiary needs it. The schema already
declares the relation, so no currency pool mapping or table ordering is needed.
`owned_by` is optional in these create schemas; `{}` explicitly requests it.
The supplied tenant must exist. Repeating this example against the same data
requires a new seed and any unique business values, or an explicitly cleared
development dataset.

In this mode, `space` is an **array of existing records**, or an async function
of the transaction returning that array. The generator derives table pools
from record IDs and deduplicates repeated IDs. Omitted counts default to zero;
zero-count tables can still provide parents. `rules` contains reusable table
policies independently of a run's counts. `counts` and `recipe` cannot be mixed.

Each rule accepts `priority` (default 1), `refs`, `values`, and `id`.
The table selection weight is `remaining × priority`; zero priority disables
selection and leaves a blocker if its quota remains. IDs default to stable
hashes of seed, table, and per-table accepted index. An explicit `id` or `id(ctx)`
can supply a full record ID.

A reference policy supports these independent controls:

| Option | Meaning |
| --- | --- |
| `bias: { table: weight }` | Weight each record of that target table; unspecified targets use 1, zero excludes a target |
| `skew` | Exponent in `(uses + offset) ** skew`; 0 is uniform, positive favors popular parents, negative favors less-used parents |
| `offset` | Positive starting weight base, default 1; larger values soften the influence of early usage |
| `usage: { recordId: count }` | Explicit starting totals, overriding counts inferred from supplied children for those IDs |
| `weight(record, ctx)` | Pure synchronous custom multiplier; return zero to exclude an incompatible candidate |
| `after: [field]` | Select the named reference fields first, so a custom weight can use `ctx.parents` |

Default polymorphic selection weights records equally. Ten candidates of one
target therefore receive ten times the total weight of a single candidate of
another target. Usage is counted separately for each `table.field`, once per
accepted child/parent pair. Array selection chooses distinct IDs and respects
both schema bounds and native fixed array length. Skew controls tendencies,
not exact 80/20 guarantees. Weights and their totals must remain finite.

For related fields, declare the actual dependency:

```js
refs: {
  treasury: {
    after: ["invoice"],
    weight: (cash, { parents }) =>
      Number(cash.subsidiary === parents.invoice.subsidiary),
  },
}
```

Optional references are omitted unless requested through `refs` or values.
Static `values` can pin reference IDs. `refs: { account: false }` delegates
selection of that field to the values callback; required manual references
must still be provided and belong to the supplied or accepted space. Nested
reference objects also need explicit values. Empty required cycles cannot
bootstrap; an existing seed can enable a self-reference or schema cycle.

`values(ctx)` receives `{ table, index, sequence, seed, space, parents, remaining,
faker, pick }`. `index` is the accepted count for that table; `sequence` is the
accepted count across all tables. Native population also supplies `transaction`.
`parents` contains a record for each selected scalar reference and an array
for each selected array reference. IDs and decimals in these views are strings.
Treat `space` and `parents` as read-only views; return new inputs from `values`
and accepted records from `apply`.

Before each values callback, native population rereads all selected parents in
one bound query inside the write transaction. It then validates, binds, and
inserts the new row before making another choice. Business calculations stay
in SurrealDB. Use current `parents` values for capacity bounds; query more distant
ancestors through `transaction` when needed. Custom selection weights see cached
candidate records, so use them for stable compatibility fields. Changing
aggregate feasibility belongs in the values callback. Unselected entries in
`space` remain snapshots.

Return `null` from `values` to decline an infeasible choice without writing or
consuming its quota. `maxAttempts` defaults to 32 attempts per table without
progress; an accepted row resets these budgets. When no table can proceed,
`FixtureStalledError` exposes `code: "FIXTURE_STALLED"`, `seed`, `remaining`,
`blocked`, `attempts`, and `completed`. This is a diagnostic of the sampled run,
not proof that the request is unsatisfiable. There is no hidden restart.
Thrown callback errors and database rejections are fatal. Native population
cancels all writes on either a fatal error or a stall. `assert(result, context)`
can also reject before commit, using `context.transaction` for final native
aggregate checks.

The result includes `rows` (bound accepted inputs), `created` (acceptance
responses), `space` (table pools), `usage` (role counts), and total `attempts`.
Query again for final derived state. Population is sequential in counts mode;
`batchSize` belongs to the offline recipe path. Each run retains its records
and indexes in memory, so choose deliberate transaction-sized counts.

For explicit composition, `generate` requires `apply(row, ctx)` to return the
complete accepted record. Public references in that response, including nested
references, must belong to the supplied space or previously accepted rows.
Database normalization determines usage counts and future selection weights;
generated/protected fields are excluded from this reference check. A bad saved
reference fails before updating pools or quotas. `populate` cancels the whole
transaction; custom `generate` callers own rollback of their effects.
Optional `read(ids)` receives native `RecordId` values and must
return exactly those records. Additional callback context can be passed as
`context: { ... }`. It opens no connection and owns no commit/cancel boundary:

```js
const result = await fixtures.generate({
  model, seed: "offline-graph", counts: { subsidiary: 3, currency: 1 },
  rules: { subsidiary: { values: { effective_at: "2027-01-01T00:00:00Z" } } },
  apply: async row => ({ id: row.id, ...row.content }),
})
```

That in-memory acceptor exercises graph selection and input validation. Current
database aggregates require read/write effects; `populate` provides the native
composition. Ordinary callback closures can also supply another explicit effect
implementation. All randomness and ordering must be reproducible for seed replay.

## Coupled constraints and accounting trial

Simple bounds belong in ordinary functions. For coupled equations, write native
Z3 expressions inside `withSolver`; there is no second constraint language:

```js
const pair = await fixtures.withSolver(async ({ Int, solver, solve }) => {
  const x = Int.const("x"), y = Int.const("y")
  solver.add(x.ge(20), y.ge(20), x.add(y).eq(90), x.le(y))
  const solution = await solve()
  return [solution.eval(x).value(), solution.eval(y).value()]
})
```

Extract ordinary values inside the callback. `solve()` distinguishes impossible
constraints from unknown/timeout outcomes. `timeoutMs` (default 5000) bounds
each solver check, not arbitrary JavaScript callbacks. Z3 loads only when used;
sessions clean up their workers even after errors. A satisfying model is not
a uniform random sample. General arithmetic, rounding, and temporal rules
must be declared; database errors are not automatically inverted into generators.

The [accounting recipe](./fixtures/examples/accounting.js) composes exact-cent
allocations, percentage plus fixed charges, named relations, and funding
prerequisites. Its independent prefix check verifies the generated scenario.

The [incremental accounting example](./fixtures/examples/accounting-incremental.js)
withdraws from explicitly selected funded treasuries. It reads current account
and subsidiary summaries, applies their floors in exact cents, and chooses a
feasible amount. It checks that the supplied start follows the relevant history
and supports two-decimal treasuries in their subsidiary's reporting currency.

```js
const { withdrawalOptions } = require("./dev-tools/fixtures/examples/accounting-incremental")
const result = await fixtures.populate(admin.db, withdrawalOptions({
  model, tenant: "rebase_tenant:demo", accounts: ["treasury:cash"],
  seed: "cash-movements", count: 20, maxCents: 500n,
  startAt: "2027-02-01T00:00:00Z",
}))
```

For coupled constraints, enclose the whole population in one `withSolver`
callback. Define stable formulas once, then scope each changing bound inside
`values`: `solver.push(); try { solver.add(currentBound); ... await solve() }
finally { solver.pop() }`. Extract plain values before popping. Adding another
bound does not replace an earlier bound. A solver's unsatisfiable result may be
handled explicitly as `return null`; timeout/unknown should remain distinguishable
from infeasibility. The generator does not swallow solver failures.

```sh
node dev-tools/fixtures/examples/accounting.js  # offline preview
npm run probe:fixtures                       # disposable SurrealKV integration
npm run probe:prepare                        # preparation rollback, metadata and clearing
npm run test:dev-tools
```

The integration probe checks native bindings, replay, exact tree prefixes,
current parent feedback, and full-table rollback after overdraw, backdating,
cross-tenant failures, and incremental stalls. These are correctness trials,
not throughput claims. The [design and verification record](../designs/rebase-system/fixture-generation.md)
documents selection costs and implementation boundaries.
The [17 explicit accounting records](./accounting/fixture-example.js) remain
available and now share the same metadata-based binding implementation.

The 48 public accounting schemas are separately authored create contracts.
Their compilation/export checks do not prove equivalence to every SurrealQL
business rule. The broader accounting contract is documented in the
[accounting guide](../designs/all-in-accounting/developer-guide.md).

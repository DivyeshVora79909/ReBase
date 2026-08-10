# ReBase

ReBase contains a SurrealQL compiler and a minimal native Node REPL for post-deployment development. There is no web application, profile registry, notebook loader, generator CLI, or workflow framework.

## Layout

```text
framework/                 Shared authorization and access contracts
src/                       Compiler implementation
designs/<name>/            Project SurrealQL
designs/<name>/data/       Project-owned JSON Schemas
dev-tools/repl-adv.js      Native JavaScript and SurrealQL REPL
scripts/data.js            Deterministic generation, validation, DAG inspection, and optional casting
scripts/materialize.js     SurrealDB-native create-as-you-go relationship materialization
scripts/benchmark.js       Query classification, timing, and plan analysis
scripts/database.js        Explicit database reset, clearing, and metadata operations
scripts/schema.js           Schema loading and Surreal CLI validation
scripts/inspect.js           Live metadata and DAG inspection
queries/                   Manual SurrealQL examples
```

## Compiler

```bash
node --env-file=.env compile.js --project designs/test
node --env-file=.env compile.js --project designs/test --check
```

Validate and deploy the generated `build/<design>/schema.surql` using `surreal validate` and `surreal sql`. Import mode is not appropriate because it disables normal event and field processing.

## Native REPL

```bash
node --env-file=.env dev-tools/repl-adv.js
```

JavaScript is evaluated by Node normally. Input beginning with a SurrealQL statement keyword is executed as SQL. End direct SQL with `;`; multiline SQL is supported.

The JavaScript context contains:

```js
db; // currently active SurrealDB session
sql; // query helper returning the cleaned final result
vars; // ordinary object, also the default SQL bindings object
tools; // namespaced reusable functions
```

Examples:

```js
vars.limit = 10;
vars.users = await sql("SELECT * FROM user LIMIT $limit;", vars);
console.table(vars.users);
```

Direct SQL is also valid:

```surrealql
SELECT id, email FROM user LIMIT 10;
```

The only custom commands are:

```text
.as user:alice       switch to an independent record-authenticated session
.admin               switch back to the administrator
.benchmark on        analyze every direct SELECT
.benchmark off       disable automatic analysis
.benchmark once      analyze only the next direct SELECT
```

At startup the REPL defines a temporary record access method that signs in an existing record without changing passwords or login fields. Normal exit removes it. After an abnormal termination, clean it up manually:

```surrealql
REMOVE ACCESS personifier ON DATABASE;
```

## Deterministic Data

JSON Schemas belong to their design, for example:

```text
designs/test/data/user.schema.json
designs/test/data/groups.schema.json
designs/test/data/test_primitive.schema.json
```

Generate plain payload JSON while keeping relationships explicit:

```js
const config = {
  cwd: "designs/test",
  seed: "manual-1",
  anchors: { groups: ["groups:root"] },
  datasets: {
    groups: { schema: "data/groups.schema.json", count: 5, batchSize: 2 },
    user: { schema: "data/user.schema.json", count: 20, batchSize: 5 },
    test_primitive: { schema: "data/test_primitive.schema.json", count: 100 },
  },
  relations: [
    {
      from: "groups.id",
      to: "groups.parents[]",
      cardinality: { min: 1, max: 2 },
    },
    { from: "groups.id", to: "user.parents[]" },
    { from: "user.id", to: "test_primitive.owned_by" },
  ],
};

vars.data = await tools.data.generateData({ config });
tools.data.validateData({ data: vars.data, config });
```

`generateData()` uses JSON Schema Faker, Faker, AJV formats, and seeded randomness. It deliberately omits IDs and declared relation targets, returning only portable payloads. Runtime count overrides do not require editing the design config:

```js
vars.data = tools.data.generateData({
  config,
  counts: { user: 25, test_primitive: 100000 },
});
```

Datasets with database unique indexes declare the corresponding payload paths once, for example `unique: ["email"]`. JSF retries collisions before any database write.

The `omit` lists in a design config describe optional relation-shaped fields that are intentionally left for a later materializer. Payload generation remains plain JSON and does not connect to SurrealDB.

Materialize complete records in dependency batches:

```js
vars.native = tools.data.castData({
  data: vars.data,
  rules: [
    { path: "test_primitive[].a_datetime", type: "datetime" },
    { path: "test_primitive[].a_decimal", type: "decimal" },
  ],
});

await tools.materialize.materializeData({
  db,
  data: vars.native,
  config,
});
```

The materializer uses direct SurrealDB `CREATE` operations inside one query per batch. IDs are generated natively. Each relation selects only records committed before the current batch, so generated references cannot form cycles. Existing roots such as `groups:root` are declared once through `config.anchors`; small per-dataset `batchSize` values create deeper self-referencing DAGs without making large resource datasets slow.

`validateData()` validates the projected payload schemas. Final IDs, references, database assertions, computed fields, and events are validated by SurrealDB during materialization.

## Native SurrealDB Values

Generation stays database-independent. Cast only immediately before SDK writes:

```js
const native = tools.data.castData({
  data: vars.data,
  rules: [
    { path: "user[].parents[]", type: "record" },
    { path: "invoice[].amount", type: "decimal" },
  ],
});
```

Supported casts are `record`, `datetime`, `decimal`, and `uuid`.

## Benchmarking

Automatic mode prints one-sample timing and `EXPLAIN FULL` scan/index information for direct SELECT statements. It does not store hidden reports.

For deliberate measurements, assign the result yourself:

```js
vars.report = await tools.benchmark.benchmark({
  db,
  query: "SELECT id FROM test_primitive WHERE owned_by = $owner LIMIT 50;",
  vars,
  warmups: 3,
  samples: 20,
});
```

Reports contain the SQL, normalized fingerprint, timing percentiles, returned rows, query classification, scan/index analysis, and raw plan.

## Query Examples

`queries/` contains ordinary SurrealQL files for authorization, cycles, edge workflows, and benchmark shapes. They are intentionally not discovered or parsed by tooling; inspect and paste what is useful.

## Maintenance Rule

Persistent behavior belongs in SurrealQL or standard JSON Schema. Runtime orchestration belongs in native JavaScript. Add a library capability only when it is reusable computation, not workflow convenience.

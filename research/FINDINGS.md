# SurrealDB Data-Generation Findings

This document records the local experiments that led to the current data pipeline. It is deliberately separated into measured facts, design conclusions, and open assumptions. The measurements were made against SurrealDB `3.2.0` using an isolated in-memory database on 2026-08-10.

Re-run the probes after changing the SurrealDB version, schema, storage engine, or event/index definitions. These are engineering observations, not guarantees for every deployment.

## Current pipeline

The lowest-maintenance boundary is:

```text
JSON Schema
  -> JSON Schema Faker + seeded JS randomness
  -> AJV payload validation
  -> optional SDK casting for datetime/decimal/UUID values
  -> SurrealDB dependency batches
  -> native CREATE, IDs, references, assertions, events, and computed fields
```

The reusable implementation is split intentionally:

- `scripts/data.js` is database-independent payload generation, validation, casting, and DAG inspection.
- `scripts/materialize.js` is the SurrealDB-specific write/materialization layer.
- `designs/<name>/data/*.schema.json` remains the persistent shape contract.
- `suite.config.js` contains counts, anchors, relation declarations, omission lists, uniqueness hints, and batch sizes.

## What JSON Schema and SurrealDB each validate

SurrealDB does not parse or execute JSON Schema. Validation is therefore two-stage:

1. AJV validates the generated payload projection in Node. ID and relation target fields are omitted at this stage because SurrealDB will provide them.
2. SurrealDB validates the final record against `DEFINE FIELD`, `ASSERT`, `REFERENCE`, `VALUE`, permissions, events, and computed-field behavior during `CREATE`.

The database cannot invent arbitrary JSON-Schema Faker values when cloning a payload. It can merge objects and repeat rows, but it does not know how to produce a new valid email, regex value, or business-specific unique string. Database unique fields must either be generated per row in JS or have an explicit database-side transformation.

`json-schema-faker` also does not promise database-index uniqueness. Unique database fields are declared explicitly in the dataset config, for example:

```js
user: {
  schema: "data/user.schema.json",
  unique: ["email"]
}
```

The generator retries those values before insertion.

## SurrealQL capabilities confirmed

The following primitives worked in the installed version:

- `<array> 0..=N` creates integer ranges.
- `.map(...)` constructs arrays of objects or record values.
- `.fold(...)` accumulates a value functionally.
- `object::extend(a, b)` merges payload fields and generated fields.
- `object::from_entries(...)` can construct dynamic objects when needed.
- `type::record("table:key")` creates a native record pointer.
- `CREATE table CONTENT object` generates a native random record ID when no explicit ID is supplied.
- `FOR $row IN $rows { CREATE ... RETURN NONE; }` performs many writes inside one submitted query.
- `BEGIN TRANSACTION` / `COMMIT TRANSACTION` makes a batch atomic. A `THROW` inside the transaction prevents partial writes.
- `SELECT VALUE id FROM table` builds a source value pool for the next dependency batch.
- `array::distinct`, `array::flatten`, `array::slice`, and modulo indexing are available for relation pools and cardinality handling.
- `rand::ulid`, `rand::int`, and `rand::enum` are available for non-seeded database randomness.

`INSERT INTO table <array-expression>` is valid for one table and is useful for simple independent data. It is not a single cross-table insertion mechanism; cross-table work requires ordered statements or a loop containing `CREATE`.

## Measured write results

The probes used simple schemafull tables and `RETURN NONE` to avoid result serialization noise.

| Operation | Approximate Surreal time for 10,000 records |
| --- | ---: |
| Mapped bulk `INSERT` of generated objects | 10.6 seconds on the repeated probe |
| Direct `FOR` + `CREATE` with ordinal IDs | 0.28 seconds |
| Direct `FOR` + random database IDs, anchored parent | 0.33 seconds |
| `FOR` + `object::extend` template merge | 0.47 seconds |
| Two cross-table `FOR` loops with references | 0.69 seconds |
| Self-reference using direct ordinal IDs | 0.55 seconds |
| Precomputed random IDs stored in an array, then `CREATE $ids[$i]` | about 15 seconds |
| Two-parent array references with reverse-reference maintenance | about 9.2 seconds for 10,000 rows in the probe |

The bulk `INSERT` result was unexpectedly slower than direct `FOR` creation in this environment. This may depend on SurrealDB version, storage engine, indexes, record-ID shape, and schema behavior; it must not be generalized without re-running the probe.

## Why precomputed random ID arrays bottlenecked

The slow pattern was:

```surql
LET $ids = (<array> 0..=9999).map(|$i| type::record('node', rand::ulid()));
FOR $i IN <array> 0..=9999 {
  CREATE $ids[$i] CONTENT ...;
};
```

The same shape with ordinal IDs was fast. Direct `CREATE table CONTENT ...` with Surreal-generated IDs was also fast. The likely costs are the dynamic record-ID lookup path and poor write locality caused by precomputed random keys, but this should be treated as a measured behavior rather than a proven internal implementation fact.

Practical rule:

- Do not precompute a large random ID array and index into it for each write.
- Let `CREATE table CONTENT ...` generate IDs directly when using the database-native path.
- If deterministic IDs are required, use simple ordinal/key IDs and benchmark their locality.

## Why dependency batches guarantee no cycles

The materializer does not choose from future records. For each dataset batch it:

1. Selects source values already present in the database.
2. Adds explicit anchor values such as `groups:root`.
3. Creates the complete current batch in a transaction.
4. Commits it before the next dependent batch is built.

Therefore a generated relation can only point backward to an existing record. A record cannot point to itself or to a future batch, so a cycle cannot be introduced by generated edges.

Required dependency cycles with no anchor are impossible and fail before the batch writes. Optional relations may be empty when their source pool is empty. Small per-dataset batch sizes allow self-referencing DAGs to gain deeper parents while still preventing same-batch cycles.

This is stronger and easier to reason about than precomputing a global random ID graph.

## Randomness and reproducibility

The JavaScript seed controls JSF payload generation and unique-value retries.

SurrealDB's `rand::*` functions are not driven by that JavaScript seed. Consequently:

- payload JSON is reproducible for the same JS seed;
- native IDs and relation selections are intentionally different between materialization runs;
- acyclicity is reproducible as an invariant, but exact graph edges are not.

This is appropriate for high-volume benchmark data. For debugging a specific authorization case, keep the payload seed and use a separate deterministic materialization mode based on ordinal IDs/modulo selection rather than attempting to seed SurrealDB's random generator.

## Performance bottlenecks by layer

Node ID generation is not the bottleneck. A Node `randomUUID()` probe produced roughly 1.9 million IDs/second at 100,000 IDs.

The existing full JSF pipeline generated approximately 500–650 complete rows/second because it generated fake relation fields and performed Node-side relation work. Payload-only JSF measured approximately 2,600–5,300 rows/second in a small local probe.

SurrealDB write time is dominated by schema behavior for relation-heavy tables:

- `REFERENCE` fields maintain reverse-reference state;
- arrays of references cost more than scalar references;
- events and computed fields execute during the write;
- indexes and uniqueness checks add work;
- result output must be suppressed with `RETURN NONE` for bulk operations.

Moving relation selection to SurrealDB removes Node/database glue and network round trips, but it cannot remove these intrinsic database costs.

## Best use cases

Use the current Surreal materializer when:

- IDs should be generated by the database;
- relations must be valid at write time;
- self and cross-table dependencies need an acyclic guarantee;
- schemas contain computed fields, assertions, events, or references that should run normally;
- payloads can be generated once in JS and sent in batches;
- you want one query per batch rather than one request per record.

Keep payload generation in Node when:

- values must satisfy complex JSON Schema formats or patterns;
- unique text fields need realistic per-row values;
- data needs to be inspected before touching the database;
- the target database is not SurrealDB.

Do not use template repetition for a dataset with unique payload indexes unless a deliberate uniqueness transform exists. The current materializer creates one database row per payload row; it does not silently clone templates.

## Current limitations

- Materialized relation targets must currently be top-level fields. Nested ordinary payload objects remain supported by JSF.
- The dependency planner supports a DAG of required dataset dependencies plus explicit anchors. A required cross-dataset cycle without an anchor is rejected.
- Relation selection is random and unseeded in SurrealDB.
- Native datetime/decimal/UUID coercion is not assumed; cast those values before materialization when the schema requires native types.
- The materializer currently uses `CREATE`, not an upsert/replay mode.
- A batch pool contains records committed before that batch, not records created inside the same batch.

## Re-running the findings probes

Use an isolated in-memory server, never a project database:

```bash
surreal start memory --user root --pass root --bind 127.0.0.1:8001
surreal sql --endpoint http://127.0.0.1:8001 --user root --pass root --namespace probe --database probe
```

Measure internal query time with:

```surql
LET $started = time::now();
-- operation under test
RETURN time::now() - $started;
```

Always compare the same schema, indexes, events, row shape, batch size, and `RETURN NONE` behavior. Record the SurrealDB version with every result.


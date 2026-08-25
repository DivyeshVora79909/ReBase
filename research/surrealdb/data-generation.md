# SurrealDB Data Generation Findings

Status: measured fixture-generation reference

Tested: SurrealDB `3.2.0`, isolated in-memory database, 2026-08-10. These are
engineering observations; rerun after changing database version, storage,
schema, indexes, events, or materialization strategy.

## Pipeline boundary

```text
JSON Schema
  -> JSON Schema Faker + seeded JS randomness
  -> AJV payload validation
  -> optional SDK casting for datetime/decimal/UUID
  -> SurrealDB dependency batches
  -> native CREATE, IDs, references, assertions, events, computed fields
```

Implementation ownership:

- `dev-tools/populate.js`: generation, AJV validation, native casting,
  dependency analysis, batching, and SurrealDB materialization;
- `designs/<name>/data/*.schema.json`: scalar shape contracts;
- the compiled SurrealDB schema: reference topology, required dependencies,
  generated fields, assertions, and write-time integrity.

JSON Schema and SurrealDB validate different projections. AJV validates generated
scalar payloads while omitting database-generated IDs and relation targets.
SurrealDB validates the final record through typed fields, assertions,
permissions, references, `VALUE`, events, and computed fields. SurrealDB cannot
invent arbitrary JSON-Schema Faker values when cloning payloads; unique text
values need per-row JS generation or a database-side transformation.

## Confirmed SurrealQL generation primitives

The installed version supported:

- integer ranges (`<array> 0..=N`), `.map`, `.fold`, and modulo indexing;
- `object::extend` and `object::from_entries`;
- `type::record("table:key")`;
- `CREATE table CONTENT object` with native random IDs;
- `FOR $row IN $rows { CREATE ... RETURN NONE; }`;
- `BEGIN TRANSACTION` / `COMMIT TRANSACTION` with rollback on `THROW`;
- `SELECT VALUE id FROM table` as a source pool;
- `array::distinct`, `flatten`, `slice`, and relation-pool operations;
- `rand::ulid`, `rand::int`, and `rand::enum` for database-side randomness.

`INSERT INTO table <array-expression>` is useful for one independent table, not
for cross-table insertion; dependencies require ordered statements or loops.

## Measured writes

Approximate SurrealDB time for 10,000 records in the local probe:

| Operation | Time |
| --- | ---: |
| mapped bulk `INSERT` | 10.6 s |
| direct `FOR` + ordinal IDs | 0.28 s |
| direct `FOR` + random DB IDs | 0.33 s |
| `FOR` + `object::extend` | 0.47 s |
| two cross-table loops with references | 0.69 s |
| self-reference with ordinal IDs | 0.55 s |
| precomputed random ID array | ~15 s |
| two-parent arrays with reverse-reference maintenance | ~9.2 s |

The precomputed random-ID pattern was slow:

```surql
LET $ids = (<array> 0..=9999).map(|$i| type::record('node', rand::ulid()));
FOR $i IN <array> 0..=9999 {
    CREATE $ids[$i] CONTENT ...;
};
```

Let SurrealDB generate IDs directly. If deterministic IDs are required, use
simple ordinal/key IDs and benchmark locality. Suppress result serialization
with `RETURN NONE` for bulk work.

## Dependency and DAG guarantees

The materializer selects only records committed before the current batch, adds
explicit anchors such as `groups:root`, writes the complete batch atomically,
and refreshes pools only after commit. Thus generated references point backward
to existing records and cannot create self/future-batch cycles. Required
dependency cycles without an anchor fail before writing; optional relations may
be empty when their source pool is empty. Small batches permit deeper
self-referencing DAGs without same-batch cycles.

This is easier to reason about than a precomputed global random graph.

## Reproducibility

The JS seed controls JSON-Schema Faker payloads and unique-value retries.
SurrealDB `rand::*` IDs and relation choices are not controlled by that seed:

- scalar payloads reproduce for the same JS seed;
- native IDs and relation selections differ between materializations;
- acyclicity is reproducible as an invariant, not exact graph edges.

For an exact authorization fixture, use a deterministic ordinal materialization
mode rather than trying to seed SurrealDB randomness.

## Cost by layer

Node `randomUUID()` generated roughly 1.9 million IDs/s at 100,000 IDs in the
local probe. Full relation-aware JSF produced about 500–650 rows/s; payload-only
JSF about 2,600–5,300 rows/s. Database time is dominated by reverse-reference
maintenance, array references, events, computed fields, indexes, uniqueness,
and result serialization.

Move relation selection into SurrealDB to remove glue and round trips, but do not
expect that to remove intrinsic schema/reverse-link costs.

## Appropriate use

Use this materializer when IDs/relations should be database-valid, references
must be checked at write time, dependencies must be acyclic, schemas contain
computed/asserted/eventful fields, and batches are preferable to per-record
requests. Keep generation in Node when values require complex JSON Schema
formats, realistic unique strings, preflight inspection, or a non-Surreal target.

Do not template-clone unique-indexed datasets without a uniqueness transform.

## Current limitations

- materialized relation targets must be top-level fields;
- required dependency graphs must be DAGs or have explicit anchors;
- relation selection is random and unseeded in SurrealDB;
- native datetime/decimal/UUID coercion must be performed before materialization
  when the schema requires native values;
- the materializer uses `CREATE`, not an upsert/replay mode;
- a batch pool contains records committed before that batch, not same-batch rows.

## Reproduction

Use an isolated in-memory server, never a project database:

```bash
surreal start memory --user root --pass root --bind 127.0.0.1:8001
surreal sql --endpoint http://127.0.0.1:8001 --user root --pass root \
  --namespace probe --database probe
```

Measure an operation with:

```surql
LET $started = time::now();
-- operation under test
RETURN time::now() - $started;
```

Compare identical schema, indexes, events, row shape, batch size, and return
projection. Record the SurrealDB version with every result.

# Compiler and Development Contract

Status: adopted development-tool policy

The compiler is a deterministic development tool, not a runtime library or a
second application backend. It combines SurrealQL material by syntax and
markers, analyzes the result, generates framework sections, and copies validated
table handlers. The SurrealDB and ReBase architecture documents own engine and
runtime semantics respectively.

## Compilation pipeline

1. discover all `.surql`/`.sql` material recursively;
2. preserve source comments and print the combined raw material when requested;
3. extract explicit `REBASE SECTION <name> BEGIN/END` blocks;
4. classify remaining statements by syntax (`USE`, schema, views, seed,
   migration, or raw), never by filename convention;
5. detect/bind the two principal tables from project schema material;
6. parse schema and views and analyze reverse references, effects, and indexes;
7. emit context, raw schema/framework, generated assertions/security/audit/
   reactivity/effect events, views, indexes, and optional seed/bootstrap;
8. copy the design’s validated `table-handlers/` tree;
9. validate deterministic output and stale artifacts.

The project may manually compose small stateless functions around the compiler
pipeline. No environment-provided namespace/database defaults are part of the
compiler core; deployment context is an explicit CLI/runtime argument.

## Material classification

Use syntax/markers rather than names such as `schema.surql`, `views.surql`, or
`seed.surql`:

```text
REBASE SECTION seed BEGIN
...
REBASE SECTION seed END
```

The compiler rejects duplicate or unclosed marked sections and conflicting
`USE NS ... DB ...` contexts. A raw file can contain multiple concerns as long
as its statements/markers classify unambiguously.

## Schema-derived generation

The compiler derives, rather than duplicates:

- principal table names and their authorization bindings;
- record reference cardinality and targets;
- existence assertions and native delete policies;
- ownership, access indexes, readers, views, audit, and change logs;
- effect process, input/output fields, handlers, and generated events;
- UUIDv7 IDs and indexes;
- seed dependency ordering and population pools.

Reference assertions apply to top-level record fields. Required scalars use
`record::exists($value)`, optional scalars allow `NONE`, and arrays validate each
member. The principal `parents` field is the deliberate delta-validation
exception; see [`parents-field.md`](./parents-field.md).

## Effect/handler validation

An effect table must map to exactly one table-keyed handler. The compiler checks
process type, handler existence, input/output markers, declared output types,
and copied artifact parity. It rejects writable runtime outputs, missing output
fields, unknown handlers, and mismatched table declarations. Details live in
[`runtime-dispatch.md`](./runtime-dispatch.md).

## Build artifact and CLI

The artifact contains the compiled `schema.surql` and copied handler modules. It
does not contain operation catalogs, manifests, generic job schemas, or legacy
compatibility files. `--check` compares generated schema and copied trees; the
compiler cleans known legacy artifacts before writing.

Useful commands:

```bash
npm run build
npm run check
node dev-tools/compiler/cli.js --print-raw
```

The compiler can generate runtime events only when explicit namespace, database,
runtime URL, and wake secret arguments are supplied. This keeps the material
compiler context-free and makes deployment context visible.

## Development data

`data/<table>.schema.json` files generate scalar fake values through JSON Schema
Faker/AJV. They are not gateway request contracts. SurrealDB validates the final
record, including native types, assertions, references, permissions, events, and
computed fields.

Population uses:

- keyset pagination of committed candidate IDs;
- bounded per-table reservoirs;
- dependency-aware batches that only reference prior committed batches;
- optional anchors such as `groups:root`;
- a printed seed for replayable JS payload generation.

SurrealDB’s native random IDs and relation selections are intentionally not
controlled by the JS seed. Exact graph edges need a separate deterministic
ordinal mode; acyclicity is guaranteed by dependency ordering.

Avoid precomputed large random ID arrays, repeated `COUNT + OFFSET`, full random
sorts, cloning templates into unique-indexed tables, and one network request per
record. Suppress bulk result serialization with `RETURN NONE`.

## Workbench

The REPL is a small manual orchestrator with explicit runtime context:

```text
.build
.deploy
.populate [table] [count]
.as <email> <password>
.edge <function> {...}
.probe [security|data|all]
```

It does not require fixed namespace/database values in environment variables.
Static cookbook scripts, operation discovery, and a monolithic scenario graph
are not target architecture.

## Verification

`npm run verify` performs deterministic compile checks, `surreal validate`,
architecture/runtime/security/data probes, and generated-artifact checks. Live
probes use disposable in-memory namespaces/databases, create their own actors
and records, assert the important matrix, and clean up by terminating the
instance.

Critical coverage includes principal DAGs, permission-aware references,
ownership delegation, readers and revocation, views, audit/change logs, sync and
async effects, duplicate claims/retry/reconciliation, webhook signatures and
deduplication, and seeded data generation.

Before changing a core rule, ask:

1. Which invariant or duplicate source of truth does it address?
2. Is SurrealDB or the schema already capable of doing it?
3. Does it add a mode, registry, or compatibility branch?
4. Has engine behavior been reproduced in a disposable probe?
5. Does revocation, deterministic output, strict typing, and handler validation
   still pass?

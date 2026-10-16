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
6. parse schema and views; analyze references, field provenance, temporal memberships,
   business dependencies, effects, and indexes;
7. emit context, raw schema/framework, generated assertions/security/audit/
   tree/reactivity/effect events, views, indexes, and optional seed/bootstrap;
8. copy the design’s validated `table-handlers/` tree;
9. validate deterministic output and stale artifacts.

The project may compose small stateless functions around the compiler pipeline
in `dev-tools/compiler/`. Deployment context comes from the validated process
configuration at the build boundary; the compiler stages receive it explicitly.
See the [JavaScript development guide](../../dev-tools/README.md) for the public
API and native Node REPL.

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
- protected tree storage, derived-field refresh, and consumed-field dependency routes;
- effect process, exact named adapters, input/output fields, handlers, and generated events;
- SurrealDB-generated record IDs and runtime indexes;
- seed dependency ordering and population pools.

Reference assertions apply to top-level business record fields, excluding
structural storage. Required scalars use
`record::exists($value)`, optional scalars allow `NONE`, and arrays validate each
member. The principal `parents` field is the deliberate delta-validation
exception; see [`parents-field.md`](./parents-field.md).

Temporal authoring uses `@rebase-tree-root`, `@rebase-tree-node`,
`@rebase-members fn::...`, `@rebase-derived`, and `@rebase-validate fn::...`.
The [temporal contract](./temporal-trees.md) owns their API and constraints.
Consumed references must be typed, scalar, and tracked with native `REFERENCE`.
Opaque helper reads need `@rebase-depends`; multi-hop identity is materialized
one hop at a time. Local shadows precede their consumers in field-name order.
Field analysis distinguishes a real `VALUE` clause from `$value` in assertions
and preserves quoted text/comments during expression rewriting.

Rotations and derived refreshes do not change business timestamps or produce
audited mutations. Client inputs include `$value` normalizers, but exclude
computed/derived fields, tree storage, effect outputs, and `@rebase-system` fields.
Custom field SELECT permissions remain intact when generated writes are protected.

## Effect/handler validation

An effect table must map to exactly one table-keyed handler. The compiler checks
process type, handler existence, input/output markers, declared output types,
and copied artifact parity. It rejects writable runtime outputs, missing output
fields, unknown handlers, invalid adapter identifiers, and mismatched table
declarations. Repeat
`@rebase-adapter <functionName>` for each function the handler may receive. Details live in
[`runtime-dispatch.md`](./runtime-dispatch.md).

## Build artifact and CLI

The artifact contains the compiled `schema.surql` and copied handler modules. It
does not contain operation catalogs, manifests, or generic job schemas.
`--check` compares generated schema and copied trees.

Useful commands:

```bash
npm run build
npm run check
node dev-tools/compiler/cli.js --print-raw
```

The compiler can generate runtime events only when a complete environment profile
supplies a namespace/database context and runtime URL/secret. Without those
values the generated schema remains context-neutral and contains no
deployment-specific event calls. Use Node's `--env-file` option before the
script to select a profile; inherited process variables take precedence.
CLI flags select project/output paths and check mode; connection and runtime
credentials remain process-profile configuration.

## Development data

Use the [fixture primitives](../../dev-tools/README.md) with standard JSON Schemas,
explicit named reference spaces, and reusable JavaScript recipes. The model
reuses complete compiler metadata for native binding and compiles Ajv validators
once. Private `data/*.schema.json` files are fixture input shapes; public
`schemas/*.schema.json` files are separately authored client contracts.

Generation has isolated seeded state, deterministic IDs, and explicit dependency
ordering. Recipe values calculate domain bounds or call the optional native Z3
helper for coupled rules. No `x-rebase-*` sampling keywords or automatic business
constraint inference is used. `populate(db, options)` reads supplied spaces and
writes the entire recipe in one transaction; batches limit requests, not commits.
Use `plan` and `insert` separately when controlling transactions yourself.

## Workbench

The workbench starts Node's built-in JavaScript REPL with the public functions
from `dev-tools/index.js`. It supports ordinary JavaScript and top-level
`await`; database access starts only when a developer explicitly calls
`connect()`. Select among configured contexts through the SDK. The
[developer tools guide](../../dev-tools/README.md) documents build/check mode,
fixture planning, transactional population, and direct SDK use.

The workbench exposes the fixture namespace directly with explicit inputs.
`check()` and `deploy()` wrappers were removed; use `build({ check: true })`
and the SDK's `query` with generated SQL.

## Verification

`npm run verify` performs deterministic compile checks, `surreal validate`,
architecture/runtime/security/data probes, and generated-artifact checks. Live
probes use disposable instances (on-disk SurrealKV for temporal/account probes),
create their own actors and records, and terminate/remove the instance afterward.

Critical coverage includes principal DAGs, permission-aware references,
ownership delegation, readers and revocation, views, audit/change logs, sync and
async effects, duplicate claims/retry/reconciliation, webhook signatures and
deduplication, seeded data generation, intrusive multi-tree topology and
chronology, exact ordered summaries, live prefix invalidation, final-state
guards, and concurrent owner conflicts. `probe:temporal-tree`, `probe:accounts`,
and `probe:suite` are required gates; the suite probe checks CRM lifecycle,
HRM allowances, inherited unit activity, and populated schema reapplication.

Before changing a core rule, ask:

1. Which invariant or duplicate source of truth does it address?
2. Is SurrealDB or the schema already capable of doing it?
3. Does it add a mode, registry, or compatibility branch?
4. Has engine behavior been reproduced in a disposable probe?
5. Does revocation, deterministic output, strict typing, and handler validation
   still pass?

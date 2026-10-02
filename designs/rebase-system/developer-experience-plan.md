# Developer experience redesign plan

Restart from [the execution handoff](developer-experience-handoff.md) for
working-tree status, review findings, evidence, and the smallest required checks.

Status: D0–D4 implemented; scoped checks passed. The user reports D5's frontend
work was implemented separately; see the 2026-10-02 update in the
[completion handoff](developer-experience-handoff.md). Frontend review awaits
an explicit user request. The
compiler/runtime contract and business behavior stay fixed.

## Objective and boundaries

Make ordinary JavaScript the main developer interface: a small public API, a
native Node.js REPL with top-level `await`, and a thin compatibility CLI. Keep
database work visible as normal SurrealDB SDK calls. Publish authored
accounting JSON Schemas separately from private fixture data and test contracts.

This is a source-layout and authoring change. It does not alter generated
SurrealQL, authorization, authentication, adapters, scheduling, accounting
identities, lifecycle rules, or business policy. It adds no developer-tool
registry, query DSL, framework, or parallel database abstraction.

## Baseline and implementation map

- The implementation baseline is permanent checkpoint `d0593fa` (`major
  changes: reworked the compiler, new engine for compiling tree based linked
  list references and more`). That review used a shared dirty worktree, later
  committed in `0625f9b`; preserve any subsequent user changes.
- The empty-environment baseline has an 18-artifact manifest across `test`,
  `all-in-one`, and `all-in-accounting`. The handoff links the retained review
  evidence, source fingerprints, and reproducible parity commands.
- Compiler-only modules now live under `dev-tools/compiler/`, with the plain
  build API in `project.js`; `package.json` retains existing build/check script
  names. Runtime/provider code and its adapter contract remain under
  `gateway/`, with environment configuration under `config/`.
- `dev-tools/index.js` exposes ordinary JavaScript functions and
  `dev-tools/workbench.js` starts Node's native REPL. The workbench project
  object is mutable; SDK operations remain direct.
- `dev-tools/populate.js` retains its batching, caps, and context checks, with
  an optional identity-by-default transform hook before validation/conversion.
- `designs/test/data/*.schema.json` remain private fixture-generation
  contracts with `x-rebase-*` vocabulary. Five authored public accounting
  schemas live under `designs/all-in-accounting/schemas/` and are validated
  and exported separately by `dev-tools/client-schemas.js`.
- Reusable checks and performance experiments are grouped under
  `dev-tools/checks/` and `dev-tools/experiments/`.

## Keep, change, defer

**Keep:** current compiler phases, generated artifact names, scripts, config
allowlist, database ownership, direct SDK escape hatch, targeted regressions,
and measurement evidence with its setup, counters, variance, and limits.

**Change:** move compiler-only modules into `dev-tools/compiler/`; expose a
small ordinary-JS API from `dev-tools/index.js`; use native `node:repl` from
`dev-tools/workbench.js`; add separate standard-JSON-Schema accounting shapes
and one explicit JavaScript SDK fixture.

**Separate scope:** frontend implementation now has its own
[documentation](../frontend/README.md); frontend review waits for the user's
request. For developer-tools work, do not rebuild a general CRUD layer,
form/query/route registry, field framework,
project factory, schema-driven UI, metadata registry, or custom query syntax.

## Compatibility and security boundaries

- Generated files and `--check` behavior stay byte-for-byte stable. Preserve
  npm script names and current CLI flags during the cutover.
- Use `resolveConfiguration`, `assertConnectionConfiguration`, and
  `assertConfiguredContext` from `config/environment.js`; never infer a local
  endpoint, namespace, database, or unconfigured context.
- A native REPL evaluates trusted local JavaScript; it is not a sandbox and
  must not become a network service or execute untrusted input.
- Do not print passwords or store typed secrets in REPL history. Prompt for
  passwords or use one-shot local variables; remove the old `.as` password-in-
  command-line flow. Connection errors must not echo credentials.
- Return raw SDK clients. Callers choose query, select, sign-in, transactions,
  and SDK methods directly; database policy remains authoritative.
- Public schemas describe intended public record fields, not access rules,
  secrets, provider credentials, internal helpers, or fixture sampling. Do not
  strip/redact a schema to manufacture its public shape.
- Validate public schemas with Ajv strict mode. Any fixture-only vocabulary
  belongs only in the fixture validator; do not disable strict mode globally.

## Ordered packets

### D0 — Inventory and parity (complete)

1. Map compiler modules/imports, CLI callers, gateway/runtime ownership,
   populate, fixture schemas, and current regression/probe commands.
2. Rebuild all profiles from clean `d0593fa` in empty env; compare 18 outputs
   byte-for-byte with the manifest. Record commands, Node/Surreal versions.
3. Record the current parser imports, native schema/migration checks, and
   profile build/check commands before moving files.
4. Make no source edits. Resolve any unexplained baseline difference first.

**Exit:** reproducible baseline and an explicit map of compiler versus runtime
ownership.

### D1 — Compiler file/API reorganization (complete)

1. Move only compiler-owned schema parsing, analysis, policy, tree and
   derived-order logic, SurrealQL helpers, and generators into
   `dev-tools/compiler/`.
2. Keep gateway/provider/runtime code, configuration, timing constants,
   project SurrealQL, and business schemas in their owners.
3. Export compilation as a plain function. Make the CLI a small argument and
   configuration adapter over it, preserving project/output/check/permissions.
4. Update imports mechanically; do not alter compiler phases or output bytes.

**Exit:** all 18 outputs match D0; build, profile checks, and native validation
pass; no runtime module imports compiler code from its former `src/` path.

### D2 — Public JavaScript API and native REPL (complete)

1. Export a small set of plain functions from `dev-tools/index.js` for
   compile/build, checked-config connect, explicit deploy, and populate.
   Accept a plain options object; avoid project registries and factories.
   Treat `projectDir` as an explicit path. Read the live workbench options on
   each call and give explicit per-call project selection precedence.
2. Expose raw SurrealDB clients. Provide only the convenience boundary needed
   for configured-context selection and explicit connection cleanup.
3. Start Node's built-in `node:repl` with a plain project options object, the
   public functions, and explicitly opened session handles. Support ordinary
   JavaScript and top-level `await`.
4. Default `--project` to `all-in-accounting`; preserve `--help`, parser shape,
   and explicit project paths/names used by existing environment checks.
5. Remove the custom `.command` parser and compiler child-process runner. Do
   not wrap query/select/sign-in or every SDK call.
6. Attempt to close each opened connection once on exit or explicit shutdown; do not
   configure persistent REPL history or expose credentials in output.
   Completion must include pending opens and asynchronous closes. Test delayed
   completion, not just a synchronous close counter. Keep automatic REPL build
   output compact while retaining the full public compiler result for JS use.

**Exit:** offline `node:test` covers public imports/build options, configured
context acceptance/rejection with a stub, JavaScript plus `await`, and cleanup.
No live DB or provider call.

### D3 — Public accounting schemas and one fixture (complete)

1. Select first public record shapes from current accounting use and map each
   intended field to the existing SurrealQL source.
2. Author standard JSON Schema in a public accounting directory, separate from
   `designs/test/data/` and all private fixture contracts. Add no Faker keys.
3. Validate with Ajv strict mode; unknown public keywords fail. Keep any
   fixture vocabulary registered only in its isolated validator.
4. Add one small `.js` fixture with explicit objects and a preview that opens
   no database. Document opt-in insertion using a configured disposable DB and
   normal SDK calls. Keep IDs, dates, decimals, transactions, and cleanup visible;
   do not infer a business flow from JSON Schema. Retain the isolated SDK smoke
   with the dated evidence so its native conversions can be reproduced.
5. Compare public shape with DB enforcement without changing business schema,
   permissions, lifecycle, or domain semantics to satisfy the validator.
6. Check the actual compiler export path, including missing/invalid sources,
   stale outputs, and source/output overlap. Never remove authoring inputs as
   part of pruning generated output. Preserve record identity during SDK
   conversion; canonical UUIDs and custom keys have different meanings.

**Exit:** independently reviewable public shapes, strict validation, and one
explicit fixture with a disposable integration check. It is not production data
or a semantic oracle.

### D4 — Regressions and measured experiments (complete for this slice)

1. Keep compiler, auth/config, runtime, queue, temporal-tree, and accounting
   regressions that guard current behavior. Update paths after D1/D2 settle.
2. Use existing `dev-tools/accounting/` and `dev-tools/temporal-tree/`
   directories as the organization pattern; add no test-runner framework.
3. Label synthetic, feasibility, and physical-cost work. Keep setup, oracle,
   measurements, variance, and limits beside each experiment. Do not turn
   logical-million or harness results into storage/production claims.
4. Retain checkpoints/evidence. Archive a probe only after a focused regression
   preserves its contract and the old command leaves the supported route.

**Exit:** focused changed-surface regressions pass. Run broad `npm run verify`
for shared integration/release gates, not documentation or path-only edits.
Do not delete evidence as cleanup.

### D5 — Historical frontend blueprint; superseded by separate work

The user reports the frontend redesign is implemented separately. Git metadata
records MetaSol `3022392` and ReBase frontend docs `738e8d3`. This update does
not review or validate that implementation. Use [its documentation](../frontend/README.md)
for future frontend work when requested; the original notes below are historical
rationale, not an instruction to restart or restore an older frontend.

The initial developer-tools inventory observed MetaSol as a separate nested
checkout at `cccd1df`, with a large uncommitted replacement implementing the
simplified starter. This is a recorded snapshot, not fresh frontend verification;
inspect that checkout only when frontend review/work is explicitly requested.

Files recorded in that earlier snapshot:

- `MetaSol/src/app/SessionProvider.jsx` and `WorkspaceProvider.jsx`: session
  scoping and query-cache clearing on context/account switch.
- `MetaSol/src/app/PreferencesProvider.jsx`: small separate `localStorage`
  preferences.
- `MetaSol/src/routes/` and `MetaSol/src/data/users.js`: explicit route-local
  page/query, bound SDK values, URL search/page state, stable sort, and
  `pageSize + 1` pagination. Database authorization stays authoritative.
- Relation picker in history: async search, selected-record hydration,
  stale-result isolation, and table-plus-record identity; retain behavior only
  when a concrete page needs a small selector.

History records the traps: `4126329` and `d406d5d` introduced a resource
registry, query compiler/operator model, and generic console; `fa5d9be` and
`0cead8e` expanded generic query state, validation, and pagination; `e8881d8`
reworked a large query builder and relation/form components. The then-uncommitted
simplification removed those layers. Do not restore them for dev-tools work.

Original guidance for a separately authorized frontend slice:

1. Keep one account/session context and independent preferences; clear caches
   and live subscriptions on account/context change.
2. Implement one ordinary route/page using installed Solid and SDK versions.
   Pick the router from observed reactivity and complexity; TanStack supports
   Solid, and TypeScript implementation alone is no reason to switch.
3. Add async polymorphic single/multi-select only where needed. Preserve
   `(table, record ID)`, bind values, and ignore stale-context results.
4. Add table/grid/kanban helpers only after repetition. Cap groups at ten plus
   explicit “other”; make range grouping a named feature. Promise no automatic
   aggregates, joins, or live refresh without a query contract.
5. Prefer direct SDK functions and visible page-specific forms. No arbitrary
   UI query DSL, generated form framework, or automatic route registry.

**Original exit:** no MetaSol changes in D0–D4. Frontend implementation has since
proceeded independently; do not execute this historical packet again.

## Verification gates

- Compiler moves compare outputs with D0, run `npm run check`,
  `npm run check:all-in-accounting`, `npm run check:all-in-one`, and native
  validation of schemas/migration artifacts.
- API/REPL changes run the focused offline tests and current config/compiler
  probes. They do not need a real DB, Redis, provider, external network, or
  personal `.env`.
- D3 runs strict JSON Schema validation and only disposable checks needed for
  the selected record shape. `npm run verify` is for shared integration or an
  agreed release gate. Passing a focused test proves only its stated boundary.

## Primary references

- Node's stable built-in REPL supports standalone/embedded use, JavaScript,
  and top-level `await`: [Node.js REPL docs](https://nodejs.org/api/repl.html).
- Ajv strict mode rejects unknown JSON Schema keywords unless explicitly
  registered: [Ajv strict mode](https://ajv.js.org/strict-mode.html).
- TanStack lists `@tanstack/solid-router` as supported:
  [supported frameworks](https://tanstack.com/router/latest/docs/framework).

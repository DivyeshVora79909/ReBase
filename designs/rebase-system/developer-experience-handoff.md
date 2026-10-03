# Developer experience restart handoff

Updated 2026-10-03. This records the completed scoped developer-tools redesign
and its verification. The design rationale and historical frontend guidance
are in [the plan](developer-experience-plan.md).

## Review scope update — 2026-10-03

The user now requests review of both backend and frontend. The earlier
frontend deferral below is historical. Current results and corrections are in
the [redesign review](evidence/2026-10-03-redesign-verification.json) and
[frontend verification](../frontend/verification.md). Acceptance stops at local
SurrealDB consistency and delivered browser workflows. Do not test real
email/SMS/payment credentials. There is no existing data to migrate.

The review reproduced and fixed one more input-preservation bug: a hard-linked
generated artifact could overwrite an authoring file. Generated files now use
temporary writes and atomic replacement, preserving existing permission bits.
The final offline workbench/public-schema suite passed **26/26** after this
fix; the six-row fixture preview also passed. Atomicity is per generated file,
not across the complete build. See the current review for commands and hashes.

## Historical user update: frontend redesigned separately (2026-10-02)

- The user reports completing the previously deferred frontend independently,
  without changing the developer-tools work covered by this handoff. Preserve
  that work; do not restart or undo it from the old D5 blueprint.
- Git metadata observed: ReBase `738e8d3` (`full frontend built`) adds
  `designs/frontend/` documentation and evidence; MetaSol `3022392`
  (`full frontend MetaSol redesign`) contains the frontend changes. The earlier
  developer-tools work is committed in ReBase `0625f9b`. Both worktrees were
  clean before this documentation-only update.
- [Frontend documentation](../frontend/README.md) now owns frontend scope and
  continuation. This turn inspected Git status/log/stat only: no frontend code
  review, build, test, or revalidation of its evidence. The user will explicitly
  request frontend reverification later.
- Backend, developer-tools, and accounting handoffs retain their own scope.
  Continue the selected non-frontend packet using their existing instructions;
  do not reopen completed D0–D4 or expand into frontend work. The dated checks
  below remain historical evidence for their recorded source fingerprints.

## Scope and working-tree state

- Developer tools were reorganized around ordinary JavaScript, a small public
  API, and Node's native REPL. Frontend work is tracked separately above.
- This slice preserves core engine behavior, end-user client behavior,
  database rules, generated SurrealQL, authorization, and business behavior.
- All-in-accounting received five explicit public JSON Schemas and one visible
  SDK fixture example. CRM/HRM designs were not redesigned.
- The original review used a shared dirty worktree, subsequently committed as
  noted above. Always preserve current user work; do not reset, stash, or commit
  unrelated changes.

## Completed implementation

- Compiler-only modules are under `dev-tools/compiler/`; runtime-owned adapter
  definitions are under `gateway/operation-adapters.js`. The plain build API is
  `dev-tools/compiler/project.js`, and existing npm script keys remain.
- Reusable checks and performance experiments are grouped under
  `dev-tools/checks/` and `dev-tools/experiments/`. Useful regression evidence
  was retained.
- `dev-tools/index.js` exposes the small JavaScript API. `dev-tools/workbench.js`
  starts the native REPL without connecting. Project selection is a mutable
  plain object; per-call overrides are read when operations run. Connection
  cleanup handles in-flight opens and rejects new opens once shutdown begins.
- `dev-tools/client-schemas.js` validates strict public JSON Schemas and is
  wired into build and check, including stale-output pruning. Exactly five
  authored schemas are exported for all-in-accounting; private fixture schemas,
  SurrealQL, handlers, and secrets are excluded.
- `dev-tools/populate.js` accepts an optional identity-by-default
  `transform(document, { table, index, seed })` callback before the existing
  AJV validation and SDK type conversion.
- `dev-tools/accounting/fixture-example.js` demonstrates six explicit fixture
  rows with SDK `RecordId`, `Decimal`, and `Date` values. Preview validates
  fixture input without opening a database.
- The old custom workbench dot-command parser was replaced by normal
  JavaScript and top-level `await`. It does not configure a persistent history
  file; developers should keep secrets out of typed JavaScript literals.

## Lead review and corrections

The first implementation needed the fixes below before its completion claims
were accepted. These are regression boundaries for later edits, not new
framework features.

| Observed mistake | Correction and required invariant |
|---|---|
| A build directed into its own input deleted source handlers; a generated-file symlink could overwrite authoring input | Reject overlapping project/framework inputs and output, canonical directory aliases, and symlinked generated files before writes. Preflight copied directories before public-schema pruning. Regression snapshots preserve source files and modes. |
| Explicit source directories could be interpreted as design names; REPL operations dropped live options | Treat `projectDir` as a path, read the live plain project object on every operation, and honor explicit call overrides. `.clear` restores initial helpers and project without losing connection ownership. |
| Bare REPL build results exposed the full compiler bundle/configuration | Give workbench build/check results a compact inspection summary. Keep the full public API result and deliberate property access available. |
| Shutdown missed delayed opens/closes or a manual close failure during another pending open | Share each managed close promise, wait for all pending attempts, and report retained errors. This guarantees cleanup attempts and error reporting, not successful transport closure after an SDK failure. |
| UUID conversion depended on UUID version and could truncate UUID-looking custom keys | Parse only the supported full record-ID forms and preserve native UUID versus string identity. Test actual DB string output as well as SDK serialization. |
| Public exports and test fixtures assumed output could live inside authoring input | Validate public inputs before writes, reject path overlap, keep exports separate, and put probe outputs beside their disposable source directory. |
| Documentation mixed up defaults, filesystem writes, and fixture execution | Separate API/workbench versus CLI defaults; build writes files, deploy/populate write a database. Fixture preview is offline and SDK insertion is explicit. |

Path guards cover the checked build/copy layout. They are not a sandbox for
untrusted filesystem mutation and do not make multi-file writes atomic. Public
JSON Schemas cover five create inputs; they do not replace database policy or
constitute schemas for the whole accounting domain.

## Verification completed

The [dated review evidence](evidence/2026-10-02-developer-experience-review.json)
contains the baseline manifest, commands, timings, versions, final source
fingerprints, and integration result. Temporary output paths are conveniences;
the retained manifest and commands below are the restart evidence.

- `node --test dev-tools/tests/workbench.test.js dev-tools/tests/client-schemas.test.js`:
  **25 passed, 0 failed**. Coverage includes schema validation, path/source
  preservation, native IDs, mutable project options, compact REPL output,
  connection configuration, and delayed cleanup/error races.
- Syntax checks passed for changed JavaScript modules and both focused tests.
- The accounting fixture preview passed for all six rows without a database.
- Isolated builds for `test`, `all-in-one`, and `all-in-accounting` matched all
  **18 original generated artifact hashes** from checkpoint `d0593fa`.
- All three profile `--check` runs passed. The five emitted accounting schemas
  matched their sources byte-for-byte and exactly. `surreal validate` passed
  for the generated schema and two migration files in each profile (**9
  validations**).
- With an empty environment, `compiler-probe.js` and `environment-probe.js`
  passed. `git diff --check` passed after the documentation update.
- The retained disposable memory-engine SDK smoke inserted six accounting
  fixture rows, preserved a native UUIDv4 and a UUID-looking custom string key
  through SDK and database serialization, and read a native decimal treasury
  balance of `42.5`. It passed in 9.245 seconds. No personal `.env`, provider, or
  application database was used.
- The earlier broad `npm run verify` was stopped with SIGTERM while running;
  it has no usable result and was not repeated. Focused evidence above is the
  acceptance evidence for this scoped work.

D0–D4 have no remaining implementation packet. The former D5 deferral was
superseded by the user's separate frontend work and the 2026-10-03 review
request; its ongoing contracts belong to the frontend documentation.

## Lower-model execution guide

This handoff owns developer-tools restart status. The
[plan](developer-experience-plan.md) owns the design decisions, and
[dev-tools/README.md](../../dev-tools/README.md) owns developer usage. Core and
accounting handoffs keep their existing scope. Read the active surface below;
do not reload the whole chat or treat every historical open item as a new task.

### Decisions to preserve

- Compiler phases, native schema/permissions, tree rules, generated SurrealQL,
  and runtime contracts retain their meaning. A relocation must preserve the
  old artifact bytes under the same process configuration.
- Public API/workbench default: `all-in-accounting`. Compatibility CLI and
  population CLI default: `test`. `projectDir` is a source path, `project` may
  be a design name, and `outputDir` is generated output. Database context is
  selected separately from the validated process profile.
- Use `config/environment.js` for configuration. Do not add another environment
  parser, implicit credentials, project registry, per-field framework, or query
  language. Keep SDK methods accessible through the session's `db`.
- Public `schemas/` contain authored create-input JSON shapes. Private `data/`
  contain fake-data vocabulary. Never infer frontend authorization or publish
  the entire backend build. Database permissions and aggregate rules remain
  authoritative. `owned_by` is authorization ownership; an accounting
  `economic_entity` can be the existing user or an organization.
- Ordinary JavaScript handles fixture edits. Preserve validation, conversion,
  batching, seeded generation, and bounded reference sampling around it.
- Frontend implementation and verification are tracked separately. Routine
  fixes inside this scope need no further lead
  approval. New business policies, frontend expansion, deployment, and commits
  are separate scope decisions; do not invent them to keep working.

### Pick the smallest work packet

These are maintenance routes, not additional unfinished features.

| Surface | Read/edit boundary | Required evidence after a change |
|---|---|---|
| JS API and native REPL | `dev-tools/index.js`, `workbench.js`, `tests/workbench.test.js`; read `gateway/connection.js` and `config/environment.js` | Offline workbench tests; delayed open/close, override, and output cases relevant to the change |
| Public schema export | `client-schemas.js`, `compiler/project.js`, `tests/client-schemas.test.js`, authored `schemas/` | Strict validation, build/check integration, stale/absent source, source preservation, exact public file set |
| Fixture edits/population | `populate.js`, `accounting/fixture-example.js`, selected input schema | Transform-before-validation and SDK value tests; preview; disposable DB smoke only if actual write/conversion semantics changed |
| Compiler/layout | `compiler/`, affected `checks/` or `experiments/`, `package.json` | Import/path checks, compiler/environment probes, three-profile build/check, 18-artifact parity and native validation |
| Docs/routing | This handoff, the plan, or developer README | Check examples against current functions; resolve local links; whitespace check; no runtime suite |

For each packet: state the observed problem and one acceptance condition, read
only its dependencies, reproduce the failure at the smallest boundary, make a
bounded fix, then run the relevant checks once after edits settle. A regression
should fail for the old behavior and pass for the required behavior; avoid
tests that merely repeat implementation details. Inspect the final diff and
update this handoff with evidence and any remaining limitation.

Use one executor for coupled files. Independent API, schema, and layout reviews
may run in parallel with explicit file ownership; share findings before editing
another executor's files. The coordinator integrates and runs shared checks
once. Luna at high/max reasoning is the normal route requested by the user; use
Sol for a problem that remains unresolved after a minimal reproducer. Send the
reproducer, files, expected/actual behavior, and attempted fixes, rather than
the entire history. A model name is not acceptance evidence.

### Verification commands

Run from the ReBase root. Use installed locked dependencies; do not upgrade
packages to make a check pass. The isolated commands below neither load `.env`
nor start a database/provider. Select rows from the matrix above rather than
running this entire block after every edit.

```bash
env -i PATH="$PATH" node --test dev-tools/tests/workbench.test.js dev-tools/tests/client-schemas.test.js
env -i PATH="$PATH" node dev-tools/checks/compiler-probe.js
env -i PATH="$PATH" node dev-tools/checks/environment-probe.js
env -i PATH="$PATH" node dev-tools/accounting/fixture-example.js
```

For a compiler/build change, generate and check the same temporary outputs:

```bash
set -e
task_output_dir="$(mktemp -d /tmp/rebase-dx-check.XXXXXX)"
for profile in test all-in-one all-in-accounting; do
  env -i PATH="$PATH" node dev-tools/compiler/cli.js \
    --project "designs/$profile" --framework framework \
    --output "$task_output_dir/$profile"
  env -i PATH="$PATH" node dev-tools/compiler/cli.js --check \
    --project "designs/$profile" --framework framework \
    --output "$task_output_dir/$profile"
  for artifact in schema.surql migrate-one-shot-backfill.surql migrate-one-shot-finalize.surql; do
    surreal validate "$task_output_dir/$profile/$artifact"
  done
done
diff -ru designs/all-in-accounting/schemas \
  "$task_output_dir/all-in-accounting/client/schemas"
```

Compare the original artifacts with the durable audit manifest:

```bash
node - "$task_output_dir" <<'NODE'
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const evidence = require("./designs/rebase-system/evidence/2026-10-02-developer-experience-review.json");
const root = process.argv[2];
const entries = Object.entries(evidence.baselineArtifactSha256);
assert.equal(entries.length, 18);
for (const [relative, expected] of entries) {
  const actual = crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(root, relative))).digest("hex");
  assert.equal(actual, expected, relative);
}
console.log("All 18 original artifacts match the baseline.");
NODE
git diff --check
```

The manifest is specific to the unchanged-engine redesign at `d0593fa`. A
future intentionally changed schema needs a new reviewed baseline; never
replace expected hashes merely to silence a difference. If reconstructing the
baseline, extract `git archive d0593fa` into a disposable directory, make the
same locked dependencies available there, and build in the same empty
environment. Preserve the active worktree.

Only when fixture writes or native value conversion change, reuse that built
accounting schema for the retained disposable integration check:

```bash
env -i PATH="$PATH" node \
  designs/rebase-system/evidence/2026-10-02-fixture-sdk-smoke.cjs \
  "$task_output_dir/all-in-accounting/schema.surql"
```

This starts its own loopback SurrealDB server with the memory engine, writes
only throwaway rows, and closes it on completion. It uses no personal profile
or external provider. It checks native IDs and a single treasury balance, not
the entire accounting model.

### Completion and failure handling

- Record the actual command, exit status, scope, versions, and fingerprints of
  relevant tracked **and untracked** source. Temporary outputs alone are not a
  durable handoff. Untracked source is omitted by ordinary `git diff`, so review
  its contents and whitespace separately.
- A stale generated output is not automatically a source regression: build and
  check with the same project, output path, and environment. Investigate any
  parity difference before claiming compatibility.
- On a failure, stop broadening the suite. Determine whether it is source,
  test setup, stale build, missing binary, or external infrastructure. Fix the
  smallest cause and rerun the failed boundary plus affected regressions.
- Passing offline checks does not prove provider delivery, production migration,
  capacity, or every runtime interleaving. `surreal validate` checks syntax,
  not accounting behavior. Historical in-memory integration evidence stays
  dated; do not relabel it as a fresh run.
- `npm run verify` is a separate integration gate with database/Redis/runtime
  work; do not run it by habit after tool or documentation edits. New engine,
  authorization, or runtime changes must use the existing core handoff's
  relevant integration gates instead of relying on this audit.
- When the selected packet and checks are complete, report the outcome and
  remaining scope. Do not add abstractions, expand domains, or repeat passing
  suites to fill an otherwise complete turn. Preserve the shared dirty tree.

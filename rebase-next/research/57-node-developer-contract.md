# Proposed Node developer contract

Status: **PLANNING ONLY — no API below is implemented or accepted.**
This paper specifies the developer surface for the redesign program in
[paper 56](56-node-and-index-redesign-program.md). That program owns implementation gates;
this paper does not authorize executable changes or new capacity claims.
The user's new direction supersedes the earlier instruction to preserve Python:
replace active Python developer tooling with ordinary Node ESM JavaScript.
Rust remains the native engine, including its Cargo build and test workflow.
Historical Python evidence remains dated evidence; no compatibility layer is planned.

## 1. Contract and ownership

The entry point is a Node REPL or a JavaScript source file importing functions.
Examples are committed programs composed from these functions, not a command
language. Do not introduce a custom argument parser, CLI command registry,
shell command generator, workflow interpreter or universal SDK object.
Use explicit objects and ordinary asynchronous functions. Keep import effects zero:
no process start, environment read, filesystem creation, network connection or
schema compilation merely from importing a module.

The following paths and exports are **PROPOSED**, not current modules.
Choose final names at the implementation gate; do not add aliases for old names.
Eight capability groups bound the public surface:

| Proposed module | Public verbs | Responsibility and reason |
| --- | --- | --- |
| `tools/node/config.mjs` | `resolveConfig`, `parseEnvironment` | Resolve one explicit configuration; keep deployment policy out of transport. |
| `tools/node/native.mjs` | `openNative` | Own one native host and structured private transport; avoid a wrapper for every CLI command. |
| `tools/node/model.mjs` | `prepareModel` | Turn a native catalog into reusable local validation and generation preparation. |
| `tools/node/client.mjs` | `connect`, `savePlan` | Return a bounded public client with `call`, `prepare`, `execute`, `status`; preserve atomic mutation identity and private write-once intent persistence. |
| `tools/node/population.mjs` | `preparePopulation`, `propose`, `accept`, `reject` | Caller-owned typed generation and explicit acknowledgement, with no submission hidden in generation. |
| `tools/node/operator.mjs` | `openOperator` | Return scoped `inspect`, `snapshot`, `restore`, `archive`, `reset` capabilities over private IPC. |
| `tools/node/workload.mjs` | `runWorkload`, `checkRun` | Execute ordinary supplied scenario functions and independently check retained observations. |
| `tools/node/package.mjs` | `buildPackage`, `verifyPackage` | Build committed source in isolation and verify exported artifacts. |

Resource handles additionally expose `close`; cancellation uses `AbortSignal`.
These are lifecycle obligations, not separate capability groups.
`call(method, params)` uses the existing native method names and structured data.
It does not add another read/query discriminator or infer queries. Mutations use
`prepare` and `execute` so the original intent is retained before submission.
Do not export a CRUD helper for each contract, root, schema field or RPC method.
Keep protocol dispatch, hashing, bounded parsing, process framing, archive extraction,
redaction and schema traversal private unless a second concrete consumer needs them.
A small internal codec is justified by duplicate-key and exact-value requirements;
it is not a public alternate JSON platform.

`openOperator(native, scope)` grants methods over an existing local native host;
it does not independently reopen its live embedded store or create another host.
Operator handles expose only their explicitly granted verbs. `snapshot` means a
verified native backup, not an arbitrary filesystem copy. Restore and reset require
explicit destination/store identity and expected identity guards. Naming and wire
shapes must be reconciled with native lifecycle semantics during the bounded trial.
No production server needs Node installed. A packaged Rust executable can serve
its configured model/backend directly. Node is development/operator orchestration,
not a dependency embedded in native calculations, transactions or authorization.
No N-API binding or JavaScript engine business logic is selected by default.

## 2. Shared model and values

Rust owns authored schemas, contract codes, reference declarations, model behavior
identity, available operations and capability limits. It publishes a structured
catalog with a version and identity. JavaScript consumes that catalog unchanged;
it does not maintain another catalog of model truth or scrape help text.
Public and developer catalogs retain distinct disclosure scopes. An authenticated
public session does not thereby gain private developer/operator metadata.

`prepareModel(catalog, options)` prepares reusable validators and generator state
once per model identity/options, not once per row or operation. Use direct imports
of Ajv and json-schema-faker in ESM, with exact versions and lockfile. The current
Python-to-Node subprocess value provider is replaced, not retained as an adapter.
Prove the chosen Ajv dialect/formats against the actual authored schemas before
selecting dependencies. Reject unsupported generation keywords or require an
ordinary explicit field strategy; never silently weaken a schema for convenience.
Disable external reference fetches and dynamic schema code supplied by remote users.
Catalogs are trusted local developer inputs within declared byte/shape limits.
Ajv's generated validators are not a hostile-code sandbox.

Validation and generation are separate: a generated schema-valid object can still
violate references, authority, history, topology or native invariants. Rust checks
all accepted mutations again. JS validation is fast feedback, never permission
to bypass native validation or to call a proposal globally valid.

Use built-in `node:fs/promises`, `node:crypto`, `node:test`, `node:assert/strict`,
`node:child_process` and Node `fetch` for their established jobs. Do not wrap
`writeFile`, `mkdir`, `randomUUID` or basic path operations merely to create an SDK.
Use existing supported standards libraries for identity/key formats beyond the
narrow current profile. Do not hand-roll JWT, certificates, signature algorithms
or another crypto format. Native identity verification remains authoritative.

Exact integers outside the safe Number range stay canonical decimal strings on
JSON boundaries. Ordinary model-aware functions may use `BigInt` internally;
convert deliberately at declared fields, not with a global stringify monkeypatch.
Exact rational values retain explicit numerator/denominator strings and declared
normalization/rounding rules. Never pass financial values through Number and then
stringify the rounded result. Reject unsafe numeric JSON literals where exactness
is required. Seed/cursor values have their own explicit encoding and bounds.

## 3. Population as trusted ordinary functions

`preparePopulation` receives the prepared model, quotas, seed, typed existing
reference pools, row/batch bounds and optional trusted strategy/rule functions.
Preparation checks public contract membership, duplicate identities, compatible
reference target codes and stated limits. Existing rows supply references; they
do not silently count as newly committed generated rows or prove full-store scope.
Caller-owned state contains accepted counts, typed pools, deterministic cursor,
committed reference usage and at most one pending proposal/plan binding.

A proposal follows this order:

1. Choose an eligible contract with a seeded bounded selector.
2. Produce base fields and object/array shape from prepared generation or an
   explicit field strategy. Missing native fields may be filled by later overlays.
3. Select and overlay typed references at the now-concrete declared paths,
   including array elements and optional/nested fields. Required scalar reference
   slots may be filled without a dummy UUID in the base fields.
4. Obtain fresh context for that row after reference selection.
5. Run its ordinary rule with fields, selected references and fresh context.
6. Validate the completed fields and emit a bounded detached proposal.

Context is an explicit mapping or callback; missing context never means zero.
Time is caller-supplied, including any clock function. No implicit `Date.now()`
or hidden database reads appear in model-specific rules. A callback may perform
explicit reads through its caller-owned client; document their snapshot boundary.
The server settles current authority/invariants at mutation time, so a context
read does not reserve state or prove the eventual commit will succeed.

Typed pools store contract identity, record ID and explicitly available projection.
A reference selector sees compatible pools and committed usage, not an untyped
bag of UUIDs. Default weighted selection indexes retained IDs without scanning
all rows for every selection. Custom selectors are trusted functions whose cost
is charged to the caller's runtime budget. Do not invent a universal constraint
solver, dependency discovery engine, expression DSL or generic scheduling framework.
A concrete domain rule is ordinary JavaScript; reuse a primitive after real uses.

Pin and record the seeded selection algorithm and generator versions. Determinism
requires the same catalog identity, seed, cursor, pool order, supplied context and
function behavior. Do not promise deterministic network timing or equal outputs
across dependency upgrades. Isolate faker RNG configuration per prepared generator;
a process-global mutable seed must not let concurrent populations interfere.
The bounded trial must establish whether the selected faker version supports this
without subprocesses; if not, choose a bounded explicit ownership arrangement.
Do not silently use global random state as the final concurrency contract.

A proposal retains its exact commands, selected IDs, digest and cursor transition.
Preparing a mutation binds it once to the exact saved plan. Acceptance requires
a committed native receipt for that plan's original operation ID, revision and
ordered returned record IDs. Only acceptance advances committed pools and quotas.
Definite no-commit rejection may release pending work under an explicit cursor
policy; timeout, cancellation, expired history or unobserved status cannot do so.
Expose blocked prerequisites and exhausted budgets as structured outcomes, not
unbounded retries or automatically invented parent rows.

## 4. Public client and immutable operations

`connect` receives the resolved target, an explicit credential provider, transport
budgets and optional signal. It does not issue credentials or own a local store.
`prepare` captures model, actor/store operation context, original operation ID,
commands, returning projections and normalized endpoint fence in an immutable plan.
The caller invokes `savePlan(path, plan)` before submission. This function owns a
specific existing obligation: private, write-once, fully persisted intent data,
with no overwrite or partially published plan after failure. Implement and check
its actual platform durability boundary with standard Node filesystem operations.
This is the single justified file helper; ordinary config/report/HTML output uses
`node:fs/promises` directly. Proposed plan formats may change, but exact identity,
immutability and failure semantics must remain explicit.

`execute(plan)` submits the exact original mutation. `status(plan)` uses its exact
original context and operation ID. Never refresh context to evade archive expiry,
replace an original unknown plan, regenerate IDs, or rebase a mutation implicitly.
Credential refresh is permitted only for the same fenced identity/context contract;
it cannot transform the logical operation or make an expired receipt observable.
Receipt expiry and unknown absence remain explicit unknown semantics.

A complete rejection can establish no commit only where the native protocol says
so. A lost body, deadline, abort, oversized response, invalid JSON or process exit
can occur after commit. Return a structured unknown outcome and retain the plan.
Do not classify all non-2xx replies as safe rejection. Successful records mutations
return the native receipt shape; do not accidentally expect a second nested
`result` wrapper around an already unwrapped operation result.

Normalize endpoints once, preserving meaningful path and port distinctions.
Reject credentials, fragments and queries in endpoint definitions. Compare saved
plan targets before every execute/status call. Disable redirects; bearer tokens
must not follow a redirected endpoint. HTTPS uses ordinary certificate/hostname
validation. Remote plaintext requires an explicit supported deployment policy;
local HTTP and private IPC have separately declared trust boundaries.
Bound request/response bytes and read response streams before unbounded allocation.
Use duplicate-key rejecting JSON parsing at every untrusted JSON boundary, including
nested objects; native duplicate-key rejection must remain in force too.
Plain `JSON.parse` alone cannot establish that property. Select a small maintained
parser or a narrowly reviewed codec at the trial; do not assume a reviver sees
keys that the parser has already overwritten. Verify exact large-value behavior.

## 5. Native model/operator transport

Default proposal: a private structured JSON control host in the Rust executable,
started locally by `openNative`. Prefer extending/reusing native RPC framing and
typed dispatch after a bounded trial of its actor, model and lifetime assumptions.
Today's `rpc` is an actor-scoped public-operation boundary, not an operator API.
Do not pass privileged lifecycle methods through its public method namespace.
A private operator dispatcher can reuse transport primitives while retaining its
own method allowlist, store lock/lifecycle guards and capability ownership.

Use inherited stdin/stdout pipes or an equivalently private local channel, bounded
frames, explicit request IDs, startup identity handshake and protocol version.
Reserve stdout for frames and stderr for bounded diagnostics. No TCP listener is
needed for the control host. Do not expose backup, restore, reset, inspection or
credential issuance through public HTTP to make Node integration convenient.
No arbitrary command execution, source evaluation, filesystem path escape or raw
KV mutation is accepted as a control verb. Operator authority comes from explicit
local process ownership and scoped capabilities, never a public bearer token alone.

A startup command may use a small tool-owned array such as a fixed host command
plus explicit configuration path. `spawn(binary, args, { shell: false })` and
Cargo argument arrays are acceptable native boot/build mechanics. Their values
are data, never generated shell strings. Do not build a Node wrapper for every
old Rust CLI command or parse CLI output as the long-term model API.
Existing Rust CLI verbs may remain temporarily during checkpoint replacement.
N6 removes superseded project verb/argument parsing. Retain only the minimum
documented process/service bootstrap needed to run native code, not a parallel
operator command surface for compatibility.

The transport trial must prove framing, cancellation, child exit, error correlation,
model identity mismatch, bounded output and repeated resource closure. It must also
prove that an HTTP client cannot reach operator dispatch, and that operator inspection
or packaging cannot mutate a live embedded database through an accidental second
open. Native store ownership/locking governs every operation; backup is native,
restore targets a new destination, and reset requires expected-store identity.
No failed host startup should leave a child, listener, temporary secret or lock.

## 6. One explicit configuration

`resolveConfig({ defaults, environment, overrides })` produces one validated object.
Precedence is explicit objects over explicitly parsed environment over defaults.
`parseEnvironment(env, allowlist)` is optional and called by the composition root;
imports and lower modules never inspect `process.env`. Parse booleans, integers,
paths and enum values strictly. Reject unknown supplied keys and contradictory
backend options instead of silently selecting a fallback. Do not scatter knobs.

The resolved object distinguishes target/model/backend identity, local host paths,
server/identity settings, hard capability bounds and runtime workload budgets.
Secrets are explicit protected fields or providers; diagnostic serialization uses
redaction by field contract, including nested keys and child stderr. Never include
tokens or private keys in plans, model identities, manifests or workload reports.
Pass only an explicit necessary environment subset to owned subprocesses.

Native model/backend limits are authoritative hard bounds. Runtime budgets include
row counts, batch sizes, concurrency, elapsed time, response bytes, retries and
artifact retention. A workload budget may lower a hard bound; it cannot raise one.
Report each effective value and its origin. Native startup and mutation paths
revalidate limits regardless of JavaScript preflight. FoundationDB transaction
limits and adapter-specific conformance constraints remain real backend boundaries;
an environment variable is not an escape hatch or a scalability implementation.
Changing a hard limit requires a native design/acceptance gate and new evidence.

## 7. Lifecycle and proposed composition

Every owned child, IPC channel, server, sampler or temporary resource has one owner.
`close` is explicit, awaited and idempotent. Use `try/finally` in examples and tests.
Abort stops offering new work and attempts bounded cleanup; it cannot promise
rollback of work already handed to the native writer. Drain/reconcile original
plans before archive, or report unresolved originals and incomplete evidence.
Keep external clients and caller-provided directories caller-owned unless a function
explicitly says otherwise. Never silently stop an externally owned server.

The following is **PROPOSED pseudocode; these modules are not available**:

```js
const config = resolveConfig({ defaults, environment: parsedEnv, overrides });
const native = await openNative(config.native);
try {
  const model = prepareModel(await native.catalog(), { generation });
  const client = connect({ ...config.client, credential });
  try {
    const state = preparePopulation(model, { counts, seed, existing, rules });
    const proposal = await propose(state, freshContext);
    const draft = { model: model.identity,
      commands: proposal.commands, returning: proposal.returning };
    const plan = await client.prepare(draft);
    await savePlan(planPath, plan);
    state.pending.plan = plan; // Validated, detached, write-once binding.
    const receipt = await client.execute(plan);
    accept(state, proposal, plan, receipt);
  } finally {
    await client.close();
  }
} finally {
  await native.close();
}
```

This sketch illustrates ownership only. A complete committed recipe must explicitly
handle unknown execution with `status` and retained pending state; no catch-all
`reject` or automatic retry is implied. The implementation gate fixes the exact
handle shapes before teaching them as executable examples.

The pending binding setter must validate proposal/model/target/request identity
before sending, retain a detached immutable copy, and reject rebinding. An
equivalent ordinary binding operation may be selected at N0, but there must be
one explicit composition and an adversarial control for tampered plans.

## 8. Workloads, packaging and acceptance

Workload profiles are explicit objects passed to ordinary scenario functions.
Record offered/completed counts, native identities, hard limits, effective runtime
budgets, dependencies, seed, durations, resource samples, original unknown IDs and
completion/exhaustion metadata. An incomplete observation stays incomplete; a paced
run is not a capacity claim. `checkRun` checks retained raw observations independently
of the producer's summary. Keep scenario-specific oracle functions separate from
native calculation implementation without inventing a generic checker framework.

Package functions preserve the existing committed-source discipline: select a
commit/tree, export it into an isolated directory outside Git, build only exported
inputs with locked dependencies, record source/build/model/backend identities and
verify checksums before extracted workflows. Preserve safe archive paths, duplicate
entry rejection and bounded manifest parsing. Do not package a dirty working tree
or label copied current files as an old committed artifact. Separate source-tools,
default Rust-only runtime and optional backend/developer dependencies in manifests.
Node dependency installation uses its committed lockfile; a Rust-only production
package must run without Node, npm, faker, Ajv or Python on its runtime path.

Acceptance gates must replace active Python recipes, tests, deployment tooling and
workload/checker orchestration with Node source and built-in Node tests. Retain
historical evidence without requiring Python to execute the new supported path.
Run narrow source-derived controls for exact values, duplicate JSON, endpoint/TLS
fences, immutable plans, unknown receipts, typed pools, fresh context, seeded
selection, resource ownership, native privilege isolation and isolated packages.
Use real native model/HTTP/operator trials where mocks cannot establish a boundary.
Rust remains responsible for native semantic tests. No whole historical campaign,
engine rewrite or million-record capacity claim follows from this developer change.

## Inspected source anchors

These are current-source findings, not claims that proposed exports already exist:

- `tools/client.py` implements bounded duplicate-key parsing, endpoint normalization,
  prepare/execute plans and original operation-status requests.
- `tools/population.py` implements caller-owned state, typed pools, explicit fresh
  context, proposal acknowledgement and pending unknown-plan preservation.
- `tools/population_values.py` bounds a Python-owned subprocess protocol to the
  optional Node provider; `tools/schema-values/package.json` pins faker today.
- `tools/package.py` exports committed source, builds in isolation and verifies
  bundle identities/checksums; its argument parser is not the proposed Node API.
- `src/model.rs` publishes the developer catalog; `src/rpc.rs` dispatches typed
  actor-scoped public operations; `src/server.rs` hosts authenticated HTTP.
- `src/bin/rebase-next.rs` owns current native CLI selection and lifecycle commands;
  `src/lifecycle.rs`, `src/local.rs` and `src/receipts.rs` own native lifecycle,
  mutations/status and receipt semantics. New private operator IPC needs a gate.

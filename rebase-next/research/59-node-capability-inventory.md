# Node tooling migration capability inventory

Status: capability inventory updated at N6 retirement checkpoint. The 60 Python
paths and four auxiliary schema-values bridge files have been retired from the
working tree under [the N6 retirement ledger](fixtures/n6-retirement-ledger.json)
and [retirement report](77-node-tooling-retirement.md). Extracted-release
verification remains pending; this status does not accept N6. The inventory
records obligations and capability boundaries, not a one-to-one translation. The user
selected this direction after G9.0–G9.4 acceptance. That instruction supersedes
the older Python-preservation notes in `AGENTS.md` for this new goal.

## Outcome and boundaries

The target is a usable library of ordinary functions, backed by one authoritative
model and the native Rust runtime/storage interfaces. Direct imports and the
ordinary Node REPL are the developer surface; npm install/test/build scripts are
optional standard repository conveniences. Retain only minimal Rust process
bootstrap, not a second project command grammar. Callers can compose inspect, author, apply, verify,
populate, run bounded workloads, and package/release operations without a
Python runtime or a hidden worker process.

Keep all six current model capabilities and authoritative metadata, the accepted
semantic obligations, and the established resource envelopes. Interfaces and
artifact shapes may break with explicit identity/version decisions; do not add
compatibility shims. G6 accounting-business expansion is
deferred; preserve or port the existing bounded invoicing coverage so the
migration does not regress that workflow. Do not promise arbitrary model
fakes, generic constraints, universal schemas, automatic capability discovery,
or unbounded workloads. Tests must not make those promises either.

This is a capability inventory, not a task/checkpoint ledger. Root's checkpoint
paper owns sequencing, acceptance, and evidence references. Module names below
are proposed capability-oriented paths and may be reconciled with that paper.

## Proposed Node surface

Use ESM under the proposed `tools/node/` package. The public module/export
contract belongs to [paper 57](57-node-developer-contract.md); this table maps
coverage into that one contract. It does not define another set of exports:

| Capability | Proposed module responsibility |
| --- | --- |
| `config.mjs` | Explicit resolved settings, optional environment parsing and capability-derived budgets |
| `client.mjs` | JSON-RPC, strict decoding, credentials, original plans and receipts; no contract-specific CRUD wrappers |
| `model.mjs` with private native methods | Consume six native model catalogs, explain/validate schemas and obtain authored fixture drafts; Rust owns definitions |
| `operator.mjs` over `native.mjs` | Integrity, data/model inspection, HTML, backup/restore/reset/archive and owned serving through structured local operations |
| `population.mjs` | Deterministic typed generation, context/rules and confirmed progress; examples compose the client |
| `workload.mjs` and ordinary scenario/oracle modules | Bounded scheduling and observations, independent checks, walk/explore/shrink/replay and effects/provider scenarios |
| `package.mjs` | Committed source/build identity, manifests, artifact verification and isolated release checks |
| `native.mjs` and internal process helpers | Scoped native host, FDB helper/fake provider ownership, lifecycle, bounded diagnostics and cleanup |

These are ordinary functions taking explicit model/data, resource handles,
trusted callbacks, clock/seed and bounded-resource inputs, returning values or
explicit owned handles. Serialized reports remain data-only. Shared
ordinary primitives are welcome when actual callers need them. Do not recreate
the existing custom CLI as a second command grammar inside JavaScript. Any
process bootstrap should remain the minimum needed to invoke native code.

## Capability obligations from the current surface

### Client, plans, models, and local workflow

Preserve the ordinary authenticated RPC client contract: strict duplicate-key
JSON rejection; endpoint normalization; bounded requests; no redirect credential
leak; typed HTTP/RPC/transport errors; and a distinct unknown-outcome error when
there is no complete response. Prepare plans only after reading the authenticated
session, bind the saved plan to URL/model/store/tenant/actor and operation context,
validate canonical request shape, save atomically with private permissions,
and retain explicit status/apply/replay behavior. If a response is lost, the
saved original plan remains the retry identity; never silently prepare a new
operation or infer that the mutation failed.

Model selection and catalogs must stay consistent across inspect, serving,
fixtures, population and authoring. Keep all six model metadata contracts and
their behavior identities. Expose normal data structures and APIs, not private
engine-role maps as authoring inputs. Preserve current local workflow outputs:
records, transcripts, model catalogs, receipts, offline `inspect.html`, and
JSON result artifacts. HTML visualization should consume an explicit snapshot;
it has no network behavior or hidden model computation.

### Independent verification and experiments

The verifier must stay independent of implementation-maintained indexes and
cached summaries. Expected values derive from authored source records/model
rules, and native snapshot checking must inspect persisted rows and relationships
directly within explicit work budgets. Keep verify `walk`, `check`, `explore`,
`minimize` and `replay`; deterministic seeds; independent source oracle; request
and response capture; failure-original and minimized cases; replay identity;
and named mismatch diagnostics. Native harness builds use an explicit manifest
of source/binary fingerprints and tool identity, with safe reuse only on a full
match. Report resource usage and reject over-budget checks cleanly.

Preserve measurement and observation interfaces, selection rules, exact
expectations, and report meaning; replacement formats need explicit identities
and updated consumers, not compatibility wrappers. Experiments that
establish accepted historical claims must keep their source oracle and dated
evidence provenance. Do not re-run unavailable campaigns or reinterpret paced
measurements as general capacity claims. Retain the accepted bounds: 4,096
public sources, 8,192 active outputs, 16,384 retained roles and the existing
200,000-unit mutation budget; larger fanout may reject atomically.

### Population and external effects

Population tooling must preserve reproducible IDs, explicit seed and limits,
chunking, expected-output calculation, ordinary client use and resume/replay
identity. The accepted optional schema-value provider can be a documented Node
dependency/function; it must not become a Python/NPM postinstall hook or hidden
worker. No arbitrary model generation promise is implied.

Effect tooling covers authenticated intent and replay, independent read/status
checks, provider submission and reconciliation, signed ingress validation,
durable local journal recovery, uncertain outcomes, cancellation, cleanup and
real process crash boundaries. Preserve the existing fake provider as a
deterministic test fixture service with explicit lifecycle. A Node implementation
may use ordinary functions and explicit child-process/service handles; it must
not hide persistent workers behind an import or package install. Preserve
ownership/lifecycle rules for every spawned service and stop owned processes in
failure paths.

### Workloads, storage, and release

Workloads retain exact current entry behaviors and caps for smoke, churn,
pressure/overload, outage, cycles, fault injection, observation and checking.
Results state backend, model, limits, seed, binary/package identity, measured
work and claim boundary. FoundationDB's `fdb_cluster.py` lifecycle responsibilities
include owned start/stop/status/bootstrap/check, PID/port checks, bounded waits,
logs, and cleanup; its process and extracted SDK/server ownership must not become
orphaned. Preserve the G8.3 boundary as owned local FoundationDB service
recovery, not native commit acknowledgement, replicated failover, or disk/power
loss proof. Keep adapter conformance semantic; a mock alone cannot establish
distributed behavior.

Packaging preserves source/tool/template inclusion, target and feature selection,
manifest fingerprints, archive integrity, deterministic/reproducible evidence,
restore isolation, and release check reports. `package inspect` (or equivalent
ordinary function) must explain manifest and artifact contents. Do not let
Python become a packaging prerequisite or retain an active `.py` executable as
a subprocess dependency.

## Rust and npm command boundary

The current Rust binary remains the product/runtime boundary for serving,
authenticated RPC, check/inspect/storage administration and signed token issue.
Retain only a minimal process entry and indispensable native operations. Move
developer composition, explanation, experiment orchestration and presentation
into importable Node functions. Remove `argparse`-style Python CLIs and avoid
translating each old command into a new CLI subcommand. Use optional standard
repository npm install/test/build tasks and Node's built-in `node:test` for semantic
controls. Do not add a Python bootstrap, npm postinstall, exported-tools hidden
worker, or install-time network step.

`tools/schema-values/package.json` is a separate existing Node value-provider
package; inventory its actual contract and dependencies during implementation.
The repository-root `package.json` currently belongs to the older ReBase
compiler/workbench package, not this Rust project. The implementation plan must
choose a scoped package arrangement deliberately and avoid accidentally wiring
the migration into that unrelated compiler command set.

## File inventory: active `tools/*.py`

Each current tools Python file appears exactly once below. “Port” means preserve
the listed obligation in a Node module, not retain a function-name mirror.

### Client, authored models, and invoicing

| File | Capability to preserve |
| --- | --- |
| `tools/client.py` | RPC transport, strict JSON, auth safety, unknown outcome, prepared/saved plans and replay |
| `tools/invoicing.py` | Bounded real invoicing workflow using ordinary client and model APIs |
| `tools/issue_shares.py` | Authored share issuance workflow and report |
| `tools/test_client.py` | Move semantic client controls to `node:test`, especially lost response and saved-plan identity |
| `tools/test_invoicing.py` | Move bounded invoicing behavior controls to `node:test` |

### Population and values

| File | Capability to preserve |
| --- | --- |
| `tools/population.py` | Bounded deterministic population API and explicit limits |
| `tools/population_demo.py` | Composed public population example and resumable output |
| `tools/population_values.py` | Exact typed value generation/provider boundary |
| `tools/test_population.py` | Population semantic and limit controls in `node:test` |
| `tools/test_population_demo.py` | Demo composition/resume controls in `node:test` |
| `tools/test_population_values.py` | Value contract controls in `node:test` |

### Harness, measurement, and observation

| File | Capability to preserve |
| --- | --- |
| `tools/harness.py` | Local process/API harness, setup/cleanup, archives, resource observations and reports |
| `tools/capacity.py` | Bounded population/churn/authority workflows and independent expected state |
| `tools/observation_selection.py` | Bounded sensor/event selection workflow |
| `tools/observation_reports.py` | Human-readable and machine-readable observation reports |
| `tools/test_harness.py` | Harness lifecycle and artifact controls in `node:test` |
| `tools/test_capacity.py` | Capacity envelope and atomic rejection controls in `node:test` |

### Independent verification

| File | Capability to preserve |
| --- | --- |
| `tools/verify.py` | Thin current entry behavior for walk/check/explore/replay |
| `tools/verify_runtime.py` | Scenario, comparison, mismatch and artifact runtime primitives |
| `tools/verify_cases.py` | Explicit scenario construction and expected case data |
| `tools/verify_oracles.py` | Independent source oracle/evaluation/staging |
| `tools/verify_checks.py` | Independent native snapshot checks and bounded work |
| `tools/verify_explore.py` | Seeded explore, shrink/minimize and logical replay |
| `tools/test_verify_checks.py` | Independent checker semantic controls in `node:test` |
| `tools/test_verify_explore.py` | Explore/minimize/replay controls in `node:test` |
| `tools/test_verify_walk.py` | Walk/explanation controls in `node:test` |

### Effects and provider lifecycle

| File | Capability to preserve |
| --- | --- |
| `tools/effects.py` | Public effect intent/replay/read/status workflow and accepted report |
| `tools/effects_worker.py` | Durable journal, worker lifecycle, reconciliation and crash boundaries |
| `tools/effects_ingress.py` | Signed webhook ingress, deduplication and restore/reset checks |
| `tools/fake_provider.py` | Explicit deterministic fake provider service fixture |

### G7/G8 storage and workload evidence

| File | Capability to preserve |
| --- | --- |
| `tools/g7_http.py` | Backend HTTP conformance and fault-boundary evidence |
| `tools/g7_oracle.py` | Independent storage/application oracle used by G7 checks |
| `tools/fdb_cluster.py` | Owned local FoundationDB process and cluster lifecycle |
| `tools/g8.py` | Public bounded smoke/churn/pressure/outage/check dispatch behavior |
| `tools/g8_workload.py` | Workload setup, bounded execution and output |
| `tools/g8_check.py` | Independent workload result validation |
| `tools/g8_cycles.py` | Bounded repeated workload/cycle evidence |
| `tools/g8_faults.py` | Fault injection with declared boundaries and cleanup |
| `tools/g8_pressure.py` | Pressure/overload workload and explicit resource caps |
| `tools/g8_observe.py` | Workload observation and report collection |
| `tools/g8_release.py` | Release behavior and release report checks |
| `tools/test_g8_cli.py` | Move dispatch/API semantics to `node:test`; delete CLI-specific wrapper assumptions |
| `tools/test_g8_workload.py` | Workload bounds and report controls in `node:test` |
| `tools/test_g8_check.py` | Independent result-check controls in `node:test` |
| `tools/test_g8_faults.py` | Fault boundary and cleanup controls in `node:test` |
| `tools/test_g8_pressure.py` | Pressure caps and claims controls in `node:test` |
| `tools/test_g8_observe.py` | Observation selection/report controls in `node:test` |
| `tools/test_g8_release.py` | Release manifest/report controls in `node:test` |

### Packaging

| File | Capability to preserve |
| --- | --- |
| `tools/package.py` | Bundle construction, source/tool inclusion, manifest and artifact validation |
| `tools/test_package.py` | Archive, manifest, corruption and restore-isolation controls in `node:test` |

## File inventory: `research/experiments/*.py`

These are research implementations, not necessarily current operational entry
points. Dated JSON evidence and source fingerprints remain frozen records. For
each script decide explicitly whether a live Node oracle/control is needed for
future accepted obligations or whether the evidence and historical commit are
sufficient. Convert still-required controls to Node; retire unneeded executable
Python sources to their recorded historical Git commits rather than retaining a
second Python source surface in the new package. Keep dated JSON evidence and
fingerprints immutable. Do not discard a still-required independent oracle.

| File | Classification and capability |
| --- | --- |
| `research/experiments/m3_m5.py` | Historical literal calculation/query oracle; preserve source cases and provenance needed to explain accepted semantics |
| `research/experiments/m6.py` | Historical independent typed snapshot checker; relevant invariants may feed current Node checker, not a general tree engine |
| `research/experiments/native_slice.py` | Historical source oracle/native-KV checker; retain necessary independent controls and accepted fingerprints |
| `research/experiments/reactive_windows.py` | Historical independent window/causality oracle; preserve semantic vectors referenced by accepted results |
| `research/experiments/measurement.py` | Historical executed measurement harness; accepted result is evidence, not a claim to rerun unavailable campaigns |
| `research/experiments/exact_values.py` | Historical exact-value independent oracle and vectors; preserve accepted value obligations |
| `research/experiments/effect_lifecycle.py` | Historical effect lifecycle model/control; preserve relevant independent lifecycle expectations |
| `research/experiments/local_prototype.py` | Historical local adapter independent snapshot/receipt checker; preserve accepted local workflow semantics |
| `research/experiments/deployment_bundle.py` | Historical release bundle verifier; preserve manifest/artifact/recovery expectations where still accepted |
| `research/experiments/workshop_shrink_probe.py` | Historical injected-failure shrink/replay probe; preserve demonstrated minimized logical replay behavior |

## Active documents, package usage, and migration implications

The operational guides currently teach Python commands across local prototype,
developer tools, compiled models, equipment, exact values, invoicing, external
effects, deployment, storage backends, population, native indexes, workshop and
G8 workloads. Update these guides and examples as part of the eventual
implementation so developer examples match the Node API. The top of AGENTS and
CONTEXT selects [G10](56-node-and-index-redesign-program.md), while accepted
G8/G9 claims remain historical. Historical dated papers and reports may cite the old
Python commands as evidence provenance; do not rewrite those claims as if the
new runtime had executed them.

Current `Cargo.toml` owns the 0.16 Rust binary, runtime dependencies and native
features; it has no Node dependency. The root `package.json` is for a different
compiler/workbench. The scoped `tools/schema-values/package.json` already
provides the only immediate local Node packaging precedent. Confirm whether the
new package belongs under `tools/` or a dedicated package directory before
changing either manifest. Node built-in APIs should cover process, files,
network, test and JSON needs where practical; only add dependencies for a
concrete contract and pin/document them.

The Rust CLI should retain only operations that genuinely need a product
process/native library boundary. Keep `cargo` for building/testing the runtime
and examples. Avoid Python shell-out wrappers around Cargo, Node wrappers around
the old custom command parser, or exporting CLI-only helper code as a hidden
worker. Use normal process invocation in Node at the narrow boundary and pass
structured inputs/outputs with bounded timeouts and explicit ownership.

## Coverage and completion rule

Before deleting any active Python file, the implementation should maintain a
coverage ledger that maps every inventory row to one of: (a) equivalent Node
function and semantic control, (b) historical frozen evidence plus a documented
reason no executable port is needed, or (c) intentionally removed CLI-only
surface with the replacement API documented. Tests move by meaning to
`node:test`; filenames and line counts are not acceptance criteria. Keep source
fingerprints and dated JSON unchanged unless a new execution produces a
separately identified artifact. Deletion follows successful semantic controls
and docs updates, never precedes them. The final package must contain no active
`.py` runtime or required Python install/execution step.

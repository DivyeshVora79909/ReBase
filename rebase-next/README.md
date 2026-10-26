# ReBase Next

ReBase Next is a Rust calculation and transactional state engine with compiled
models for calculation, equipment, invoicing, measurement, external effects and
quantity. It provides exact connected calculations, private outputs, ordered
aggregates and historical invariants, transactional DAG authority, authenticated
JSON-RPC, replay receipts and verified storage recovery. Model schemas drive
validation and public catalogs; the server remains authoritative for global
rules and reference access.

**N6 status (2026-10-26):** accepted within the documented model, backend,
source and workload bounds. The Node developer functions, structured `host` /
`serve` bootstrap, and retirement of 60 Python paths plus four bridge
auxiliaries are accepted from source
`1243168424294728968591d69efbe5d836fd36fd`. Both committed-source packages and
extracted acceptance are recorded in the [N6 result](research/78-node-retirement-result.md)
and [release evidence](research/evidence/2026-10-26-n6-release.json). Do not use
historical Python workflows or legacy CLI instructions as current operating
procedures. The old campaigns remain available as dated evidence in `research/`;
their outcomes and limits are not relabeled as new acceptance. This does not
complete G10 or establish unrestricted production capacity. Next is S0's
workload/trace schema and measurement baseline, before choosing an S1 candidate.
See the [G10 program](research/56-node-and-index-redesign-program.md),
[Node contract](research/57-node-developer-contract.md),
[storage plan](research/58-ordered-storage-redesign.md), and
[capability inventory](research/59-node-capability-inventory.md),
[native bootstrap contract](research/76-native-bootstrap-contract.md), and
[retirement report](research/77-node-tooling-retirement.md).

The ordinary JavaScript API is an explicit ESM barrel at
[`tools/node/index.mjs`](tools/node/index.mjs). Importing it only defines
functions; callers choose when to open a native host, connect to a service, or
run a workflow. Complete examples remain separate modules because they show
specific caller-owned compositions: [N1 model catalog](tools/node/examples/n1-model-catalog.mjs),
[N2 equipment workflow](tools/node/examples/n2-equipment-workflow.mjs),
[N3 population workflow](tools/node/examples/n3-population.mjs),
[N4 intent replay](tools/node/examples/n4-original-intent-replay.mjs),
[N5 lifecycle and release](tools/node/examples/n5-lifecycle.mjs),
[N6 signed ingress](tools/node/examples/n6-signed-ingress.mjs), and
[N6 IssueShare](tools/node/examples/n6-issue-share.mjs). Examples are evidence
and learning material, not additional SDK exports.

The frozen native bootstrap interface is `rebase-next host` for the line-framed
native protocol and `rebase-next serve /absolute/service.json` for the HTTP
service. The JSON uses `format: "rebase-service-1"`, an explicit compiled model,
backend, open target with expected store identity, and service settings. The
server opens existing stores only. Configure a store through the documented
application lifecycle before pointing a service at it; a mismatched store
identity or model fails closed. The [server guide](docs/server.md) and
[deployment guide](docs/deployment.md) describe configuration and operating
limits.

| Topic | Guide |
| --- | --- |
| Compiled models and authored model behavior | [Compiled models](docs/compiled-models.md) |
| Exact fractional values and rounding | [Exact values](docs/exact-values.md) |
| Equipment allocation and reservations | [Equipment](docs/equipment.md) |
| Invoice pricing, tax, credits, payments and refunds | [Invoicing](docs/invoicing.md) |
| Native indexes and measurement semantics | [Native indexes](docs/native-indexes.md) |
| Bounded external work, retries and reconciliation | [External effects](docs/external-effects.md) |
| Exact financial windows and reactive reads | [Reactive windows](docs/reactive-windows.md) |
| Node functions and client plans | [Developer tools](docs/developer-tools.md) |
| Storage identity, recovery and backend behavior | [Storage](docs/storage.md) · [Backends](docs/storage-backends.md) |
| Workload bounds and verification limits | [Workloads](docs/workloads.md) · [Workshop](docs/workshop.md) |
| Deployment configuration | [Deployment](docs/deployment.md) |

Calculation and equipment support up to 4,096 public source records, 8,192
active private outputs and 16,384 retained output identity reservations, subject
to explicit work, query and receipt limits. Bounded invoicing supports 64 public
sources, 256 outputs and 512 retained roles. These are enforced bounds, not a
general production-capacity claim. Model behavior identities bind the model,
token and coordination contract; there is no implicit migration between store
formats or models. Keep each store with its matching compatible binary and
verified backups. Broader accounting, arbitrary behavior loading, live provider
adapters, TiKV and a frontend remain deferred.

Research records preserve the evidence and limits of earlier campaigns. In
particular, the [N4 result](research/69-node-experiment-result.md),
[N5 release result](research/71-node-lifecycle-result.md), and N6 contracts for
[complete backup](research/72-node-complete-backup-contract.md),
[signed ingress](research/73-node-signed-ingress-contract.md), and
[IssueShare](research/74-node-issue-share-contract.md) plus the
[N6 result](research/78-node-retirement-result.md) describe bounded claims.
Read [CONTEXT.md](CONTEXT.md) for
the current handoff and [research/sources.md](research/sources.md) for the
original discussion index.

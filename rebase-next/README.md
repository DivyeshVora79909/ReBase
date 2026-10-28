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
complete G10 or establish unrestricted production capacity.

**S0.1 status (2026-10-27):** [bounded instrumentation is accepted](research/80-s0-instrumentation-result.md).
Independent per-sample checks pass all 23 selected actions on redb, SurrealKV
and local FoundationDB; the Node suite passes 166 tests. The next checkpoint is
S0.2's committed-source optimized pilot and bounded measurement campaign, before
any S1 layout decision. Work stops here at the user's requested checkpoint.
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

Current compiled models have no configured fixed population ceilings; their
population counters are u64. Model identity includes configured limits, so
stores created under earlier model/codec identities are rejected and are not
automatically migrated. The redb-connected end-to-end checks above 4,096 cover
5,001 and 10,001 records in scoped tests; they do not establish unrestricted or
production capacity. Other bounds remain: a 262,144-row observation budget for
full inventory and check operations, 64 MiB backups, 1,024 receipts, 200,000
mutation work units, 64 commands, 32 returning IDs or page rows, and 128 query
visits. Broader accounting, arbitrary behavior
loading, live provider adapters, TiKV and a frontend remain deferred.

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

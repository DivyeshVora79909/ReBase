# N6 — Node tooling retirement and release result

Status: **accepted within the bounded source, model, backend, and workload
scopes below.** N6 retires the inventoried 60 Python paths and four schema-value
bridge auxiliaries, and replaces the old project command surface with ordinary
Node ESM functions plus the minimal native `host` and structured `serve`
bootstrap. This accepts N6; it does not complete G10 or claim unrestricted
production capacity.

## Source and packages

The accepted source is commit
[`1243168424294728968591d69efbe5d836fd36fd`](https://github.com/DivyeshVora79909/ReBase/tree/1243168424294728968591d69efbe5d836fd36fd/rebase-next).
The actual committed-source packages are under
`/home/agent/rebase-n6-release-1243168/bundle-redb` and
`/home/agent/rebase-n6-release-1243168/bundle-all`. Each contains 1,061
checksummed files and all six compiled models. Their SHA-256 values are:

- redb: `5a61cdb7f96f3ee62ccd2c17683b3a8bfe2f85529205f94e368735c67b48b2ad`
- all features: `cc9b9571681a14e3870848f739227fb96923d5b9cb2bf2ef4ad6eb94169b279c`

The extracted Node suite passes 143 tests with zero skips. Three extracted
adapter lifecycle runs pass for redb, SurrealKV, and local FoundationDB. They
include complete Equipment source and physical backup checking with the explicit
role-history witness, archive, restore isolation, reset and reopen. Repeated
failed restore preserves the complete destination backup payload; FoundationDB reports
its documented internal wire error, while redb and SurrealKV report
`invalid_destination`. Every owned process and temporary store is cleaned up.

The standalone Rust service runs for all six models with `PATH` empty. Each run
checks the public catalog and fixture path, uses a fresh signed JWT and the
native session context, commits a mutation, drains on SIGTERM, restarts, and
replays the exact original receipt. Seven invalid service configurations fail
without changing the store. The default native campaign has 200 passing tests,
seven focused scope controls, and an explicit live local FoundationDB reset
control, as detailed in the [bootstrap contract](76-native-bootstrap-contract.md).

The final Node-only source changes leave all 89 native inputs unchanged. After
input hash synchronization, Cargo completed in 0.11 seconds for redb and 0.15
seconds for all features; preserved input mtimes and matching profile binary
hashes confirm the existing native executables were reused. The package source
identity is the accepted commit above. The earlier bootstrap and catalog
campaigns remain separately identified in their dated evidence.

The 60 Python paths and four bridge auxiliaries match their pinned dispositions
at `0d0601187c79d430f8d7ed41674f53e9905af75f`. The N0 migration ledger and dated
historical evidence remain preserved. Replacement controls are bounded to
their named obligations; retirement of M3/M5, M6, native-slice, and reactive
window implementations does not claim full Node parity with the old synthetic
KV, report, or matrix engines.

## Supported claims and limits

The accepted native bootstrap is `rebase-next host` and
`rebase-next serve /absolute/service.json`, with `rebase-service-1` configuration
and existing-store-only service targets. All-feature package and local
FoundationDB lifecycle results do not establish multi-host latency, replicated
failover, power-loss recovery, or general production capacity. Existing model
and workload ceilings remain enforced bounds, not a universal capacity result.
There is no implicit store migration.

N6 acceptance is recorded alongside the [native bootstrap contract](76-native-bootstrap-contract.md),
[tool retirement disposition](77-node-tooling-retirement.md), and
[release evidence](evidence/2026-10-26-n6-release.json). Root's evidence record
owns detailed commands, per-case reports, artifact manifests, and cleanup
receipts.

## Next work

Proceed to S0. First freeze a workload and trace schema for logical and physical
reads, writes, bytes, scans, cache hits, wait dependencies, conflicts, and
resource usage. Record backend, host/cluster/process topology, data shape, and
cold/warm conditions. Execute the same bounded baseline on the supported
adapters and retain correctness witnesses. Do not choose an S1 candidate until
this baseline and its measurement limits are recorded. S1 may retain the
current AVL layout if measured alternatives do not justify a smaller supported
design. S2 implements only that decision, S3 checks cross-adapter semantics and
latency within available infrastructure, and F0 integrates the resulting source
and artifacts. Broader accounting, frontend, live providers, TiKV, populated
migrations, unrestricted million-record capacity, and the explanation course
remain deferred.

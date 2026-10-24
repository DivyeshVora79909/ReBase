# Selecting a transactional backend

The same engine, model, authority, query and effect code can run over redb,
FoundationDB or standalone SurrealKV. [G7.3](../research/48-storage-publication-result.md)
and [G7.4](../research/49-storage-api-result.md) record the verified application
and HTTP scope. Final G7.5/G7.6 coordination and cross-backend acceptance remain
open; these checks do not establish production capacity or replicated failover.

## Build and select

The default build uses redb and needs no FoundationDB client. Optional Cargo
features are `foundationdb` and `surrealkv`:

```sh
cargo build --locked --release --bin rebase-next
cargo build --locked --release --bin rebase-next --features surrealkv
# Requires the FoundationDB native SDK/runtime described below.
cargo build --locked --release --bin rebase-next --features foundationdb,surrealkv
```

Leading options compose in any order, before the command. The selected model
defaults to `calculation`; the backend defaults to `redb`.

```sh
rebase-next --model quantity --backend redb check ./quantity.redb
rebase-next --backend surrealkv --model quantity check ./quantity-kv
rebase-next --backend foundationdb --cluster-file ./fdb.cluster --model quantity check quantity-dev
```

| Backend | Meaning of the store argument | Runtime |
| --- | --- | --- |
| redb 4.4.0 | File path | One serialized writer; stable read snapshots |
| FoundationDB 7.3.77, Rust client 0.11.0 | Exact UTF-8 namespace label | Native client network booted once for the process |
| SurrealKV 1.0.0 | Directory path | Standalone embedded engine, persistent WAL runtime, Immediate durability |

The FoundationDB CLI maps the exact store label to its SHA-256 namespace inside
the adapter's reserved application prefix. Use the same label and cluster file
to reopen it; it is not a local filesystem path or a globally unique store
locator. Lower-level adapter callers supply namespace bytes explicitly.
A missing SurrealKV directory rejects an open; `init` creates the destination.
SurrealKV is embedded here, not a distributed SurrealDB API.

`init`, `rpc`, `serve`, `check`, `inspect`, `backup`, `restore`, receipt archive,
reset and effect retry all use the same selected target. The teaching `demo`
command remains calculation/redb; other models use their ordinary fixture plans.
For example, after choosing fresh tenant/actor UUIDs:

```sh
rebase-next --backend foundationdb --cluster-file ./fdb.cluster --model quantity init quantity-dev --tenant <tenant-uuid> --actor <actor-uuid>
rebase-next --backend foundationdb --cluster-file ./fdb.cluster --model quantity serve quantity-dev --config ./server.json
```

The server uses the existing bounded blocking-worker admission. The storage
adapter does not introduce automatic retries. RPC distinguishes
`transaction_conflict`, `transaction_aborted`, `transaction_limit` and
`outcome_unknown`. Keep a saved operation's original ID and context when its
outcome is uncertain and read its receipt; an absent observation alone does not
prove an earlier request has stopped. The [client guide](developer-tools.md)
describes saved plans and explicit composition.

## FoundationDB prerequisites and limits

Install/use the compatible native `libfdb_c` and a running cluster; the accepted
local pair is 7.3.77 with Rust binding 0.11.0 / API 7.3. Build-time library lookup
uses `FDB_CLIENT_LIB_PATH`; the operating-system loader must also find the
library at runtime, through its configured search path or `LD_LIBRARY_PATH`.
A binary compiled with the FoundationDB feature needs that library even when
selecting redb. A default redb-only build has no such dependency.

The disposable cloud helper is `python3 -B tools/fdb_cluster.py start|status|stop`;
its extracted SDK/server and cluster file live under ignored `target/g7-environment`.
This single-process cluster has no replicated fault tolerance. It is test
infrastructure, not the production deployment recipe.

FoundationDB limits are exposed as encoded key 10,000 bytes, value 100,000
bytes, transaction 10,000,000 bytes and approximately five-second snapshot
lifetime. The adapter selects a 4,500 ms client timeout and checks the native
approximate transaction size before commit. Namespace and conflict overhead
count; a sparse application update can still rewrite complete encoded values.
An oversized operation rejects atomically; no automatic transaction splitting
is provided. Embedded engines still enforce the engine's declared work and
population bounds. SurrealKV's table-wide range guards can conservatively
conflict with unrelated writes; point guard buckets can also collide.

## Recovery and verification

`restore` is create-only. For non-redb targets, a disposable redb validation
store verifies the complete backup and applies effect quarantine before the
image is atomically imported into an empty destination. The destination's
emptiness is protected inside that transaction. A populated destination rejects.
Backups, operation context expiry, reset identity and effect quarantine use the
shared [storage lifecycle](storage.md); a backend change does not bypass them.

The bounded secured HTTP suite is an ordinary developer script:

```sh
python3 -B tools/g7_http.py --binary target/verification-build/debug/rebase-next --backend redb --out target/my-g7-redb
python3 -B tools/g7_http.py --binary target/verification-build/debug/rebase-next --backend surrealkv --out target/my-g7-surreal
python3 -B tools/g7_http.py --binary target/verification-build/debug/rebase-next --backend foundationdb --cluster-file target/g7-environment/fdb.cluster --out target/my-g7-fdb
```

Each output directory must be new. Defaults are four rounds of four competing
clients. The script retains private credentials, plans, complete backups and a
result, then stops its owned application server. It reuses the normal client and
harness; it adds no model DSL or runtime service. Its proxy deliberately loses
one request or completed HTTP response, not a native database commit acknowledgement.

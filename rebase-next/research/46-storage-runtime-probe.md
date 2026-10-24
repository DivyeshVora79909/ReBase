# G7.1 storage/runtime probe

**Accepted 2026-10-24: raw storage/runtime contract only.**
[Evidence](evidence/2026-10-24-g7-storage-probe.json) pins the code, exact engine
versions, commands/logs and failed-trial corrections. This does not accept the
application persistence refactor or complete G7. The
[active plan](45-storage-adapter-plan.md) owns subsequent checkpoints.

FoundationDB 7.3.77, Rust binding 0.11.0 and standalone SurrealKV 1.0.0 each pass
six real controls: atomic logical spaces, stable read snapshots, dropped attempt
rollback, protected missing-key reads, empty-range phantom rejection, independent
point commits and bounded paging/read-your-writes (the atomic/snapshot pair is
one named control). redb 4.4.0 passes three applicable controls and the new native
port unit control. The optimistic concurrent schedules are explicitly excluded
from redb's serialized-writer probe. All-target Clippy and formatting pass.

The common facade has owned transaction/table values and 64-row lazy pages.
The application retains its existing synchronous attempt workspace. Blocking
SDK calls run on the existing bounded worker; FoundationDB uses its native
network, and SurrealKV owns a persistent runtime to drive its commit pipeline.
Tree close precedes runtime shutdown. No per-commit worker or nested async
runtime is introduced. The redb physical file codec is preserved by its adapter.

SurrealKV mutation reads use get_for_update, including absent keys. Range reads
validate 256 guard buckets and point writes mutate their own bucket. This
conservatively prevents phantoms while admitting disjoint point writers in
different buckets; collisions may abort unrelated writers. Guard records are
adapter metadata, not business aggregates. Immediate durability is selected.
These checks execute inside an actual Tokio blocking-worker context.

FoundationDB was installed locally from official release packages into ignored
target, without changing the system. The native client and server are pinned
to 7.3.77; the test deployment has one process and one coordinator. It proves
transaction behavior, not fault-tolerant cluster deployment. Native client
linking is opt-in through the foundationdb Cargo feature, so ordinary redb
builds do not require libfdb_c. SurrealKV is separately feature-gated.

Reproduce after installing the pinned client/server and setting FDB_CLIENT_LIB_PATH
and LD_LIBRARY_PATH to the client library directory:

```sh
CARGO_TARGET_DIR=target/verification-build cargo run --locked --features foundationdb,surrealkv --example storage_probe -- foundationdb target/g7-environment/fdb.cluster
CARGO_TARGET_DIR=target/verification-build cargo run --locked --features foundationdb,surrealkv --example storage_probe -- surrealkv target/my-fresh-surreal-probe
CARGO_TARGET_DIR=target/verification-build cargo run --locked --features foundationdb,surrealkv --example storage_probe -- redb target/my-fresh-redb-probe.redb
```

Use fresh embedded destinations. The FoundationDB probe creates a unique owned
namespace. Next: G7.2, shared application persistence and coordination/version
contracts. Models/formulas, HTTP workflows, unknown-response recovery, complete
application lifecycle and cross-backend acceptance are not certified by this
raw probe. TiKV, G6, G8 execution and frontend remain deferred.

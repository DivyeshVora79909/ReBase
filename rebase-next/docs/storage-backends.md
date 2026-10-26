# Selecting a transactional backend

The same engine, model, authority, query and effect code can run over redb,
FoundationDB or standalone SurrealKV. [G7.6](../research/51-storage-conformance-result.md)
accepts the final byte, application, coordination and secured HTTP cases on all
three adapters, using the [G7.5](../research/50-scoped-coordination-result.md)
FoundationDB evidence. These checks do not establish production capacity or
replicated failover.
Current source is 0.16.0 with store format 10 /native codec 7 /effect codec 4 /
API 4. Earlier-format stores and backups require their matching binaries;
selection of another backend does not migrate them.

## Select a backend

The service configuration selects the model and backend explicitly. The
complete [redb](../deploy/server.example.json),
[SurrealKV](../deploy/server-surrealkv.example.json), and
[FoundationDB](../deploy/server-foundationdb.example.json) examples each include
the full `rebase-service-1` shape. The binary opens the configured existing
target only through `rebase-next serve /absolute/service.json`; it has no
backend or model command-line flags. Replace the store UUID and any
`REPLACE_WITH_` placeholders before use.

| Backend | Meaning of the store argument | Runtime |
| --- | --- | --- |
| redb 4.4.0 | File path | One serialized writer; stable read snapshots |
| FoundationDB 7.3.77, Rust client 0.11.0 | Exact UTF-8 namespace label | Native client network booted once for the process |
| SurrealKV 1.0.0 | Directory path | Standalone embedded engine, persistent WAL runtime, Immediate durability |

The FoundationDB adapter maps the exact store label to its SHA-256 namespace inside
the adapter's reserved application prefix. Use the same label and cluster file
to reopen it; it is not a local filesystem path or a globally unique store
locator. Lower-level adapter callers supply namespace bytes explicitly.
A missing SurrealKV directory rejects an open.
SurrealKV is embedded here, not a distributed SurrealDB API.

The server configuration fields are authoritative: `backend.kind` is `redb`,
`surrealkv` or `foundationdb`; `cluster_file` is null except for FoundationDB;
`target.mode` is `open`; embedded backends use an absolute `target.path`, and
FoundationDB uses a nonempty `target.namespace`; all targets carry the expected
canonical store UUID. The service process owns the selected store while active.

The server uses the existing bounded blocking-worker admission. An HTTP timeout
leaves native work running and retains its permit until completion. The storage
adapter does not introduce automatic retries. RPC distinguishes
`transaction_conflict`, `transaction_aborted`, `transaction_limit` and
`outcome_unknown`. Keep a saved operation's original ID and context when its
outcome is uncertain and read its receipt; an absent observation alone does not
prove an earlier request has stopped. The [client guide](developer-tools.md)
describes saved plans and explicit composition.

## Coordination and contention

Source mutations use fresh UUID tokens for changed records and roots, with
equality-only CAS. There is no global domain revision write. Immutable identity
is separate from exact population/reservation counters; ordinary updates write
those counters only if the population or reservations change. Creates and new
output reservations can therefore require shared capacity coordination.

Public query epochs are scoped to `(reader, contract)`. Changes in one such
partition coordinate even when their business roots differ. Cursors digest the
selected epochs plus the numeric authority administration revision. True no-ops
and edits outside that scope preserve cursors; changed public derivations and
old/new readers on a move invalidate affected scopes. Any actual authority graph
change invalidates secured cursors. The digest is one signed 64-character SHA-256 field,
so the full epoch vector need not fit inside the 4,096-byte cursor bound.

There are 1,024 receipt allocation slots. Hash-start linear probing preserves the
exact capacity, with the selected slot pointer and receipt in the same commit.
Replays check the original receipt before allocating. Occupied-slot probes and
hash collisions create contention, especially near capacity. Ordinary operations
only read the archive/reset header; cleanup protects and compares the complete
backup digest before clearing receipts and slots and advancing context expiry.

The disjoint-root conformance case updates already-populated business roots in
distinct reader partitions and receipt slots. It requires real FoundationDB
transactions and records the absence of a shared written coordination key. This
case does not measure unrestricted throughput or make creates, shared roots,
same-partition queries or effect-runtime quotas independent. Business-root
invariants retain their required guards. redb has one serialized writer;
SurrealKV uses `get_for_update` for optimistic validation at commit. Each write
updates one of 256 per-table buckets selected by `SHA-256(key)[0]`; a scan
validates all 256, including for an empty or limited result. Bucket collisions
and other writes in a scanned table can cause conservative conflicts. Immediate
durability requests fsync. Its retained WAL runtime closes the tree and releases
the directory lock. redb retains its default Immediate durability and one
blocking serialized writer. See [storage lifecycle](storage.md) for token and
retention contracts.

## FoundationDB prerequisites and limits

Install/use the compatible native `libfdb_c` and a running cluster; the accepted
local pair is 7.3.77 with Rust binding 0.11.0 / API 7.3. Build-time library lookup
uses `FDB_CLIENT_LIB_PATH`; the operating-system loader must also find the
library at runtime, through its configured search path or `LD_LIBRARY_PATH`.
A binary compiled with the FoundationDB feature needs that library even when
selecting redb. A default redb-only build has no such dependency.

The earlier disposable single-process FoundationDB cluster was test
infrastructure with no replicated fault tolerance. Its dated setup and
conformance details remain in [G7.6](../research/51-storage-conformance-result.md);
they are not a deployment recipe.

FoundationDB limits are exposed as encoded key 10,000 bytes, value 100,000
bytes, transaction 10,000,000 bytes and approximately five-second snapshot
lifetime. The adapter selects a 4,500 ms client timeout and checks the native
approximate transaction size before commit. Namespace and conflict overhead
count; a sparse application update can still rewrite complete encoded values.
An oversized operation rejects atomically; no automatic transaction splitting
is provided. FoundationDB protects the entire requested read range even when
only its first page is returned. Embedded adapters advertise no finite native
transaction limits through the common `Limits` structure; this is not a resource
capacity guarantee. The engine's declared work and population bounds still apply.

## Recovery and verification

`restore` is create-only. For non-redb targets, a disposable redb validation
store verifies the complete backup and applies effect quarantine before the
image is atomically imported into an empty destination. The destination's
emptiness is protected inside that transaction. A populated destination rejects.
Backups, operation context expiry, reset identity and effect quarantine use the
shared [storage lifecycle](storage.md); a backend change does not bypass them.

The dated G7.6 secured HTTP suite used four rounds of four competing clients,
retained private credentials, plans and complete backups, and stopped the
server it owned. Its proxy deliberately lost one request or completed HTTP
response, not a native database commit acknowledgement. This is historical
conformance evidence, not a current execution procedure.
The current complete secured inventory contains thirteen tables, including
`query_epochs` and `receipt_slots`. Restart and restore compare their complete
images; archive compares all preserved tables and the exact expiry-header change.
